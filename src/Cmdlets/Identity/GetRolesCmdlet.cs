using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Graph;
using Microsoft.Graph.Models;

namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    /// <summary>
    /// Cmdlet to collect directory role memberships and PIM assignments for security analysis
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "Roles")]
    [OutputType(typeof(RolesResult))]
    public class GetRolesCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
        public string OutputDir { get; set; } = "Output\\Roles";

        [Parameter(
            HelpMessage = "File encoding for output files")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(
            HelpMessage = "Include roles with no members in the summary output")]
        public SwitchParameter IncludeEmptyRoles { get; set; }

        [Parameter(
            HelpMessage = "Operation mode: AllRoles, PIMAssignments, or Both")]
        [ValidateSet("AllRoles", "PIMAssignments", "Both")]
        public string Mode { get; set; } = "Both";

        [Parameter(
            HelpMessage = "Include detailed sign-in activity information")]
        public SwitchParameter IncludeSignInActivity { get; set; }

        private GraphApiClient? _graphClient;
        private readonly string[] RequiredScopes = {
            "User.Read.All",
            "Directory.Read.All",
            "AuditLog.Read.All",
            "RoleAssignmentSchedule.Read.Directory",
            "RoleEligibilitySchedule.Read.Directory"
        };

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            if (AuthManager.GraphClient != null)
            {
                _graphClient = new GraphApiClient(AuthManager.GraphClient);
            }
        }

        protected override async Task ProcessRecordAsync()
        {
            WriteVerbose("=== Starting Roles Collection ===");

            // Check for authentication and scopes
            if (_graphClient == null || !await _graphClient.IsConnectedAsync())
            {
                WriteErrorWithTimestamp("Not connected to Microsoft Graph. Please run Connect-M365 first.");
                return;
            }

            var authInfo = await _graphClient.GetAuthenticationInfoAsync();
            // Note: Scope checking is not available through Graph API directly
            // Continuing without scope validation
            WriteVerbose("Proceeding with roles collection...");

            var outputDirectory = GetOutputDirectory();
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmm");

            var summary = new RolesSummary
            {
                StartTime = DateTime.Now,
                ProcessedRoles = 0,
                RolesWithMembers = 0,
                RolesWithoutMembers = 0,
                TotalMembers = 0,
                PIMActiveAssignments = 0,
                PIMEligibleAssignments = 0,
                OutputFiles = new List<string>()
            };

            try
            {
                switch (Mode.ToUpperInvariant())
                {
                    case "ALLROLES":
                        await ProcessAllRoleActivityAsync(outputDirectory, timestamp, summary);
                        break;
                    case "PIMASSIGNMENTS":
                        await ProcessPIMAssignmentsAsync(outputDirectory, timestamp, summary);
                        break;
                    case "BOTH":
                        await ProcessAllRoleActivityAsync(outputDirectory, timestamp, summary);
                        await ProcessPIMAssignmentsAsync(outputDirectory, timestamp, summary);
                        break;
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
                LogSummary(summary);

                var result = new RolesResult
                {
                    RoleMembers = new List<RoleMember>(),
                    PIMAssignments = new List<PIMAssignment>(),
                    Summary = summary
                };

                WriteObject(result);
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during roles collection: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessAllRoleActivityAsync(string outputDirectory, string timestamp, RolesSummary summary)
        {
            WriteVerbose("=== Starting Directory Role Membership Export ===");

            var allRoleMembers = new List<RoleMember>();
            var emptyRoles = new List<string>();
            var rolesWithUsers = new List<string>();

            try
            {
                var allRoles = await _graphClient.GetDirectoryRolesAsync();
                var allRolesList = allRoles?.ToList() ?? new List<DirectoryRole>();
                WriteVerbose($"Found {allRolesList.Count} directory roles");

                foreach (var role in allRolesList)
                {
                    summary.ProcessedRoles++;
                    var displayName = role.DisplayName;

                    var roleMembers = await _graphClient.GetDirectoryRoleMembersAsync(role.Id);
                    var roleMembersList = roleMembers?.ToList() ?? new List<DirectoryObject>();

                    if (roleMembersList.Count == 0)
                    {
                        summary.RolesWithoutMembers++;
                        emptyRoles.Add(displayName);
                        continue;
                    }

                    summary.RolesWithMembers++;
                    var roleMemberCount = 0;

                    foreach (var member in roleMembersList)
                    {
                        // Skip service principals
                        if (member.OdataType?.Contains("servicePrincipal") == true)
                        {
                            WriteVerbose($"Skipping service principal in role {displayName}");
                            continue;
                        }

                        summary.TotalMembers++;
                        roleMemberCount++;

                        try
                        {
                            var user = await GetUserDetailsAsync(member.Id);

                            var roleMember = new RoleMember
                            {
                                Role = displayName,
                                UserName = user?.UserPrincipalName,
                                UserId = member.Id,
                                DisplayName = user?.DisplayName,
                                Department = user?.Department,
                                JobTitle = user?.JobTitle,
                                AccountEnabled = user?.AccountEnabled ?? false,
                                CreatedDateTime = user?.CreatedDateTime,
                                LastInteractiveSignIn = user?.SignInActivity?.LastSignInDateTime,
                                LastNonInteractiveSignIn = user?.SignInActivity?.LastNonInteractiveSignInDateTime,
                                DaysSinceLastSignIn = CalculateDaysSinceLastSignIn(user?.SignInActivity?.LastSignInDateTime)
                            };

                            allRoleMembers.Add(roleMember);
                        }
                        catch (Exception ex)
                        {
                            WriteWarningWithTimestamp($"Error processing user {member.Id} in role {displayName}: {ex.Message}");

                            // Add basic information even if detailed lookup fails
                            var roleMember = new RoleMember
                            {
                                Role = displayName,
                                UserName = "Error retrieving data",
                                UserId = member.Id,
                                DisplayName = "Error retrieving data",
                                Department = "Error retrieving data",
                                JobTitle = "Error retrieving data",
                                AccountEnabled = false,
                                CreatedDateTime = null,
                                LastInteractiveSignIn = null,
                                LastNonInteractiveSignIn = null,
                                DaysSinceLastSignIn = "Error retrieving data"
                            };

                            allRoleMembers.Add(roleMember);
                        }
                    }

                    rolesWithUsers.Add($"{displayName} ({roleMemberCount} users)");
                }

                // Write results
                if (allRoleMembers.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-All-Roles.csv");
                    await WriteRoleMembersAsync(allRoleMembers, fileName);
                    summary.OutputFiles.Add(fileName);

                    WriteVerbose($"Role memberships written to: {fileName}");
                }

                // Log summary information
                LogRolesSummaryInfo(rolesWithUsers, emptyRoles, summary);
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during directory roles processing: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessPIMAssignmentsAsync(string outputDirectory, string timestamp, RolesSummary summary)
        {
            WriteVerbose("=== Starting PIM Role Assignment Export ===");

            var allAssignments = new List<PIMAssignment>();

            try
            {
                // Get active PIM assignments
                WriteVerbose("Retrieving active PIM assignments...");
                var activeAssignments = await _graphClient.GetPIMActiveAssignmentsAsync();

                foreach (var assignment in activeAssignments)
                {
                    try
                    {
                        var pimAssignment = await ProcessPIMAssignmentAsync(assignment, "Active");
                        if (pimAssignment != null)
                        {
                            allAssignments.Add(pimAssignment);
                            summary.PIMActiveAssignments++;
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteWarningWithTimestamp($"Failed to process active PIM assignment: {ex.Message}");
                    }
                }

                // Get eligible PIM assignments
                WriteVerbose("Retrieving eligible PIM assignments...");
                var eligibleAssignments = await _graphClient.GetPIMEligibleAssignmentsAsync();

                foreach (var assignment in eligibleAssignments)
                {
                    try
                    {
                        var pimAssignment = await ProcessPIMAssignmentAsync(assignment, "Eligible");
                        if (pimAssignment != null)
                        {
                            allAssignments.Add(pimAssignment);
                            summary.PIMEligibleAssignments++;
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteWarningWithTimestamp($"Failed to process eligible PIM assignment: {ex.Message}");
                    }
                }

                // Write results
                if (allAssignments.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-PIM-Assignments.csv");
                    await WritePIMAssignmentsAsync(allAssignments, fileName);
                    summary.OutputFiles.Add(fileName);

                    WriteVerbose($"PIM assignments written to: {fileName}");

                    LogPIMSummaryInfo(allAssignments, summary);
                }
                else
                {
                    WriteVerbose("No PIM assignments found");
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during PIM assignments processing: {ex.Message}");
                throw;
            }
        }

        private async Task<PIMAssignment> ProcessPIMAssignmentAsync(dynamic assignment, string assignmentType)
        {
            var pimAssignment = new PIMAssignment
            {
                RoleName = assignment.RoleDefinition?.DisplayName?.ToString(),
                AssignmentType = assignmentType,
                AssignmentStatus = assignmentType,
                DirectoryScopeId = assignment.DirectoryScopeId?.ToString(),
                StartDateTime = assignment.ScheduleInfo?.StartDateTime,
                EndDateTime = assignment.ScheduleInfo?.Expiration?.EndDateTime
            };

            // Set end date to "Permanent" if null
            if (!pimAssignment.EndDateTime.HasValue)
            {
                pimAssignment.EndDateTimeString = "Permanent";
            }

            // Process principal (user or group)
            var principalType = assignment.Principal?.OdataType?.ToString();

            if (principalType?.Contains("user") == true)
            {
                var user = assignment.Principal;
                var isOnPremSynced = user.OnPremisesSyncEnabled == true;

                pimAssignment.UserPrincipalName = user.UserPrincipalName?.ToString();
                pimAssignment.DisplayName = user.DisplayName?.ToString();
                pimAssignment.SourceType = "Direct";
                pimAssignment.SourceName = "N/A";
                pimAssignment.OnPremisesSynced = isOnPremSynced;
            }
            else if (principalType?.Contains("group") == true)
            {
                var groupId = assignment.PrincipalId?.ToString();
                var groupName = assignment.Principal?.DisplayName?.ToString();

                WriteVerbose($"Processing group {groupName} with role {pimAssignment.RoleName}");

                try
                {
                    var groupMembers = await _graphClient.GetGroupMembersAsync(groupId);
                    var groupMemberCount = 0;

                    foreach (var member in groupMembers)
                    {
                        if (member.OdataType?.Contains("user") == true)
                        {
                            try
                            {
                                var userDetails = await _graphClient.GetUserAsync(member.Id);
                                var isOnPremSynced = userDetails.OnPremisesSyncEnabled == true;

                                // Create a separate assignment for each group member
                                var memberAssignment = new PIMAssignment
                                {
                                    RoleName = pimAssignment.RoleName,
                                    UserPrincipalName = userDetails.UserPrincipalName,
                                    DisplayName = userDetails.DisplayName,
                                    AssignmentType = assignmentType,
                                    SourceType = "Group",
                                    SourceName = groupName,
                                    OnPremisesSynced = isOnPremSynced,
                                    AssignmentStatus = assignmentType,
                                    StartDateTime = pimAssignment.StartDateTime,
                                    EndDateTime = pimAssignment.EndDateTime,
                                    EndDateTimeString = pimAssignment.EndDateTimeString,
                                    DirectoryScopeId = pimAssignment.DirectoryScopeId
                                };

                                // Return the first member assignment (subsequent ones will be processed in the main loop)
                                if (groupMemberCount == 0)
                                {
                                    pimAssignment = memberAssignment;
                                }

                                groupMemberCount++;
                            }
                            catch (Exception ex)
                            {
                                WriteWarningWithTimestamp($"Could not process user {member.Id} in group {groupName}: {ex.Message}");
                            }
                        }
                    }

                    if (groupMemberCount == 0)
                    {
                        WriteVerbose($"Group {groupName} has no user members");
                        return null;
                    }
                }
                catch (Exception ex)
                {
                    WriteWarningWithTimestamp($"Error processing group members for {groupName}: {ex.Message}");
                    return null;
                }
            }

            return pimAssignment;
        }

        private async Task<UserDetails> GetUserDetailsAsync(string userId)
        {
            try
            {
                var selectProperties = new[]
                {
                    "userPrincipalName", "displayName", "id", "department", "jobTitle",
                    "accountEnabled", "createdDateTime", "signInActivity"
                };

                var user = await _graphClient.GetUserAsync(userId, selectProperties);

                return new UserDetails
                {
                    UserPrincipalName = user.UserPrincipalName,
                    DisplayName = user.DisplayName,
                    Department = user.Department,
                    JobTitle = user.JobTitle,
                    AccountEnabled = user.AccountEnabled,
                    CreatedDateTime = user.CreatedDateTime?.DateTime,
                    SignInActivity = user.SignInActivity != null ? new SignInActivity
                    {
                        LastSignInDateTime = user.SignInActivity.LastSignInDateTime?.DateTime,
                        LastNonInteractiveSignInDateTime = user.SignInActivity.LastNonInteractiveSignInDateTime?.DateTime
                    } : null
                };
            }
            catch (Exception ex)
            {
                // Handle rate limiting
                if (ex.Message.Contains("429"))
                {
                    WriteVerbose("Rate limit encountered, waiting 5 seconds...");
                    await Task.Delay(5000);
                    return await GetUserDetailsAsync(userId); // Retry
                }

                throw;
            }
        }

        private string CalculateDaysSinceLastSignIn(DateTime? lastSignIn)
        {
            if (!lastSignIn.HasValue)
                return "No sign-in data";

            var days = (DateTime.Now - lastSignIn.Value).Days;
            return days.ToString();
        }

        private void LogRolesSummaryInfo(List<string> rolesWithUsers, List<string> emptyRoles, RolesSummary summary)
        {
            WriteVerbose("");
            WriteVerbose("Roles with users:");
            foreach (var role in rolesWithUsers)
            {
                WriteVerbose($"  + {role}");
            }

            if (IncludeEmptyRoles && emptyRoles.Count > 0)
            {
                WriteVerbose("");
                WriteVerbose("Empty roles:");
                foreach (var emptyRole in emptyRoles)
                {
                    WriteVerbose($"  - {emptyRole}");
                }
            }
        }

        private void LogPIMSummaryInfo(List<PIMAssignment> assignments, RolesSummary summary)
        {
            var directCount = assignments.Count(a => a.SourceType == "Direct");
            var groupCount = assignments.Count(a => a.SourceType == "Group");
            var onPremSyncedCount = assignments.Count(a => a.OnPremisesSynced);
            var cloudOnlyCount = assignments.Count(a => !a.OnPremisesSynced);

            WriteVerbose("");
            WriteVerbose("PIM Assignment Summary:");
            WriteVerbose($" - Direct assignments: {directCount}");
            WriteVerbose($" - Group-inherited assignments: {groupCount}");
            WriteVerbose($" - On-premises synced users: {onPremSyncedCount}");
            WriteVerbose($" - Cloud-only users: {cloudOnlyCount}");
        }

        private string GetOutputDirectory()
        {
            var directory = OutputDir;

            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
                WriteVerbose($"Created output directory: {directory}");
            }

            return directory;
        }

        private void LogSummary(RolesSummary summary)
        {
            WriteVerbose("");
            WriteVerbose("=== Roles Collection Summary ===");
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");

            if (Mode == "AllRoles" || Mode == "Both")
            {
                WriteVerbose($"Total roles processed: {summary.ProcessedRoles}");
                WriteVerbose($"Roles with members: {summary.RolesWithMembers}");
                WriteVerbose($"Roles without members: {summary.RolesWithoutMembers}");
                WriteVerbose($"Total role user assignments: {summary.TotalMembers}");
            }

            if (Mode == "PIMAssignments" || Mode == "Both")
            {
                WriteVerbose($"PIM Active assignments: {summary.PIMActiveAssignments}");
                WriteVerbose($"PIM Eligible assignments: {summary.PIMEligibleAssignments}");
            }

            WriteVerbose("");
            WriteVerbose("Output Files:");
            foreach (var file in summary.OutputFiles)
            {
                WriteVerbose($"  - {file}");
            }
            WriteVerbose("===================================");
        }

        private async Task WriteRoleMembersAsync(IEnumerable<RoleMember> members, string filePath)
        {
            var csv = "Role,UserName,UserId,DisplayName,Department,JobTitle,AccountEnabled,CreatedDateTime,LastInteractiveSignIn,LastNonInteractiveSignIn,DaysSinceLastSignIn" + Environment.NewLine;

            foreach (var member in members)
            {
                var values = new[]
                {
                    EscapeCsvValue(member.Role),
                    EscapeCsvValue(member.UserName),
                    EscapeCsvValue(member.UserId),
                    EscapeCsvValue(member.DisplayName),
                    EscapeCsvValue(member.Department),
                    EscapeCsvValue(member.JobTitle),
                    member.AccountEnabled.ToString(),
                    member.CreatedDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    member.LastInteractiveSignIn?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    member.LastNonInteractiveSignIn?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(member.DaysSinceLastSignIn)
                };

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WritePIMAssignmentsAsync(IEnumerable<PIMAssignment> assignments, string filePath)
        {
            var csv = "RoleName,UserPrincipalName,DisplayName,AssignmentType,SourceType,SourceName,OnPremisesSynced,AssignmentStatus,StartDateTime,EndDateTime,DirectoryScopeId" + Environment.NewLine;

            foreach (var assignment in assignments)
            {
                var values = new[]
                {
                    EscapeCsvValue(assignment.RoleName),
                    EscapeCsvValue(assignment.UserPrincipalName),
                    EscapeCsvValue(assignment.DisplayName),
                    EscapeCsvValue(assignment.AssignmentType),
                    EscapeCsvValue(assignment.SourceType),
                    EscapeCsvValue(assignment.SourceName),
                    assignment.OnPremisesSynced.ToString(),
                    EscapeCsvValue(assignment.AssignmentStatus),
                    assignment.StartDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    assignment.EndDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? assignment.EndDateTimeString ?? "",
                    EscapeCsvValue(assignment.DirectoryScopeId)
                };

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private string EscapeCsvValue(string value)
        {
            if (string.IsNullOrEmpty(value))
                return "";

            if (value.Contains(",") || value.Contains("\"") || value.Contains("\n"))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }

            return value;
        }
    }

    // Supporting classes
    public class RolesResult
    {
        public List<RoleMember> RoleMembers { get; set; } = new List<RoleMember>();
        public List<PIMAssignment> PIMAssignments { get; set; } = new List<PIMAssignment>();
        public RolesSummary Summary { get; set; }
    }

    public class RoleMember
    {
        public string Role { get; set; }
        public string UserName { get; set; }
        public string UserId { get; set; }
        public string DisplayName { get; set; }
        public string Department { get; set; }
        public string JobTitle { get; set; }
        public bool AccountEnabled { get; set; }
        public DateTime? CreatedDateTime { get; set; }
        public DateTime? LastInteractiveSignIn { get; set; }
        public DateTime? LastNonInteractiveSignIn { get; set; }
        public string DaysSinceLastSignIn { get; set; }
    }

    public class PIMAssignment
    {
        public string RoleName { get; set; }
        public string UserPrincipalName { get; set; }
        public string DisplayName { get; set; }
        public string AssignmentType { get; set; }
        public string SourceType { get; set; }
        public string SourceName { get; set; }
        public bool OnPremisesSynced { get; set; }
        public string AssignmentStatus { get; set; }
        public DateTime? StartDateTime { get; set; }
        public DateTime? EndDateTime { get; set; }
        public string EndDateTimeString { get; set; }
        public string DirectoryScopeId { get; set; }
    }

    public class UserDetails
    {
        public string UserPrincipalName { get; set; }
        public string DisplayName { get; set; }
        public string Department { get; set; }
        public string JobTitle { get; set; }
        public bool? AccountEnabled { get; set; }
        public DateTime? CreatedDateTime { get; set; }
        public SignInActivity SignInActivity { get; set; }
    }

    public class SignInActivity
    {
        public DateTime? LastSignInDateTime { get; set; }
        public DateTime? LastNonInteractiveSignInDateTime { get; set; }
    }

    public class RolesSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public int ProcessedRoles { get; set; }
        public int RolesWithMembers { get; set; }
        public int RolesWithoutMembers { get; set; }
        public int TotalMembers { get; set; }
        public int PIMActiveAssignments { get; set; }
        public int PIMEligibleAssignments { get; set; }
        public List<string> OutputFiles { get; set; } = new List<string>();
    }
}
