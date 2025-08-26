namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Graph;
    using Microsoft.Graph.Models;


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
#pragma warning disable SA1600
        public string OutputDir { get; set; } = "Output\\Roles";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "File encoding for output files")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Include roles with no members in the summary output")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeEmptyRoles { get; set; }

        [Parameter(
            HelpMessage = "Operation mode: AllRoles, PIMAssignments, or Both")]
        [ValidateSet("AllRoles", "PIMAssignments", "Both")]
#pragma warning disable SA1600
        public string Mode { get; set; } = "Both";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Include detailed sign-in activity information")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1309
        public SwitchParameter IncludeSignInActivity { get; set; }
#pragma warning disable SA1201
        private GraphApiClient? _graphClient;
#pragma warning restore SA1201
        private readonly string[] RequiredScopes = {
            "User.Read.All",
            "Directory.Read.All",
            "AuditLog.Read.All",
            "RoleAssignmentSchedule.Read.Directory",
            "RoleEligibilitySchedule.Read.Directory"
#pragma warning disable SA1600
        };
#pragma warning restore SA1600

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
#pragma warning disable SA1101
            if (AuthManager.GraphClient != null)
            {
#pragma warning disable SA1101
                _graphClient = new GraphApiClient(AuthManager.GraphClient);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected override async Task ProcessRecordAsync()
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting Roles Collection ===");
#pragma warning restore SA1101

            // Check for authentication and scopes
#pragma warning disable SA1101
            if (_graphClient == null || !await _graphClient.IsConnectedAsync())
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp("Not connected to Microsoft Graph. Please run Connect-M365 first.");
#pragma warning restore SA1101
                return;
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            var authInfo = await _graphClient.GetAuthenticationInfoAsync();
#pragma warning restore SA1101
            // Note: Scope checking is not available through Graph API directly
            // Continuing without scope validation
#pragma warning disable SA1101
            WriteVerbose("Proceeding with roles collection...");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var outputDirectory = GetOutputDirectory();
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                switch (Mode.ToUpperInvariant())
                {
                    case "ALLROLES":
#pragma warning disable SA1101
                        await ProcessAllRoleActivityAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                    case "PIMASSIGNMENTS":
#pragma warning disable SA1101
                        await ProcessPIMAssignmentsAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                    case "BOTH":
#pragma warning disable SA1101
                        await ProcessAllRoleActivityAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
#pragma warning disable SA1101
                        await ProcessPIMAssignmentsAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                }
#pragma warning restore SA1101

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
#pragma warning disable SA1101
                LogSummary(summary);
#pragma warning restore SA1101

                var result = new RolesResult
                {
                    RoleMembers = new List<RoleMember>(),
                    PIMAssignments = new List<PIMAssignment>(),
                    Summary = summary
                };

#pragma warning disable SA1101
                WriteObject(result);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during roles collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task ProcessAllRoleActivityAsync(string outputDirectory, string timestamp, RolesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting Directory Role Membership Export ===");
#pragma warning restore SA1101

            var allRoleMembers = new List<RoleMember>();
            var emptyRoles = new List<string>();
            var rolesWithUsers = new List<string>();

            try
            {
#pragma warning disable SA1101
                var allRoles = await _graphClient.GetDirectoryRolesAsync();
#pragma warning restore SA1101
                var allRolesList = allRoles?.ToList() ?? new List<DirectoryRole>();
#pragma warning disable SA1101
                WriteVerbose($"Found {allRolesList.Count} directory roles");
#pragma warning restore SA1101

                foreach (var role in allRolesList)
                {
                    summary.ProcessedRoles++;
                    var displayName = role.DisplayName;

#pragma warning disable SA1101
                    var roleMembers = await _graphClient.GetDirectoryRoleMembersAsync(role.Id);
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                            WriteVerbose($"Skipping service principal in role {displayName}");
#pragma warning restore SA1101
                            continue;
                        }

                        summary.TotalMembers++;
                        roleMemberCount++;

                        try
                        {
#pragma warning disable SA1101
                            var user = await GetUserDetailsAsync(member.Id);
#pragma warning restore SA1101

#pragma warning disable SA1101
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
#pragma warning restore SA1101

                            allRoleMembers.Add(roleMember);
                        }
                        catch (Exception ex)
                        {
#pragma warning disable SA1101
                            WriteWarningWithTimestamp($"Error processing user {member.Id} in role {displayName}: {ex.Message}");
#pragma warning restore SA1101

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
#pragma warning disable SA1101
                    await WriteRoleMembersAsync(allRoleMembers, fileName);
#pragma warning restore SA1101
                    summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                    WriteVerbose($"Role memberships written to: {fileName}");
#pragma warning restore SA1101
                }

                // Log summary information
#pragma warning disable SA1101
                LogRolesSummaryInfo(rolesWithUsers, emptyRoles, summary);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during directory roles processing: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task ProcessPIMAssignmentsAsync(string outputDirectory, string timestamp, RolesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting PIM Role Assignment Export ===");
#pragma warning restore SA1101

            var allAssignments = new List<PIMAssignment>();

            try
            {
                // Get active PIM assignments
#pragma warning disable SA1101
                WriteVerbose("Retrieving active PIM assignments...");
#pragma warning restore SA1101
#pragma warning disable SA1101
                var activeAssignments = await _graphClient.GetPIMActiveAssignmentsAsync();
#pragma warning restore SA1101

                foreach (var assignment in activeAssignments)
                {
                    try
                    {
#pragma warning disable SA1101
                        var pimAssignment = await ProcessPIMAssignmentAsync(assignment, "Active");
#pragma warning restore SA1101
                        if (pimAssignment != null)
                        {
                            allAssignments.Add(pimAssignment);
                            summary.PIMActiveAssignments++;
                        }
                    }
                    catch (Exception ex)
                    {
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"Failed to process active PIM assignment: {ex.Message}");
#pragma warning restore SA1101
                    }
                }

                // Get eligible PIM assignments
#pragma warning disable SA1101
                WriteVerbose("Retrieving eligible PIM assignments...");
#pragma warning restore SA1101
#pragma warning disable SA1101
                var eligibleAssignments = await _graphClient.GetPIMEligibleAssignmentsAsync();
#pragma warning restore SA1101

                foreach (var assignment in eligibleAssignments)
                {
                    try
                    {
#pragma warning disable SA1101
                        var pimAssignment = await ProcessPIMAssignmentAsync(assignment, "Eligible");
#pragma warning restore SA1101
                        if (pimAssignment != null)
                        {
                            allAssignments.Add(pimAssignment);
                            summary.PIMEligibleAssignments++;
                        }
                    }
                    catch (Exception ex)
                    {
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"Failed to process eligible PIM assignment: {ex.Message}");
#pragma warning restore SA1101
                    }
                }

                // Write results
                if (allAssignments.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-PIM-Assignments.csv");
#pragma warning disable SA1101
                    await WritePIMAssignmentsAsync(allAssignments, fileName);
#pragma warning restore SA1101
                    summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                    WriteVerbose($"PIM assignments written to: {fileName}");
#pragma warning restore SA1101

#pragma warning disable SA1101
                    LogPIMSummaryInfo(allAssignments, summary);
#pragma warning restore SA1101
                }
                else
                {
#pragma warning disable SA1101
                    WriteVerbose("No PIM assignments found");
#pragma warning restore SA1101
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during PIM assignments processing: {ex.Message}");
#pragma warning restore SA1101
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

#pragma warning disable SA1101
                WriteVerbose($"Processing group {groupName} with role {pimAssignment.RoleName}");
#pragma warning restore SA1101

                try
                {
#pragma warning disable SA1101
                    var groupMembers = await _graphClient.GetGroupMembersAsync(groupId);
#pragma warning restore SA1101
                    var groupMemberCount = 0;

                    foreach (var member in groupMembers)
                    {
                        if (member.OdataType?.Contains("user") == true)
                        {
                            try
                            {
#pragma warning disable SA1101
                                var userDetails = await _graphClient.GetUserAsync(member.Id);
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                                WriteWarningWithTimestamp($"Could not process user {member.Id} in group {groupName}: {ex.Message}");
#pragma warning restore SA1101
                            }
                        }
                    }

                    if (groupMemberCount == 0)
                    {
#pragma warning disable SA1101
                        WriteVerbose($"Group {groupName} has no user members");
#pragma warning restore SA1101
                        return null;
                    }
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Error processing group members for {groupName}: {ex.Message}");
#pragma warning restore SA1101
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

#pragma warning disable SA1101
                var user = await _graphClient.GetUserAsync(userId, selectProperties);
#pragma warning restore SA1101

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
#pragma warning disable SA1101
                    WriteVerbose("Rate limit encountered, waiting 5 seconds...");
#pragma warning restore SA1101
                    await Task.Delay(5000);
#pragma warning disable SA1101
                    return await GetUserDetailsAsync(userId); // Retry
#pragma warning restore SA1101
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
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("Roles with users:");
#pragma warning restore SA1101
            foreach (var role in rolesWithUsers)
            {
#pragma warning disable SA1101
                WriteVerbose($"  + {role}");
#pragma warning restore SA1101
            }

#pragma warning disable SA1101
            if (IncludeEmptyRoles && emptyRoles.Count > 0)
            {
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose("Empty roles:");
#pragma warning restore SA1101
                foreach (var emptyRole in emptyRoles)
                {
#pragma warning disable SA1101
                    WriteVerbose($"  - {emptyRole}");
#pragma warning restore SA1101
                }
            }
#pragma warning restore SA1101
        }

        private void LogPIMSummaryInfo(List<PIMAssignment> assignments, RolesSummary summary)
        {
            var directCount = assignments.Count(a => a.SourceType == "Direct");
            var groupCount = assignments.Count(a => a.SourceType == "Group");
            var onPremSyncedCount = assignments.Count(a => a.OnPremisesSynced);
            var cloudOnlyCount = assignments.Count(a => !a.OnPremisesSynced);

#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("PIM Assignment Summary:");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($" - Direct assignments: {directCount}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($" - Group-inherited assignments: {groupCount}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($" - On-premises synced users: {onPremSyncedCount}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($" - Cloud-only users: {cloudOnlyCount}");
#pragma warning restore SA1101
        }

        private string GetOutputDirectory()
        {
#pragma warning disable SA1101
            var directory = OutputDir;
#pragma warning restore SA1101

            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
#pragma warning disable SA1101
                WriteVerbose($"Created output directory: {directory}");
#pragma warning restore SA1101
            }

            return directory;
        }

        private void LogSummary(RolesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("=== Roles Collection Summary ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (Mode == "AllRoles" || Mode == "Both")
            {
#pragma warning disable SA1101
                WriteVerbose($"Total roles processed: {summary.ProcessedRoles}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"Roles with members: {summary.RolesWithMembers}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"Roles without members: {summary.RolesWithoutMembers}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"Total role user assignments: {summary.TotalMembers}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (Mode == "PIMAssignments" || Mode == "Both")
            {
#pragma warning disable SA1101
                WriteVerbose($"PIM Active assignments: {summary.PIMActiveAssignments}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"PIM Eligible assignments: {summary.PIMEligibleAssignments}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("Output Files:");
#pragma warning restore SA1101
            foreach (var file in summary.OutputFiles)
            {
#pragma warning disable SA1101
                WriteVerbose($"  - {file}");
#pragma warning restore SA1101
            }
#pragma warning disable SA1101
            WriteVerbose("===================================");
#pragma warning restore SA1101
        }

        private async Task WriteRoleMembersAsync(IEnumerable<RoleMember> members, string filePath)
        {
            var csv = "Role,UserName,UserId,DisplayName,Department,JobTitle,AccountEnabled,CreatedDateTime,LastInteractiveSignIn,LastNonInteractiveSignIn,DaysSinceLastSignIn" + Environment.NewLine;

            foreach (var member in members)
            {
#pragma warning disable SA1101
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
#pragma warning restore SA1101

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WritePIMAssignmentsAsync(IEnumerable<PIMAssignment> assignments, string filePath)
        {
            var csv = "RoleName,UserPrincipalName,DisplayName,AssignmentType,SourceType,SourceName,OnPremisesSynced,AssignmentStatus,StartDateTime,EndDateTime,DirectoryScopeId" + Environment.NewLine;

            foreach (var assignment in assignments)
            {
#pragma warning disable SA1101
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
#pragma warning restore SA1101

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
#pragma warning disable SA1600

#pragma warning restore SA1600
    // Supporting classes
#pragma warning disable SA1600
    public class RolesResult
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
        public List<RoleMember> RoleMembers { get
#pragma warning restore SA1600
List<RoleMember>();
        public List<PIMAssignment> PIMAssignments { get; set; } = new List<PIMAssignment>();
#pragma warning disable SA1600
        public RolesSummary Summary { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class RoleMember
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Role { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string DisplayName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Department { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string JobTitle { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool AccountEnabled { get; set; }
        public DateTime? CreatedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? LastInteractiveSignIn { get; set; }
#pragma warning restore SA1600
        public DateTime? LastNonInteractiveSignIn { get; set; }
#pragma warning disable SA1600
        public string DaysSinceLastSignIn { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class PIMAssignment
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RoleName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserPrincipalName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string DisplayName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string AssignmentType { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string SourceType { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string SourceName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool OnPremisesSynced { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string AssignmentStatus { get; set; }
        public DateTime? StartDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? EndDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string EndDateTimeString { get; set; }public string DirectoryScopeId { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class UserDetails
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserPrincipalName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string DisplayName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Department { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string JobTitle { get; set; }
        public bool? AccountEnabled { get; set; }
#pragma warning restore SA1600
        public DateTime? CreatedDateTime { get; set; }
#pragma warning disable SA1600
        public SignInActivity SignInActivity { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class SignInActivity
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
        public DateTime? LastSignInDateTime { get; set; }
        public DateTime? LastNonInteractiveSignInDateTime { get; set; }
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class RolesSummary
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int ProcessedRoles { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int RolesWithMembers { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int RolesWithoutMembers { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalMembers { get; set; }
#pragma warning restore SA1600
        public int PIMActiveAssignments { get; set; }
        public int PIMEligibleAssignments { get; set; }public List<string> OutputFiles { get; set; } = new List<string>();
    }
}
