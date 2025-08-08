using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Graph;

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

        private readonly GraphApiClient _graphClient;
        private readonly string[] RequiredScopes = { 
            "User.Read.All", 
            "Directory.Read.All", 
            "AuditLog.Read.All",
            "RoleAssignmentSchedule.Read.Directory", 
            "RoleEligibilitySchedule.Read.Directory" 
        };

        public GetRolesCmdlet()
        {
            _graphClient = new GraphApiClient();
        }

        protected override async Task ProcessRecordAsync()
        {
            LogInformation("=== Starting Roles Collection ===");
            
            // Check for authentication and scopes
            if (!await _graphClient.IsConnectedAsync())
            {
                LogError("Not connected to Microsoft Graph. Please run Connect-M365 first.");
                return;
            }

            var authInfo = await _graphClient.GetAuthenticationInfoAsync();
            var missingScopes = RequiredScopes.Except(authInfo.Scopes).ToList();
            if (missingScopes.Count > 0)
            {
                LogWarning($"Missing some recommended scopes: {string.Join(", ", missingScopes)}");
                LogInformation("Some data may not be accessible without proper permissions.");
            }

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
                LogError($"An error occurred during roles collection: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessAllRoleActivityAsync(string outputDirectory, string timestamp, RolesSummary summary)
        {
            LogInformation("=== Starting Directory Role Membership Export ===");

            var allRoleMembers = new List<RoleMember>();
            var emptyRoles = new List<string>();
            var rolesWithUsers = new List<string>();

            try
            {
                var allRoles = await _graphClient.GetDirectoryRolesAsync();
                LogInformation($"Found {allRoles.Count} directory roles");

                foreach (var role in allRoles)
                {
                    summary.ProcessedRoles++;
                    var displayName = role.DisplayName;
                    
                    var roleMembers = await _graphClient.GetDirectoryRoleMembersAsync(role.Id);
                    
                    if (roleMembers == null || roleMembers.Count == 0)
                    {
                        summary.RolesWithoutMembers++;
                        emptyRoles.Add(displayName);
                        continue;
                    }
                    
                    summary.RolesWithMembers++;
                    var roleMemberCount = 0;
                    
                    foreach (var member in roleMembers)
                    {
                        // Skip service principals
                        if (member.ODataType?.Contains("servicePrincipal") == true)
                        {
                            LogInformation($"Skipping service principal in role {displayName}");
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
                            LogWarning($"Error processing user {member.Id} in role {displayName}: {ex.Message}");
                            
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
                    
                    LogInformation($"Role memberships written to: {fileName}");
                }

                // Log summary information
                LogRolesSummaryInfo(rolesWithUsers, emptyRoles, summary);
            }
            catch (Exception ex)
            {
                LogError($"An error occurred during directory roles processing: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessPIMAssignmentsAsync(string outputDirectory, string timestamp, RolesSummary summary)
        {
            LogInformation("=== Starting PIM Role Assignment Export ===");

            var allAssignments = new List<PIMAssignment>();

            try
            {
                // Get active PIM assignments
                LogInformation("Retrieving active PIM assignments...");
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
                        LogWarning($"Failed to process active PIM assignment: {ex.Message}");
                    }
                }

                // Get eligible PIM assignments
                LogInformation("Retrieving eligible PIM assignments...");
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
                        LogWarning($"Failed to process eligible PIM assignment: {ex.Message}");
                    }
                }

                // Write results
                if (allAssignments.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-PIM-Assignments.csv");
                    await WritePIMAssignmentsAsync(allAssignments, fileName);
                    summary.OutputFiles.Add(fileName);
                    
                    LogInformation($"PIM assignments written to: {fileName}");
                    
                    LogPIMSummaryInfo(allAssignments, summary);
                }
                else
                {
                    LogInformation("No PIM assignments found");
                }
            }
            catch (Exception ex)
            {
                LogError($"An error occurred during PIM assignments processing: {ex.Message}");
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
            var principalType = assignment.Principal?.ODataType?.ToString();
            
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
                
                LogInformation($"Processing group {groupName} with role {pimAssignment.RoleName}");
                
                try
                {
                    var groupMembers = await _graphClient.GetGroupMembersAsync(groupId);
                    var groupMemberCount = 0;
                    
                    foreach (var member in groupMembers)
                    {
                        if (member.ODataType?.Contains("user") == true)
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
                                LogWarning($"Could not process user {member.Id} in group {groupName}: {ex.Message}");
                            }
                        }
                    }
                    
                    if (groupMemberCount == 0)
                    {
                        LogInformation($"Group {groupName} has no user members");
                        return null;
                    }
                }
                catch (Exception ex)
                {
                    LogWarning($"Error processing group members for {groupName}: {ex.Message}");
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
                    CreatedDateTime = user.CreatedDateTime,
                    SignInActivity = user.SignInActivity != null ? new SignInActivity
                    {
                        LastSignInDateTime = user.SignInActivity.LastSignInDateTime,
                        LastNonInteractiveSignInDateTime = user.SignInActivity.LastNonInteractiveSignInDateTime
                    } : null
                };
            }
            catch (Exception ex)
            {
                // Handle rate limiting
                if (ex.Message.Contains("429"))
                {
                    LogInformation("Rate limit encountered, waiting 5 seconds...");
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
            LogInformation("");
            LogInformation("Roles with users:");
            foreach (var role in rolesWithUsers)
            {
                LogInformation($"  + {role}");
            }
            
            if (IncludeEmptyRoles && emptyRoles.Count > 0)
            {
                LogInformation("");
                LogInformation("Empty roles:");
                foreach (var emptyRole in emptyRoles)
                {
                    LogInformation($"  - {emptyRole}");
                }
            }
        }

        private void LogPIMSummaryInfo(List<PIMAssignment> assignments, RolesSummary summary)
        {
            var directCount = assignments.Count(a => a.SourceType == "Direct");
            var groupCount = assignments.Count(a => a.SourceType == "Group");
            var onPremSyncedCount = assignments.Count(a => a.OnPremisesSynced);
            var cloudOnlyCount = assignments.Count(a => !a.OnPremisesSynced);

            LogInformation("");
            LogInformation("PIM Assignment Summary:");
            LogInformation($" - Direct assignments: {directCount}");
            LogInformation($" - Group-inherited assignments: {groupCount}");
            LogInformation($" - On-premises synced users: {onPremSyncedCount}");
            LogInformation($" - Cloud-only users: {cloudOnlyCount}");
        }

        private string GetOutputDirectory()
        {
            var directory = OutputDir;
            
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
                LogInformation($"Created output directory: {directory}");
            }

            return directory;
        }

        private void LogSummary(RolesSummary summary)
        {
            LogInformation("");
            LogInformation("=== Roles Collection Summary ===");
            LogInformation($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
            
            if (Mode == "AllRoles" || Mode == "Both")
            {
                LogInformation($"Total roles processed: {summary.ProcessedRoles}");
                LogInformation($"Roles with members: {summary.RolesWithMembers}");
                LogInformation($"Roles without members: {summary.RolesWithoutMembers}");
                LogInformation($"Total role user assignments: {summary.TotalMembers}");
            }
            
            if (Mode == "PIMAssignments" || Mode == "Both")
            {
                LogInformation($"PIM Active assignments: {summary.PIMActiveAssignments}");
                LogInformation($"PIM Eligible assignments: {summary.PIMEligibleAssignments}");
            }
            
            LogInformation("");
            LogInformation("Output Files:");
            foreach (var file in summary.OutputFiles)
            {
                LogInformation($"  - {file}");
            }
            LogInformation("===================================");
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
            
            await File.WriteAllTextAsync(filePath, csv);
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
            
            await File.WriteAllTextAsync(filePath, csv);
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