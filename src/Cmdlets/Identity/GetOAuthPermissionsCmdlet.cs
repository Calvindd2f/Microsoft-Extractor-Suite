using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Graph;

namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    /// <summary>
    /// Cmdlet to collect OAuth permissions and application consents for security analysis
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "OAuthPermissions")]
    [OutputType(typeof(OAuthPermissionsResult))]
    public class GetOAuthPermissionsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve permissions for. If not specified, retrieves for all users")]
        public string[] UserIds { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
        public string OutputDir { get; set; } = "Output\\OAuthPermissions";

        [Parameter(
            HelpMessage = "File encoding for output files")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(
            HelpMessage = "Use Graph API method instead of legacy method")]
        public SwitchParameter UseGraphAPI { get; set; } = true;

        [Parameter(
            HelpMessage = "Include detailed permission scope information")]
        public SwitchParameter IncludeDetailedScopes { get; set; }

        [Parameter(
            HelpMessage = "Filter by high-risk permissions only")]
        public SwitchParameter HighRiskOnly { get; set; }

        private GraphApiClient? _graphClient;

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
            WriteVerbose("=== Starting OAuth Permissions Collection ===");

            // Check for authentication
            if (_graphClient == null || !await _graphClient.IsConnectedAsync())
            {
                WriteErrorWithTimestamp("Not connected to Microsoft Graph. Please run Connect-M365 first.");
                return;
            }

            var outputDirectory = GetOutputDirectory();
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmm");

            var summary = new OAuthPermissionsSummary
            {
                StartTime = DateTime.Now,
                ProcessedApplications = 0,
                ProcessedUsers = 0,
                TotalPermissions = 0,
                HighRiskPermissions = 0,
                OutputFiles = new List<string>()
            };

            try
            {
                if (UseGraphAPI)
                {
                    await ProcessGraphMethodAsync(outputDirectory, timestamp, summary);
                }
                else
                {
                    await ProcessLegacyMethodAsync(outputDirectory, timestamp, summary);
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
                LogSummary(summary);

                var result = new OAuthPermissionsResult
                {
                    Applications = new List<ApplicationPermission>(),
                    UserConsents = new List<UserConsentPermission>(),
                    ServicePrincipals = new List<ServicePrincipalPermission>(),
                    Summary = summary
                };

                WriteObject(result);
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during OAuth permissions collection: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessGraphMethodAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
            WriteVerbose("Using Graph API method for OAuth permissions collection");

            // Get all application registrations
            await ProcessApplicationRegistrationsAsync(outputDirectory, timestamp, summary);

            // Get service principals and their permissions
            await ProcessServicePrincipalsAsync(outputDirectory, timestamp, summary);

            // Get user consents
            if (UserIds != null && UserIds.Length > 0)
            {
                await ProcessSpecificUsersAsync(outputDirectory, timestamp, summary);
            }
            else
            {
                await ProcessAllUserConsentsAsync(outputDirectory, timestamp, summary);
            }
        }

        private async Task ProcessApplicationRegistrationsAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
            WriteVerbose("Collecting application registrations...");

            var applications = await _graphClient.GetApplicationsAsync();
            var applicationPermissions = new List<ApplicationPermission>();

            foreach (var app in applications)
            {
                try
                {
                    var appPermission = new ApplicationPermission
                    {
                        ApplicationId = app.AppId,
                        DisplayName = app.DisplayName,
                        CreatedDateTime = app.CreatedDateTime?.DateTime,
                        PublisherDomain = app.PublisherDomain,
                        SignInAudience = app.SignInAudience,
                        RequiredResourceAccess = ProcessRequiredResourceAccess(app.RequiredResourceAccess),
                        IsHighRisk = DetermineHighRiskStatus(app.RequiredResourceAccess)
                    };

                    if (!HighRiskOnly || appPermission.IsHighRisk)
                    {
                        applicationPermissions.Add(appPermission);
                        summary.TotalPermissions += appPermission.RequiredResourceAccess?.Count ?? 0;

                        if (appPermission.IsHighRisk)
                            summary.HighRiskPermissions++;
                    }

                    summary.ProcessedApplications++;
                }
                catch (Exception ex)
                {
                    WriteWarningWithTimestamp($"Failed to process application {app.DisplayName}: {ex.Message}");
                }
            }

            if (applicationPermissions.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-ApplicationPermissions.csv");
                await WriteApplicationPermissionsAsync(applicationPermissions, fileName);
                summary.OutputFiles.Add(fileName);

                WriteVerbose($"Application permissions written to: {fileName}");
            }
        }

        private async Task ProcessServicePrincipalsAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
            WriteVerbose("Collecting service principal permissions...");

            var servicePrincipals = await _graphClient.GetServicePrincipalsAsync();
            var spPermissions = new List<ServicePrincipalPermission>();

            foreach (var sp in servicePrincipals)
            {
                try
                {
                    // Get OAuth2 permission grants
                    var oauth2Grants = await _graphClient.GetOAuth2PermissionGrantsAsync($"clientId eq '{sp.Id}'");

                    // Get app role assignments
                    var appRoleAssignments = await _graphClient.GetAppRoleAssignmentsAsync(sp.Id);

                    var spPermission = new ServicePrincipalPermission
                    {
                        ServicePrincipalId = sp.Id,
                        AppId = sp.AppId,
                        DisplayName = sp.DisplayName,
                        CreatedDateTime = sp.CreatedDateTime?.DateTime,
                        OAuth2Grants = ProcessOAuth2Grants(oauth2Grants),
                        AppRoleAssignments = ProcessAppRoleAssignments(appRoleAssignments),
                        IsHighRisk = DetermineServicePrincipalHighRisk(oauth2Grants, appRoleAssignments)
                    };

                    if (!HighRiskOnly || spPermission.IsHighRisk)
                    {
                        spPermissions.Add(spPermission);

                        if (spPermission.IsHighRisk)
                            summary.HighRiskPermissions++;
                    }
                }
                catch (Exception ex)
                {
                    WriteWarningWithTimestamp($"Failed to process service principal {sp.DisplayName}: {ex.Message}");
                }
            }

            if (spPermissions.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-ServicePrincipalPermissions.csv");
                await WriteServicePrincipalPermissionsAsync(spPermissions, fileName);
                summary.OutputFiles.Add(fileName);

                WriteVerbose($"Service principal permissions written to: {fileName}");
            }
        }

        private async Task ProcessSpecificUsersAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
            WriteVerbose($"Processing OAuth consents for {UserIds.Length} specific users...");

            var userConsents = new List<UserConsentPermission>();

            foreach (var userId in UserIds)
            {
                try
                {
                    var grants = await _graphClient.GetOAuth2PermissionGrantsAsync($"principalId eq '{userId}'");

                    foreach (var grant in grants)
                    {
                        var consent = ProcessUserConsent(grant, userId);
                        if (!HighRiskOnly || consent.IsHighRisk)
                        {
                            userConsents.Add(consent);

                            if (consent.IsHighRisk)
                                summary.HighRiskPermissions++;
                        }
                    }

                    summary.ProcessedUsers++;
                }
                catch (Exception ex)
                {
                    WriteWarningWithTimestamp($"Failed to process user consents for {userId}: {ex.Message}");
                }
            }

            if (userConsents.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-UserConsents.csv");
                await WriteUserConsentsAsync(userConsents, fileName);
                summary.OutputFiles.Add(fileName);

                WriteVerbose($"User consents written to: {fileName}");
            }
        }

        private async Task ProcessAllUserConsentsAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
            WriteVerbose("Processing OAuth consents for all users...");

            var allGrants = await _graphClient.GetOAuth2PermissionGrantsAsync();
            var userConsents = new List<UserConsentPermission>();

            var processedUsers = new HashSet<string>();

            foreach (var grant in allGrants)
            {
                try
                {
                    if (!string.IsNullOrEmpty(grant.PrincipalId))
                    {
                        processedUsers.Add(grant.PrincipalId);

                        var consent = ProcessUserConsent(grant, grant.PrincipalId);
                        if (!HighRiskOnly || consent.IsHighRisk)
                        {
                            userConsents.Add(consent);

                            if (consent.IsHighRisk)
                                summary.HighRiskPermissions++;
                        }
                    }
                }
                catch (Exception ex)
                {
                    WriteWarningWithTimestamp($"Failed to process user consent: {ex.Message}");
                }
            }

            summary.ProcessedUsers = processedUsers.Count;

            if (userConsents.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-AllUserConsents.csv");
                await WriteUserConsentsAsync(userConsents, fileName);
                summary.OutputFiles.Add(fileName);

                WriteVerbose($"User consents written to: {fileName}");
            }
        }

        private async Task ProcessLegacyMethodAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
            WriteVerbose("Using legacy Exchange method for OAuth permissions collection");
            WriteWarningWithTimestamp("Legacy method implementation not available in C# version. Please use Graph API method.");

            // For the legacy method, we would typically use Exchange Online PowerShell commands
            // This would require different authentication and cmdlets
            throw new NotImplementedException("Legacy Exchange method is not implemented in C# version. Use -UseGraphAPI parameter.");
        }

        private List<RequiredResourceAccessInfo> ProcessRequiredResourceAccess(dynamic requiredResourceAccess)
        {
            var resourceAccess = new List<RequiredResourceAccessInfo>();

            if (requiredResourceAccess != null)
            {
                foreach (var resource in requiredResourceAccess)
                {
                    var info = new RequiredResourceAccessInfo
                    {
                        ResourceAppId = resource.ResourceAppId?.ToString(),
                        ResourceAccess = ProcessResourceAccess(resource.ResourceAccess)
                    };

                    resourceAccess.Add(info);
                }
            }

            return resourceAccess;
        }

        private List<ResourceAccessInfo> ProcessResourceAccess(dynamic resourceAccess)
        {
            var accessList = new List<ResourceAccessInfo>();

            if (resourceAccess != null)
            {
                foreach (var access in resourceAccess)
                {
                    var info = new ResourceAccessInfo
                    {
                        Id = access.Id?.ToString(),
                        Type = access.Type?.ToString()
                    };

                    accessList.Add(info);
                }
            }

            return accessList;
        }

        private List<OAuth2GrantInfo> ProcessOAuth2Grants(IEnumerable<dynamic> grants)
        {
            var grantList = new List<OAuth2GrantInfo>();

            foreach (var grant in grants)
            {
                var info = new OAuth2GrantInfo
                {
                    Id = grant.Id?.ToString(),
                    ClientId = grant.ClientId?.ToString(),
                    ConsentType = grant.ConsentType?.ToString(),
                    PrincipalId = grant.PrincipalId?.ToString(),
                    ResourceId = grant.ResourceId?.ToString(),
                    Scope = grant.Scope?.ToString(),
                    CreatedDateTime = grant.CreatedDateTime?.DateTime
                };

                grantList.Add(info);
            }

            return grantList;
        }

        private List<AppRoleAssignmentInfo> ProcessAppRoleAssignments(IEnumerable<dynamic> assignments)
        {
            var assignmentList = new List<AppRoleAssignmentInfo>();

            foreach (var assignment in assignments)
            {
                var info = new AppRoleAssignmentInfo
                {
                    Id = assignment.Id?.ToString(),
                    AppRoleId = assignment.AppRoleId?.ToString(),
                    PrincipalDisplayName = assignment.PrincipalDisplayName?.ToString(),
                    PrincipalId = assignment.PrincipalId?.ToString(),
                    PrincipalType = assignment.PrincipalType?.ToString(),
                    ResourceDisplayName = assignment.ResourceDisplayName?.ToString(),
                    ResourceId = assignment.ResourceId?.ToString(),
                    CreatedDateTime = assignment.CreatedDateTime?.DateTime
                };

                assignmentList.Add(info);
            }

            return assignmentList;
        }

        private UserConsentPermission ProcessUserConsent(dynamic grant, string userId)
        {
            return new UserConsentPermission
            {
                UserId = userId,
                ClientId = grant.ClientId?.ToString(),
                ConsentType = grant.ConsentType?.ToString(),
                ResourceId = grant.ResourceId?.ToString(),
                Scope = grant.Scope?.ToString(),
                CreatedDateTime = grant.CreatedDateTime?.DateTime,
                IsHighRisk = DetermineUserConsentHighRisk(grant.Scope?.ToString())
            };
        }

        private bool DetermineHighRiskStatus(dynamic requiredResourceAccess)
        {
            // Define high-risk permissions
            var highRiskPermissions = new[]
            {
                "Directory.ReadWrite.All",
                "Directory.AccessAsUser.All",
                "User.ReadWrite.All",
                "Mail.ReadWrite",
                "Files.ReadWrite.All",
                "Sites.ReadWrite.All",
                "RoleManagement.ReadWrite.Directory"
            };

            // This is a simplified check - in practice, you'd want more sophisticated logic
            return false; // Placeholder implementation
        }

        private bool DetermineServicePrincipalHighRisk(IEnumerable<dynamic> oauth2Grants, IEnumerable<dynamic> appRoleAssignments)
        {
            // Check for high-risk OAuth2 grants and app role assignments
            return false; // Placeholder implementation
        }

        private bool DetermineUserConsentHighRisk(string scope)
        {
            if (string.IsNullOrEmpty(scope))
                return false;

            var highRiskScopes = new[]
            {
                "Directory.ReadWrite.All",
                "User.ReadWrite.All",
                "Mail.ReadWrite",
                "Files.ReadWrite.All"
            };

            return highRiskScopes.Any(hrs => scope.IndexOf(hrs, StringComparison.OrdinalIgnoreCase) >= 0);
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

        private void LogSummary(OAuthPermissionsSummary summary)
        {
            WriteVerbose("");
            WriteVerbose("=== OAuth Permissions Collection Summary ===");
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
            WriteVerbose($"Applications Processed: {summary.ProcessedApplications:N0}");
            WriteVerbose($"Users Processed: {summary.ProcessedUsers:N0}");
            WriteVerbose($"Total Permissions: {summary.TotalPermissions:N0}");
            WriteVerbose($"High-Risk Permissions: {summary.HighRiskPermissions:N0}");
            WriteVerbose("");
            WriteVerbose("Output Files:");
            foreach (var file in summary.OutputFiles)
            {
                WriteVerbose($"  - {file}");
            }
            WriteVerbose("============================================");
        }

        private async Task WriteApplicationPermissionsAsync(IEnumerable<ApplicationPermission> permissions, string filePath)
        {
            var csv = "ApplicationId,DisplayName,CreatedDateTime,PublisherDomain,SignInAudience,RequiredResourceAccess,IsHighRisk" + Environment.NewLine;

            foreach (var perm in permissions)
            {
                var resourceAccessJson = JsonSerializer.Serialize(perm.RequiredResourceAccess);
                var values = new[]
                {
                    EscapeCsvValue(perm.ApplicationId),
                    EscapeCsvValue(perm.DisplayName),
                    perm.CreatedDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(perm.PublisherDomain),
                    EscapeCsvValue(perm.SignInAudience),
                    EscapeCsvValue(resourceAccessJson),
                    perm.IsHighRisk.ToString()
                };

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteServicePrincipalPermissionsAsync(IEnumerable<ServicePrincipalPermission> permissions, string filePath)
        {
            var csv = "ServicePrincipalId,AppId,DisplayName,CreatedDateTime,OAuth2Grants,AppRoleAssignments,IsHighRisk" + Environment.NewLine;

            foreach (var perm in permissions)
            {
                var oauth2GrantsJson = JsonSerializer.Serialize(perm.OAuth2Grants);
                var appRoleAssignmentsJson = JsonSerializer.Serialize(perm.AppRoleAssignments);

                var values = new[]
                {
                    EscapeCsvValue(perm.ServicePrincipalId),
                    EscapeCsvValue(perm.AppId),
                    EscapeCsvValue(perm.DisplayName),
                    perm.CreatedDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(oauth2GrantsJson),
                    EscapeCsvValue(appRoleAssignmentsJson),
                    perm.IsHighRisk.ToString()
                };

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteUserConsentsAsync(IEnumerable<UserConsentPermission> consents, string filePath)
        {
            var csv = "UserId,ClientId,ConsentType,ResourceId,Scope,CreatedDateTime,IsHighRisk" + Environment.NewLine;

            foreach (var consent in consents)
            {
                var values = new[]
                {
                    EscapeCsvValue(consent.UserId),
                    EscapeCsvValue(consent.ClientId),
                    EscapeCsvValue(consent.ConsentType),
                    EscapeCsvValue(consent.ResourceId),
                    EscapeCsvValue(consent.Scope),
                    consent.CreatedDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    consent.IsHighRisk.ToString()
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

    // Result and supporting classes
    public class OAuthPermissionsResult
    {
        public List<ApplicationPermission> Applications { get; set; } = new List<ApplicationPermission>();
        public List<UserConsentPermission> UserConsents { get; set; } = new List<UserConsentPermission>();
        public List<ServicePrincipalPermission> ServicePrincipals { get; set; } = new List<ServicePrincipalPermission>();
        public OAuthPermissionsSummary Summary { get; set; }
    }

    public class ApplicationPermission
    {
        public string ApplicationId { get; set; }
        public string DisplayName { get; set; }
        public DateTime? CreatedDateTime { get; set; }
        public string PublisherDomain { get; set; }
        public string SignInAudience { get; set; }
        public List<RequiredResourceAccessInfo> RequiredResourceAccess { get; set; } = new List<RequiredResourceAccessInfo>();
        public bool IsHighRisk { get; set; }
    }

    public class ServicePrincipalPermission
    {
        public string ServicePrincipalId { get; set; }
        public string AppId { get; set; }
        public string DisplayName { get; set; }
        public DateTime? CreatedDateTime { get; set; }
        public List<OAuth2GrantInfo> OAuth2Grants { get; set; } = new List<OAuth2GrantInfo>();
        public List<AppRoleAssignmentInfo> AppRoleAssignments { get; set; } = new List<AppRoleAssignmentInfo>();
        public bool IsHighRisk { get; set; }
    }

    public class UserConsentPermission
    {
        public string UserId { get; set; }
        public string ClientId { get; set; }
        public string ConsentType { get; set; }
        public string ResourceId { get; set; }
        public string Scope { get; set; }
        public DateTime? CreatedDateTime { get; set; }
        public bool IsHighRisk { get; set; }
    }

    public class RequiredResourceAccessInfo
    {
        public string ResourceAppId { get; set; }
        public List<ResourceAccessInfo> ResourceAccess { get; set; } = new List<ResourceAccessInfo>();
    }

    public class ResourceAccessInfo
    {
        public string Id { get; set; }
        public string Type { get; set; }
    }

    public class OAuth2GrantInfo
    {
        public string Id { get; set; }
        public string ClientId { get; set; }
        public string ConsentType { get; set; }
        public string PrincipalId { get; set; }
        public string ResourceId { get; set; }
        public string Scope { get; set; }
        public DateTime? CreatedDateTime { get; set; }
    }

    public class AppRoleAssignmentInfo
    {
        public string Id { get; set; }
        public string AppRoleId { get; set; }
        public string PrincipalDisplayName { get; set; }
        public string PrincipalId { get; set; }
        public string PrincipalType { get; set; }
        public string ResourceDisplayName { get; set; }
        public string ResourceId { get; set; }
        public DateTime? CreatedDateTime { get; set; }
    }

    public class OAuthPermissionsSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public int ProcessedApplications { get; set; }
        public int ProcessedUsers { get; set; }
        public int TotalPermissions { get; set; }
        public int HighRiskPermissions { get; set; }
        public List<string> OutputFiles { get; set; } = new List<string>();
    }
}