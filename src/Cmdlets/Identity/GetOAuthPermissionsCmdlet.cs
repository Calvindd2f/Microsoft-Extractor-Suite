namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Text.Json;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Graph;


    /// <summary>
    /// Cmdlet to collect OAuth permissions and application consents for security analysis
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "OAuthPermissions")]
    [OutputType(typeof(OAuthPermissionsResult))]
    public class GetOAuthPermissionsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve permissions for. If not specified, retrieves for all users")]
#pragma warning disable SA1600
        public string[] UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
#pragma warning disable SA1600
        public string OutputDir { get; set; } = "Output\\OAuthPermissions";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "File encoding for output files")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Use Graph API method instead of legacy method")]
#pragma warning disable SA1600
        public SwitchParameter UseGraphAPI { get; set; } = true;
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Include detailed permission scope information")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeDetailedScopes { get; set; }

        [Parameter(
            HelpMessage = "Filter by high-risk permissions only")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1309
        public SwitchParameter HighRiskOnly { get; set; }
#pragma warning disable SA1201
        private GraphApiClient? _graphClient;
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning restore SA1309
sho

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
            WriteVerbose("=== Starting OAuth Permissions Collection ===");
#pragma warning restore SA1101

            // Check for authentication
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
            var outputDirectory = GetOutputDirectory();
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                if (UseGraphAPI)
                {
#pragma warning disable SA1101
                    await ProcessGraphMethodAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                }
                else
                {
#pragma warning disable SA1101
                    await ProcessLegacyMethodAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
#pragma warning disable SA1101
                LogSummary(summary);
#pragma warning restore SA1101

                var result = new OAuthPermissionsResult
                {
                    Applications = new List<ApplicationPermission>(),
                    UserConsents = new List<UserConsentPermission>(),
                    ServicePrincipals = new List<ServicePrincipalPermission>(),
                    Summary = summary
                };

#pragma warning disable SA1101
                WriteObject(result);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during OAuth permissions collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task ProcessGraphMethodAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Using Graph API method for OAuth permissions collection");
#pragma warning restore SA1101

            // Get all application registrations
#pragma warning disable SA1101
            await ProcessApplicationRegistrationsAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101

            // Get service principals and their permissions
#pragma warning disable SA1101
            await ProcessServicePrincipalsAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101

            // Get user consents
#pragma warning disable SA1101
            if (UserIds != null && UserIds.Length > 0)
            {
#pragma warning disable SA1101
                await ProcessSpecificUsersAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                await ProcessAllUserConsentsAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        private async Task ProcessApplicationRegistrationsAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Collecting application registrations...");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var applications = await _graphClient.GetApplicationsAsync();
#pragma warning restore SA1101
            var applicationPermissions = new List<ApplicationPermission>();

            foreach (var app in applications)
            {
                try
                {
#pragma warning disable SA1101
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
#pragma warning restore SA1101

#pragma warning disable SA1101
                    if (!HighRiskOnly || appPermission.IsHighRisk)
                    {
                        applicationPermissions.Add(appPermission);
                        summary.TotalPermissions += appPermission.RequiredResourceAccess?.Count ?? 0;

                        if (appPermission.IsHighRisk)
                            summary.HighRiskPermissions++;
                    }
#pragma warning restore SA1101

                    summary.ProcessedApplications++;
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Failed to process application {app.DisplayName}: {ex.Message}");
#pragma warning restore SA1101
                }
            }

            if (applicationPermissions.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-ApplicationPermissions.csv");
#pragma warning disable SA1101
                await WriteApplicationPermissionsAsync(applicationPermissions, fileName);
#pragma warning restore SA1101
                summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                WriteVerbose($"Application permissions written to: {fileName}");
#pragma warning restore SA1101
            }
        }

        private async Task ProcessServicePrincipalsAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Collecting service principal permissions...");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var servicePrincipals = await _graphClient.GetServicePrincipalsAsync();
#pragma warning restore SA1101
            var spPermissions = new List<ServicePrincipalPermission>();

            foreach (var sp in servicePrincipals)
            {
                try
                {
                    // Get OAuth2 permission grants
#pragma warning disable SA1101
                    var oauth2Grants = await _graphClient.GetOAuth2PermissionGrantsAsync($"clientId eq '{sp.Id}'");
#pragma warning restore SA1101

                    // Get app role assignments
#pragma warning disable SA1101
                    var appRoleAssignments = await _graphClient.GetAppRoleAssignmentsAsync(sp.Id);
#pragma warning restore SA1101

#pragma warning disable SA1101
                    var spPermission = new ServicePrincipalPermission
                    {
                        ServicePrincipalId = sp.Id,
                        AppId = sp.AppId,
                        DisplayName = sp.DisplayName,
                        CreatedDateTime = null, // CreatedDateTime not available in SDK v5
                        OAuth2Grants = ProcessOAuth2Grants(oauth2Grants),
                        AppRoleAssignments = ProcessAppRoleAssignments(appRoleAssignments),
                        IsHighRisk = DetermineServicePrincipalHighRisk(oauth2Grants, appRoleAssignments)
                    };
#pragma warning restore SA1101

#pragma warning disable SA1101
                    if (!HighRiskOnly || spPermission.IsHighRisk)
                    {
                        spPermissions.Add(spPermission);

                        if (spPermission.IsHighRisk)
                            summary.HighRiskPermissions++;
                    }
#pragma warning restore SA1101
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Failed to process service principal {sp.DisplayName}: {ex.Message}");
#pragma warning restore SA1101
                }
            }

            if (spPermissions.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-ServicePrincipalPermissions.csv");
#pragma warning disable SA1101
                await WriteServicePrincipalPermissionsAsync(spPermissions, fileName);
#pragma warning restore SA1101
                summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                WriteVerbose($"Service principal permissions written to: {fileName}");
#pragma warning restore SA1101
            }
        }

        private async Task ProcessSpecificUsersAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose($"Processing OAuth consents for {UserIds.Length} specific users...");
#pragma warning restore SA1101

            var userConsents = new List<UserConsentPermission>();

#pragma warning disable SA1101
            foreach (var userId in UserIds)
            {
                try
                {
#pragma warning disable SA1101
                    var grants = await _graphClient.GetOAuth2PermissionGrantsAsync($"principalId eq '{userId}'");
#pragma warning restore SA1101

                    foreach (var grant in grants)
                    {
#pragma warning disable SA1101
                        var consent = ProcessUserConsent(grant, userId);
#pragma warning restore SA1101
#pragma warning disable SA1101
                        if (!HighRiskOnly || consent.IsHighRisk)
                        {
                            userConsents.Add(consent);

                            if (consent.IsHighRisk)
                                summary.HighRiskPermissions++;
                        }
#pragma warning restore SA1101
                    }

                    summary.ProcessedUsers++;
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Failed to process user consents for {userId}: {ex.Message}");
#pragma warning restore SA1101
                }
            }
#pragma warning restore SA1101

            if (userConsents.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-UserConsents.csv");
#pragma warning disable SA1101
                await WriteUserConsentsAsync(userConsents, fileName);
#pragma warning restore SA1101
                summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                WriteVerbose($"User consents written to: {fileName}");
#pragma warning restore SA1101
            }
        }

        private async Task ProcessAllUserConsentsAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Processing OAuth consents for all users...");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var allGrants = await _graphClient.GetOAuth2PermissionGrantsAsync();
#pragma warning restore SA1101
            var userConsents = new List<UserConsentPermission>();

            var processedUsers = new HashSet<string>();

            foreach (var grant in allGrants)
            {
                try
                {
                    if (!string.IsNullOrEmpty(grant.PrincipalId))
                    {
                        processedUsers.Add(grant.PrincipalId);

#pragma warning disable SA1101
                        var consent = ProcessUserConsent(grant, grant.PrincipalId);
#pragma warning restore SA1101
#pragma warning disable SA1101
                        if (!HighRiskOnly || consent.IsHighRisk)
                        {
                            userConsents.Add(consent);

                            if (consent.IsHighRisk)
                                summary.HighRiskPermissions++;
                        }
#pragma warning restore SA1101
                    }
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Failed to process user consent: {ex.Message}");
#pragma warning restore SA1101
                }
            }

            summary.ProcessedUsers = processedUsers.Count;

            if (userConsents.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-AllUserConsents.csv");
#pragma warning disable SA1101
                await WriteUserConsentsAsync(userConsents, fileName);
#pragma warning restore SA1101
                summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                WriteVerbose($"User consents written to: {fileName}");
#pragma warning restore SA1101
            }
        }

        private async Task ProcessLegacyMethodAsync(string outputDirectory, string timestamp, OAuthPermissionsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Using legacy Exchange method for OAuth permissions collection");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteWarningWithTimestamp("Legacy method implementation not available in C# version. Please use Graph API method.");
#pragma warning restore SA1101

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
#pragma warning disable SA1101
                    var info = new RequiredResourceAccessInfo
                    {
                        ResourceAppId = resource.ResourceAppId?.ToString(),
                        ResourceAccess = ProcessResourceAccess(resource.ResourceAccess)
                    };
#pragma warning restore SA1101

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
#pragma warning disable SA1101
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
#pragma warning restore SA1101
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

        private void LogSummary(OAuthPermissionsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("=== OAuth Permissions Collection Summary ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Applications Processed: {summary.ProcessedApplications:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Users Processed: {summary.ProcessedUsers:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Total Permissions: {summary.TotalPermissions:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"High-Risk Permissions: {summary.HighRiskPermissions:N0}");
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
            WriteVerbose("============================================");
#pragma warning restore SA1101
        }

        private async Task WriteApplicationPermissionsAsync(IEnumerable<ApplicationPermission> permissions, string filePath)
        {
            var csv = "ApplicationId,DisplayName,CreatedDateTime,PublisherDomain,SignInAudience,RequiredResourceAccess,IsHighRisk" + Environment.NewLine;

            foreach (var perm in permissions)
            {
                var resourceAccessJson = JsonSerializer.Serialize(perm.RequiredResourceAccess);
#pragma warning disable SA1101
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
#pragma warning restore SA1101

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

#pragma warning disable SA1101
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
#pragma warning restore SA1101

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteUserConsentsAsync(IEnumerable<UserConsentPermission> consents, string filePath)
        {
            var csv = "UserId,ClientId,ConsentType,ResourceId,Scope,CreatedDateTime,IsHighRisk" + Environment.NewLine;

            foreach (var consent in consents)
            {
#pragma warning disable SA1101
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
    // Result and supporting classes
#pragma warning disable SA1600
    public class OAuthPermissionsResult
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
        public List<ApplicationPermission> Applications { get; set; } = new List<ApplicationPermission>();
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        public List<UserConsentPermission> UserConsents { get; set; }
List<UserConsentPermission>();
        public List<ServicePrincipalPermission> ServicePrincipals { get; set; } = new List<ServicePrincipalPermission>();
#pragma warning disable SA1600
        public OAuthPermissionsSummary Summary { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class ApplicationPermission
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ApplicationId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string DisplayName { get; set; }
        public DateTime? CreatedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string PublisherDomain { get; set; }
#pragma warning restore SA1600
        public string SignInAudience { get; set; }
        public List<RequiredResourceAccessInfo> RequiredResourceAccess { get; set; } = new List<RequiredResourceAccessInfo>();
#pragma warning disable SA1600
        public bool IsHighRisk { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class ServicePrincipalPermission
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ServicePrincipalId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string AppId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string DisplayName { get; set; }
        public DateTime? CreatedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning disable SA1201
        public List<OAuth2GrantInfo> OAuth2G
#pragma warning restore SA1201
        public List<AppRoleAssignmentInfo> AppRoleAssignments { get; set; } = new List<AppRoleAssignmentInfo>();
#pragma warning disable SA1600
        public bool IsHighRisk { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class UserConsentPermission
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ClientId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ConsentType { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ResourceId { get; set; }
#pragma warning restore SA1600
        public string Scope { get; set; }
        public DateTime? CreatedDateTime { get; set; }
#pragma warning disable SA1600
        public bool IsHighRisk { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class RequiredResourceAccessInfo
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
        public string ResourceAppId { get; set; }public List<ResourceAccessInfo> ResourceAccess { get; set; } = new List<ResourceAccessInfo>();
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class ResourceAccessInfo
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Id { get; set; }public string Type { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class OAuth2GrantInfo
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Id { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ClientId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ConsentType { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string PrincipalId { get; set; }
#pragma warning restore SA1600
        public string ResourceId { get; set; }
        public string Scope { get; set; }public DateTime? CreatedDateTime { get; set; }
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class AppRoleAssignmentInfo
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Id { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string AppRoleId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string PrincipalDisplayName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string PrincipalId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string PrincipalType { get; set; }
#pragma warning restore SA1600
        public string ResourceDisplayName { get; set; }
        public string ResourceId { get; set; }public DateTime? CreatedDateTime { get; set; }
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class OAuthPermissionsSummary
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
        public int ProcessedApplications { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int ProcessedUsers { get; set; }
#pragma warning restore SA1600
        public int TotalPermissions { get; set; }
        public int HighRiskPermissions { get; set; }public List<string> OutputFiles { get; set; } = new List<string>();
    }
}
