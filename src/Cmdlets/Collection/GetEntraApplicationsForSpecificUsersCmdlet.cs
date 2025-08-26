namespace Microsoft.ExtractorSuite.Cmdlets.Collection
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;
    using CsvHelper;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Json;
    using Microsoft.Graph;
    using Microsoft.Graph.Models;


    [Cmdlet(VerbsCommon.Get, "EntraApplicationsForSpecificUsers")]
    [OutputType(typeof(UserApplicationInfo))]
#pragma warning disable SA1600
    public class GetEntraApplicationsForSpecificUsersCmdlet : AsyncBaseCmdlet
#pragma warning restore SA1600
    {
        [Parameter(HelpMessage = "The output directory.")]
#pragma warning disable SA1600
        public new string OutputDirectory { get; set; } = "Output\\Applications";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "The encoding of the output file.")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "The level of logging.")]
        [ValidateSet("None", "Minimal", "Standard", "Debug")]
#pragma warning disable SA1600
        public new string LogLevel { get; set; } = "Standard";
#pragma warning restore SA1600

        [Parameter(Mandatory = true, HelpMessage = "UserIds to filter applications by owner or assignments.")]
#pragma warning disable SA1600
        public string[] UserIds { get; set; } = Array.Empty<string>();
#pragma warning restore SA1600

#pragma warning disable SA1600
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                return;
            }
#pragma warning restore SA1101

            var applications = RunAsyncOperation(GetApplicationsForUsersAsync, "Get Entra Applications for Specific Users");

#pragma warning disable SA1101
            if (!Async.IsPresent && applications != null)
            {
                foreach (var app in applications)
                {
                    WriteObject(app);
                }
            }
#pragma warning restore SA1101
        }

        private async Task<List<UserApplicationInfo>> GetApplicationsForUsersAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var graphClient = AuthManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");
#pragma warning restore SA1101

            WriteVerboseWithTimestamp("=== Starting Entra Applications Collection ===");

            try
            {
#pragma warning disable SA1101
                if (!Directory.Exists(OutputDirectory))
                {
#pragma warning disable SA1101
                    Directory.CreateDirectory(OutputDirectory);
#pragma warning restore SA1101
#pragma warning disable SA1101
                    WriteVerboseWithTimestamp($"Created output directory: {OutputDirectory}");
#pragma warning restore SA1101
                }
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to create directory: {OutputDirectory}", ex);
#pragma warning restore SA1101
                throw;
            }

            var results = new List<UserApplicationInfo>();
            var processedAppIds = new HashSet<string>();
            var summary = new ApplicationsSummary
            {
                StartTime = DateTime.UtcNow
            };

            // Resolve users
            var validUsers = new List<User>();
#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Resolving {UserIds.Length} users...");
#pragma warning restore SA1101

#pragma warning disable SA1101
            foreach (var userId in UserIds)
            {
                try
                {
                    var user = await graphClient.Users[userId]
                        .GetAsync(requestConfiguration => {}, cancellationToken);

                    validUsers.Add(user);
                    WriteVerboseWithTimestamp($"Resolved user: {user.UserPrincipalName}");
                }
                catch (ServiceException ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Could not resolve user: {userId} - {ex.Message}");
#pragma warning restore SA1101
                }
            }
#pragma warning restore SA1101

            if (validUsers.Count == 0)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp("No valid users found. Cannot proceed.");
#pragma warning restore SA1101
                return results;
            }

            var processedCount = 0;
            foreach (var user in validUsers)
            {
                WriteVerboseWithTimestamp($"Processing user: {user.UserPrincipalName}");

                // Get owned applications
                try
                {
                    var ownedObjects = await graphClient.Users[user.Id].OwnedObjects
                        .GetAsync(requestConfiguration => {}, cancellationToken);

                    var pageIterator = PageIterator<DirectoryObject, DirectoryObjectCollectionResponse>
                        .CreatePageIterator(
                            graphClient,
                            ownedObjects,
                            async (obj) =>
                            {
                                if (obj.GetType().Name == "Application")
                                {
#pragma warning disable SA1101
                                    await ProcessOwnedApplication(
                                        graphClient,
                                        obj.Id,
                                        user.UserPrincipalName,
                                        processedAppIds,
                                        results,
                                        summary,
                                        cancellationToken);
#pragma warning restore SA1101
                                }
                                return !cancellationToken.IsCancellationRequested;
                            });

                    await pageIterator.IterateAsync(cancellationToken);
                }
                catch (ServiceException ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Error getting owned apps for {user.UserPrincipalName}: {ex.Message}");
#pragma warning restore SA1101
                }

                // Get application assignments
                try
                {
                    var assignments = await graphClient.Users[user.Id].AppRoleAssignments
                        .GetAsync(requestConfiguration => {}, cancellationToken);

                    var assignmentIterator = PageIterator<AppRoleAssignment, AppRoleAssignmentCollectionResponse>
                        .CreatePageIterator(
                            graphClient,
                            assignments,
                            async (assignment) =>
                            {
#pragma warning disable SA1101
                                await ProcessAssignedApplication(
                                    graphClient,
                                    assignment.ResourceId?.ToString(),
                                    user.UserPrincipalName,
                                    processedAppIds,
                                    results,
                                    summary,
                                    cancellationToken);
#pragma warning restore SA1101
                                return !cancellationToken.IsCancellationRequested;
                            });

                    await assignmentIterator.IterateAsync(cancellationToken);
                }
                catch (ServiceException ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Error getting assignments for {user.UserPrincipalName}: {ex.Message}");
#pragma warning restore SA1101
                }

                processedCount++;
                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = $"Processing users",
                    ItemsProcessed = processedCount,
                    TotalItems = validUsers.Count,
                    PercentComplete = (processedCount * 100) / validUsers.Count
                });
            }

            summary.TotalApps = results.Count;
            summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

            // Export results
#pragma warning disable SA1101
            await ExportResultsAsync(results, cancellationToken);
#pragma warning restore SA1101

            // Write summary
#pragma warning disable SA1101
            WriteSummary(summary, validUsers.Count);
#pragma warning restore SA1101

            return results;
        }

        private async Task ProcessOwnedApplication(
            GraphServiceClient graphClient,
            string appId,
            string userPrincipalName,
            HashSet<string> processedAppIds,
            List<UserApplicationInfo> results,
            ApplicationsSummary summary,
            CancellationToken cancellationToken)
        {
            if (processedAppIds.Contains(appId))
                return;

            try
            {
                var app = await graphClient.Applications[appId]
                    .GetAsync(cancellationToken: cancellationToken);

                processedAppIds.Add(appId);
                summary.OwnedApps++;

                // Get service principal if it exists
                ServicePrincipal? servicePrincipal = null;
                try
                {
                    var servicePrincipals = await graphClient.ServicePrincipals
                        .GetAsync(requestConfiguration =>
                        {
                            requestConfiguration.QueryParameters.Filter = $"appId eq '{app.AppId}'";
                        }, cancellationToken);

                    servicePrincipal = servicePrincipals?.Value?.FirstOrDefault();
                }
                catch { }

#pragma warning disable SA1101
                var appInfo = new UserApplicationInfo
                {
                    AssociationType = "Owner",
                    AssociatedUser = userPrincipalName,
                    ApplicationName = app.DisplayName,
                    ApplicationId = app.AppId,
                    ObjectId = app.Id,
                    PublisherName = string.Empty, // ServicePrincipal doesn't have PublisherName property
                    ApplicationType = DetermineApplicationType(servicePrincipal),
                    CreatedDateTime = app.CreatedDateTime?.DateTime,
                    ServicePrincipalEnabled = servicePrincipal?.AccountEnabled?.ToString() ?? "N/A",
                    HasClientSecrets = app.PasswordCredentials?.Any() ?? false,
                    HasCertificates = app.KeyCredentials?.Any() ?? false,
                    RequiredApiPermissionCount = app.RequiredResourceAccess?.Sum(r => r.ResourceAccess?.Count ?? 0) ?? 0,
                    SignInAudience = app.SignInAudience,
                    Homepage = servicePrincipal?.Homepage ?? app.Web?.HomePageUrl,
                    WebRedirectUris = string.Join("; ", app.Web?.RedirectUris ?? new List<string>()),
                    PublicClientRedirectUris = string.Join("; ", app.PublicClient?.RedirectUris ?? new List<string>())
                };
#pragma warning restore SA1101

                results.Add(appInfo);
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteWarningWithTimestamp($"Could not process owned app {appId}: {ex.Message}");
#pragma warning restore SA1101
            }
        }

        private async Task ProcessAssignedApplication(
            GraphServiceClient graphClient,
            string? resourceId,
            string userPrincipalName,
            HashSet<string> processedAppIds,
            List<UserApplicationInfo> results,
            ApplicationsSummary summary,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(resourceId))
                return;

            var appKey = $"SP_{resourceId}";
            if (processedAppIds.Contains(appKey))
                return;

            try
            {
                var servicePrincipal = await graphClient.ServicePrincipals[resourceId]
                    .GetAsync(cancellationToken: cancellationToken);

                processedAppIds.Add(appKey);
                summary.AssignedApps++;

                // Try to get the corresponding application registration
                Application? app = null;
                if (!string.IsNullOrEmpty(servicePrincipal.AppId))
                {
                    try
                    {
                        var apps = await graphClient.Applications
                            .GetAsync(requestConfiguration =>
                            {
                                requestConfiguration.QueryParameters.Filter = $"appId eq '{servicePrincipal.AppId}'";
                            }, cancellationToken);

                        app = apps?.Value?.FirstOrDefault();
                    }
                    catch { }
                }

#pragma warning disable SA1101
                var appInfo = new UserApplicationInfo
                {
                    AssociationType = "Assignment",
                    AssociatedUser = userPrincipalName,
                    ApplicationName = servicePrincipal.DisplayName,
                    ApplicationId = servicePrincipal.AppId,
                    ObjectId = app?.Id ?? servicePrincipal.Id,
                    PublisherName = null, // PublisherName not available in SDK v5
                    ApplicationType = DetermineApplicationType(servicePrincipal),
                    CreatedDateTime = app?.CreatedDateTime?.DateTime,
                    ServicePrincipalEnabled = servicePrincipal.AccountEnabled?.ToString() ?? "false",
                    HasClientSecrets = app?.PasswordCredentials?.Any() ?? false,
                    HasCertificates = app?.KeyCredentials?.Any() ?? false,
                    RequiredApiPermissionCount = app?.RequiredResourceAccess?.Sum(r => r.ResourceAccess?.Count ?? 0) ?? 0,
                    SignInAudience = app?.SignInAudience,
                    Homepage = servicePrincipal.Homepage,
                    WebRedirectUris = app != null ? string.Join("; ", app.Web?.RedirectUris ?? new List<string>()) : string.Empty,
                    PublicClientRedirectUris = app != null ? string.Join("; ", app.PublicClient?.RedirectUris ?? new List<string>()) : string.Empty
                };
#pragma warning restore SA1101

                results.Add(appInfo);
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteWarningWithTimestamp($"Could not process assignment: {ex.Message}");
#pragma warning restore SA1101
            }
        }

        private string DetermineApplicationType(ServicePrincipal? servicePrincipal)
        {
            if (servicePrincipal == null)
                return "Internal Application";

            var types = new List<string>();

            // Check if it's a Microsoft application
            if (servicePrincipal.AppOwnerOrganizationId?.ToString() == "f8cdef31-a31e-4b4a-93e4-5f571e91255a" ||
                servicePrincipal.AppOwnerOrganizationId?.ToString() == "72f988bf-86f1-41af-91ab-2d7cd011db47")
            {
                types.Add("Microsoft Application");
            }

            // Check if it's a managed identity
            if (servicePrincipal.ServicePrincipalType == "ManagedIdentity")
            {
                types.Add("Managed Identity");
            }

            // Check if it's an enterprise application
            if (servicePrincipal.Tags?.Contains("WindowsAzureActiveDirectoryIntegratedApp") == true)
            {
                types.Add("Enterprise Application");
            }

            return types.Count == 0 ? "Internal Application" : string.Join(" & ", types);
        }

        private async Task ExportResultsAsync(
            List<UserApplicationInfo> results,
            CancellationToken cancellationToken)
        {
            var date = DateTime.Now.ToString("yyyyMMddHHmm");
#pragma warning disable SA1101
            var outputPath = Path.Combine(OutputDirectory, $"{date}-UserApplications.csv");
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Exporting {results.Count} applications to CSV...");

#pragma warning disable SA1101
            using var writer = new StreamWriter(outputPath, false, System.Text.Encoding.GetEncoding(Encoding));
#pragma warning restore SA1101
            using var csv = new CsvWriter(writer, System.Globalization.CultureInfo.InvariantCulture);

            await csv.WriteRecordsAsync(results);

            WriteVerboseWithTimestamp($"Results exported to: {outputPath}");
        }

        private void WriteSummary(ApplicationsSummary summary, int userCount)
        {
#pragma warning disable SA1101
            WriteHost("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost("=== User Applications Summary ===", ConsoleColor.Cyan);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Users Processed: {userCount}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Owned Applications: {summary.OwnedApps}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Assigned Applications: {summary.AssignedApps}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Total Applications: {summary.TotalApps}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Processing Time: {summary.ProcessingTime:mm\\:ss}", ConsoleColor.Green);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost("===================================", ConsoleColor.Cyan);
#pragma warning restore SA1101
        }

        private void WriteHost(string message, ConsoleColor? color = null)
        {
            if (color.HasValue)
            {
#pragma warning disable SA1101
                Host.UI.WriteLine(color.Value, Host.UI.RawUI.BackgroundColor, message);
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                Host.UI.WriteLine(message);
#pragma warning restore SA1101
            }
        }
    }

#pragma warning disable SA1600
    public class UserApplicationInfo
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string AssociationType { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string AssociatedUser { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? ApplicationName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? ApplicationId { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? ObjectId { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? PublisherName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ApplicationType { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? CreatedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ServicePrincipalEnabled { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool HasClientSecrets { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool HasCertificates { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int RequiredApiPermissionCount { get; set; }
        public string? SignInAudience { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Homepage { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? WebRedirectUris { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? PublicClientRedirectUris { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    internal class ApplicationsSummary
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int OwnedApps { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int AssignedApps { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalApps { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
#pragma warning restore SA1600
        public TimeSpan ProcessingTime { get; set; }
    }
}
