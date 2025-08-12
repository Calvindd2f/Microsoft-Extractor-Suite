using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Json;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using CsvHelper;

namespace Microsoft.ExtractorSuite.Cmdlets.Collection
{
    [Cmdlet(VerbsCommon.Get, "EntraApplicationsForSpecificUsers")]
    [OutputType(typeof(UserApplicationInfo))]
    public class GetEntraApplicationsForSpecificUsersCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "The output directory.")]
        public new string OutputDirectory { get; set; } = "Output\\Applications";

        [Parameter(HelpMessage = "The encoding of the output file.")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(HelpMessage = "The level of logging.")]
        [ValidateSet("None", "Minimal", "Standard", "Debug")]
        public new string LogLevel { get; set; } = "Standard";

        [Parameter(Mandatory = true, HelpMessage = "UserIds to filter applications by owner or assignments.")]
        public string[] UserIds { get; set; } = Array.Empty<string>();

        protected override void ProcessRecord()
        {
            if (!RequireGraphConnection())
            {
                return;
            }

            var applications = RunAsyncOperation(GetApplicationsForUsersAsync, "Get Entra Applications for Specific Users");

            if (!Async.IsPresent && applications != null)
            {
                foreach (var app in applications)
                {
                    WriteObject(app);
                }
            }
        }

        private async Task<List<UserApplicationInfo>> GetApplicationsForUsersAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            var graphClient = AuthManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");

            WriteVerboseWithTimestamp("=== Starting Entra Applications Collection ===");

            try
            {
                if (!Directory.Exists(OutputDirectory))
                {
                    Directory.CreateDirectory(OutputDirectory);
                    WriteVerboseWithTimestamp($"Created output directory: {OutputDirectory}");
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Failed to create directory: {OutputDirectory}", ex);
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
            WriteVerboseWithTimestamp($"Resolving {UserIds.Length} users...");

            foreach (var userId in UserIds)
            {
                try
                {
                    var user = await graphClient.Users[userId]
                        .GetAsync(cancellationToken);

                    validUsers.Add(user);
                    WriteVerboseWithTimestamp($"Resolved user: {user.UserPrincipalName}");
                }
                catch (ServiceException ex)
                {
                    WriteWarningWithTimestamp($"Could not resolve user: {userId} - {ex.Message}");
                }
            }

            if (validUsers.Count == 0)
            {
                WriteErrorWithTimestamp("No valid users found. Cannot proceed.");
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
                        .GetAsync(cancellationToken);

                    var pageIterator = PageIterator<DirectoryObject, DirectoryObjectCollectionResponse>
                        .CreatePageIterator(
                            graphClient,
                            ownedObjects,
                            async (obj) =>
                            {
                                if (obj.ODataType == "#microsoft.graph.application")
                                {
                                    await ProcessOwnedApplication(
                                        graphClient,
                                        obj.Id,
                                        user.UserPrincipalName,
                                        processedAppIds,
                                        results,
                                        summary,
                                        cancellationToken);
                                }
                                return !cancellationToken.IsCancellationRequested;
                            });

                    await pageIterator.IterateAsync(cancellationToken);
                }
                catch (ServiceException ex)
                {
                    WriteWarningWithTimestamp($"Error getting owned apps for {user.UserPrincipalName}: {ex.Message}");
                }

                // Get application assignments
                try
                {
                    var assignments = await graphClient.Users[user.Id].AppRoleAssignments
                        .GetAsync(cancellationToken);

                    var assignmentIterator = PageIterator<AppRoleAssignment, AppRoleAssignmentCollectionResponse>
                        .CreatePageIterator(
                            graphClient,
                            assignments,
                            async (assignment) =>
                            {
                                await ProcessAssignedApplication(
                                    graphClient,
                                    assignment.ResourceId,
                                    user.UserPrincipalName,
                                    processedAppIds,
                                    results,
                                    summary,
                                    cancellationToken);
                                return !cancellationToken.IsCancellationRequested;
                            });

                    await assignmentIterator.IterateAsync(cancellationToken);
                }
                catch (ServiceException ex)
                {
                    WriteWarningWithTimestamp($"Error getting assignments for {user.UserPrincipalName}: {ex.Message}");
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
            await ExportResultsAsync(results, cancellationToken);

            // Write summary
            WriteSummary(summary, validUsers.Count);

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
                    .Request()
                    .GetAsync(cancellationToken);

                processedAppIds.Add(appId);
                summary.OwnedApps++;

                // Get service principal if it exists
                ServicePrincipal? servicePrincipal = null;
                try
                {
                    var servicePrincipals = await graphClient.ServicePrincipals
                        .Request()
                        .Filter($"appId eq '{app.AppId}'")
                        .GetAsync(cancellationToken);

                    servicePrincipal = servicePrincipals.FirstOrDefault();
                }
                catch { }

                var appInfo = new UserApplicationInfo
                {
                    AssociationType = "Owner",
                    AssociatedUser = userPrincipalName,
                    ApplicationName = app.DisplayName,
                    ApplicationId = app.AppId,
                    ObjectId = app.Id,
                    PublisherName = servicePrincipal?.PublisherName ?? string.Empty,
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

                results.Add(appInfo);
            }
            catch (Exception ex)
            {
                WriteWarningWithTimestamp($"Could not process owned app {appId}: {ex.Message}");
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
                    .Request()
                    .GetAsync(cancellationToken);

                processedAppIds.Add(appKey);
                summary.AssignedApps++;

                // Try to get the corresponding application registration
                Application? app = null;
                if (!string.IsNullOrEmpty(servicePrincipal.AppId))
                {
                    try
                    {
                        var apps = await graphClient.Applications
                            .Request()
                            .Filter($"appId eq '{servicePrincipal.AppId}'")
                            .GetAsync(cancellationToken);

                        app = apps.FirstOrDefault();
                    }
                    catch { }
                }

                var appInfo = new UserApplicationInfo
                {
                    AssociationType = "Assignment",
                    AssociatedUser = userPrincipalName,
                    ApplicationName = servicePrincipal.DisplayName,
                    ApplicationId = servicePrincipal.AppId,
                    ObjectId = app?.Id ?? servicePrincipal.Id,
                    PublisherName = servicePrincipal.PublisherName,
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

                results.Add(appInfo);
            }
            catch (Exception ex)
            {
                WriteWarningWithTimestamp($"Could not process assignment: {ex.Message}");
            }
        }

        private string DetermineApplicationType(ServicePrincipal? servicePrincipal)
        {
            if (servicePrincipal == null)
                return "Internal Application";

            var types = new List<string>();

            // Check if it's a Microsoft application
            if (servicePrincipal.AppOwnerOrganizationId == "f8cdef31-a31e-4b4a-93e4-5f571e91255a" ||
                servicePrincipal.AppOwnerOrganizationId == "72f988bf-86f1-41af-91ab-2d7cd011db47")
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
            var outputPath = Path.Combine(OutputDirectory, $"{date}-UserApplications.csv");

            WriteVerboseWithTimestamp($"Exporting {results.Count} applications to CSV...");

            using var writer = new StreamWriter(outputPath, false, System.Text.Encoding.GetEncoding(Encoding));
            using var csv = new CsvWriter(writer, System.Globalization.CultureInfo.InvariantCulture);

            await csv.WriteRecordsAsync(results);

            WriteVerboseWithTimestamp($"Results exported to: {outputPath}");
        }

        private void WriteSummary(ApplicationsSummary summary, int userCount)
        {
            WriteHost("");
            WriteHost("=== User Applications Summary ===", ConsoleColor.Cyan);
            WriteHost($"Users Processed: {userCount}");
            WriteHost($"Owned Applications: {summary.OwnedApps}");
            WriteHost($"Assigned Applications: {summary.AssignedApps}");
            WriteHost($"Total Applications: {summary.TotalApps}");
            WriteHost($"Processing Time: {summary.ProcessingTime:mm\\:ss}", ConsoleColor.Green);
            WriteHost("===================================", ConsoleColor.Cyan);
        }

        private void WriteHost(string message, ConsoleColor? color = null)
        {
            if (color.HasValue)
            {
                Host.UI.WriteLine(color.Value, Host.UI.RawUI.BackgroundColor, message);
            }
            else
            {
                Host.UI.WriteLine(message);
            }
        }
    }

    public class UserApplicationInfo
    {
        public string AssociationType { get; set; } = string.Empty;
        public string AssociatedUser { get; set; } = string.Empty;
        public string? ApplicationName { get; set; }
        public string? ApplicationId { get; set; }
        public string? ObjectId { get; set; }
        public string? PublisherName { get; set; }
        public string ApplicationType { get; set; } = string.Empty;
        public DateTime? CreatedDateTime { get; set; }
        public string ServicePrincipalEnabled { get; set; } = string.Empty;
        public bool HasClientSecrets { get; set; }
        public bool HasCertificates { get; set; }
        public int RequiredApiPermissionCount { get; set; }
        public string? SignInAudience { get; set; }
        public string? Homepage { get; set; }
        public string? WebRedirectUris { get; set; }
        public string? PublicClientRedirectUris { get; set; }
    }

    internal class ApplicationsSummary
    {
        public int OwnedApps { get; set; }
        public int AssignedApps { get; set; }
        public int TotalApps { get; set; }
        public DateTime StartTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }
    }
}
