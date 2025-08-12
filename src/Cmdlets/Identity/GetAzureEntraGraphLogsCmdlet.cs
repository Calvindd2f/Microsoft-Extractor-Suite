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

namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    /// <summary>
    /// Gets Entra ID sign-in and audit logs via Microsoft Graph API.
    /// Supports multiple event types including interactive user, non-interactive user, service principal, and managed identity sign-ins.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AzureEntraGraphLogs")]
    [OutputType(typeof(EntraLogEntry))]
    public class GetAzureEntraGraphLogsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "Start date for log collection. Default: 30 days ago")]
        public DateTime? StartDate { get; set; }

        [Parameter(HelpMessage = "End date for log collection. Default: Now")]
        public DateTime? EndDate { get; set; }

        [Parameter(HelpMessage = "Type of logs to collect: SignIn, Audit, or Both. Default: Both")]
        [ValidateSet("SignIn", "Audit", "Both")]
        public string LogType { get; set; } = "Both";

        [Parameter(HelpMessage = "Event types to collect for sign-in logs")]
        [ValidateSet("All", "InteractiveUser", "NonInteractiveUser", "ServicePrincipal", "ManagedIdentity")]
        public string[] EventTypes { get; set; } = new[] { "All" };

        [Parameter(HelpMessage = "Comma-separated list of user IDs to filter results")]
        public string[]? UserIds { get; set; }

        [Parameter(HelpMessage = "Include target resources in audit log filtering when UserIds is specified")]
        public SwitchParameter IncludeTargetResources { get; set; }

        [Parameter(HelpMessage = "Output format for the results. Default: JSON")]
        [ValidateSet("JSON", "SOF-ELK")]
        public string OutputFormat { get; set; } = "JSON";

        [Parameter(HelpMessage = "Merge output into single files per log type")]
        public SwitchParameter MergeOutput { get; set; }

        [Parameter(HelpMessage = "Text encoding for the output file. Default: UTF8")]
        public string Encoding { get; set; } = "UTF8";

        protected override void ProcessRecord()
        {
            var results = RunAsyncOperation(GetEntraGraphLogsAsync, "Getting Entra Graph Logs");

            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
        }

        private async Task<List<EntraLogEntry>> GetEntraGraphLogsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Entra ID Graph Log Collection");

            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Not connected to Microsoft Graph. Please run Connect-M365 first.");
            }

            var graphClient = AuthManager.GraphClient!;

            // Set default dates
            var startDate = StartDate ?? DateTime.UtcNow.AddDays(-30);
            var endDate = EndDate ?? DateTime.UtcNow;

            WriteVerboseWithTimestamp($"Start Date: {startDate:yyyy-MM-dd HH:mm:ss}");
            WriteVerboseWithTimestamp($"End Date: {endDate:yyyy-MM-dd HH:mm:ss}");
            WriteVerboseWithTimestamp($"Log Type: {LogType}");
            if (UserIds?.Length > 0)
            {
                WriteVerboseWithTimestamp($"Filtering for Users: {string.Join(", ", UserIds)}");
            }

            var allResults = new List<EntraLogEntry>();
            var summary = new EntraLogSummary
            {
                StartTime = DateTime.UtcNow
            };

            // Collect Sign-In Logs
            if (LogType == "SignIn" || LogType == "Both")
            {
                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Collecting Sign-In Logs",
                    PercentComplete = 10
                });

                var signInResults = await CollectSignInLogsAsync(graphClient, startDate, endDate, progress, cancellationToken);
                allResults.AddRange(signInResults);
                summary.SignInRecords = signInResults.Count;

                WriteVerboseWithTimestamp($"Collected {signInResults.Count} sign-in log entries");
            }

            // Collect Audit Logs
            if (LogType == "Audit" || LogType == "Both")
            {
                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Collecting Audit Logs",
                    PercentComplete = 60
                });

                var auditResults = await CollectAuditLogsAsync(graphClient, startDate, endDate, progress, cancellationToken);
                allResults.AddRange(auditResults);
                summary.AuditRecords = auditResults.Count;

                WriteVerboseWithTimestamp($"Collected {auditResults.Count} audit log entries");
            }

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Exporting results",
                PercentComplete = 90
            });

            // Export results if output directory is specified
            if (!string.IsNullOrEmpty(OutputDirectory))
            {
                await ExportLogsAsync(allResults, summary, cancellationToken);
            }

            summary.TotalRecords = allResults.Count;
            summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

            // Log summary
            WriteVerboseWithTimestamp($"Entra Graph Log Collection Summary:");
            WriteVerboseWithTimestamp($"  Sign-In Records: {summary.SignInRecords}");
            WriteVerboseWithTimestamp($"  Audit Records: {summary.AuditRecords}");
            WriteVerboseWithTimestamp($"  Total Records: {summary.TotalRecords}");
            WriteVerboseWithTimestamp($"  Processing Time: {summary.ProcessingTime:mm\\:ss}");

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Collection completed",
                PercentComplete = 100
            });

            return allResults;
        }

        private async Task<List<EntraLogEntry>> CollectSignInLogsAsync(
            GraphServiceClient graphClient,
            DateTime startDate,
            DateTime endDate,
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            var results = new List<EntraLogEntry>();
            var eventTypesToProcess = DetermineEventTypes();

            var currentEventType = 1;
            foreach (var eventType in eventTypesToProcess)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                WriteVerboseWithTimestamp($"Acquiring {eventType} sign-in logs");

                var filter = BuildSignInFilter(startDate, endDate, eventType);
                WriteVerboseWithTimestamp($"Using filter: {filter}");

                try
                {
                    var signIns = await graphClient.AuditLogs.SignIns
                        .GetAsync(requestConfiguration =>
                        {
                            requestConfiguration.QueryParameters.Filter = filter;
                            requestConfiguration.QueryParameters.Top = 1000;
                        }, cancellationToken);

                    var pageIterator = PageIterator<Microsoft.Graph.Models.SignIn, SignInCollectionResponse>
                        .CreatePageIterator(
                            graphClient,
                            signIns,
                            (signIn) =>
                            {
                                results.Add(MapSignInToLogEntry(signIn, eventType));
                                return !cancellationToken.IsCancellationRequested;
                            });

                    await pageIterator.IterateAsync(cancellationToken);

                    var eventProgress = 10 + (int)((currentEventType / (double)eventTypesToProcess.Count) * 40);
                    progress.Report(new Core.AsyncOperations.TaskProgress
                    {
                        CurrentOperation = $"Completed {eventType} sign-in logs",
                        PercentComplete = eventProgress
                    });
                }
                catch (Exception ex)
                {
                    WriteErrorWithTimestamp($"Error collecting {eventType} sign-in logs: {ex.Message}", ex);
                }

                currentEventType++;
            }

            return results;
        }

        private async Task<List<EntraLogEntry>> CollectAuditLogsAsync(
            GraphServiceClient graphClient,
            DateTime startDate,
            DateTime endDate,
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            var results = new List<EntraLogEntry>();

            WriteVerboseWithTimestamp("Acquiring directory audit logs");

            var filter = BuildAuditFilter(startDate, endDate);
            WriteVerboseWithTimestamp($"Using filter: {filter}");

            try
            {
                var auditLogs = await graphClient.AuditLogs.DirectoryAudits
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Filter = filter;
                        requestConfiguration.QueryParameters.Top = 1000;
                    }, cancellationToken);

                var pageIterator = PageIterator<DirectoryAudit, DirectoryAuditCollectionResponse>
                    .CreatePageIterator(
                        graphClient,
                        auditLogs,
                        (audit) =>
                        {
                            results.Add(MapAuditToLogEntry(audit));
                            return !cancellationToken.IsCancellationRequested;
                        });

                await pageIterator.IterateAsync(cancellationToken);

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Completed audit logs collection",
                    PercentComplete = 85
                });
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Error collecting audit logs: {ex.Message}", ex);
            }

            return results;
        }

        private List<string> DetermineEventTypes()
        {
            if (EventTypes.Contains("All"))
            {
                if (UserIds?.Length > 0)
                {
                    // When filtering by users, skip service principal and managed identity as they won't have results
                    return new List<string> { "InteractiveUser", "NonInteractiveUser" };
                }
                else
                {
                    return new List<string> { "InteractiveUser", "NonInteractiveUser", "ServicePrincipal", "ManagedIdentity" };
                }
            }

            return EventTypes.ToList();
        }

        private string BuildSignInFilter(DateTime startDate, DateTime endDate, string eventType)
        {
            var startDateStr = startDate.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var endDateStr = endDate.ToString("yyyy-MM-ddTHH:mm:ssZ");

            var filter = $"createdDateTime ge {startDateStr} and createdDateTime le {endDateStr}";

            // Add event type filter
            switch (eventType.ToLowerInvariant())
            {
                case "interactiveuser":
                    filter += " and (signInEventTypes/any(t: t eq 'interactiveUser'))";
                    break;
                case "noninteractiveuser":
                    filter += " and (signInEventTypes/any(t: t eq 'nonInteractiveUser'))";
                    break;
                case "serviceprincipal":
                    filter += " and (signInEventTypes/any(t: t eq 'servicePrincipal'))";
                    break;
                case "managedidentity":
                    filter += " and (signInEventTypes/any(t: t eq 'managedIdentity'))";
                    break;
            }

            // Add user filter if specified
            if (UserIds?.Length > 0 && (eventType.ToLowerInvariant().Contains("user")))
            {
                var userFilters = UserIds.Select(u => $"startsWith(userPrincipalName, '{u}')");
                filter += $" and ({string.Join(" or ", userFilters)})";
            }

            return filter;
        }

        private string BuildAuditFilter(DateTime startDate, DateTime endDate)
        {
            var startDateStr = startDate.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var endDateStr = endDate.ToString("yyyy-MM-ddTHH:mm:ssZ");

            var filter = $"activityDateTime ge {startDateStr} and activityDateTime le {endDateStr}";

            if (UserIds?.Length > 0)
            {
                var userFilters = UserIds.Select(u => $"startsWith(initiatedBy/user/userPrincipalName, '{u}')");
                filter += $" and ({string.Join(" or ", userFilters)})";

                if (IncludeTargetResources.IsPresent)
                {
                    var targetFilters = UserIds.Select(u => $"targetResources/any(tr: tr/userPrincipalName eq '{u}')");
                    filter = $"({filter}) or ({string.Join(" or ", targetFilters)})";
                }
            }

            return filter;
        }

        private EntraLogEntry MapSignInToLogEntry(Microsoft.Graph.Models.SignIn signIn, string eventType)
        {
            return new EntraLogEntry
            {
                Id = signIn.Id ?? Guid.NewGuid().ToString(),
                LogType = "SignIn",
                EventType = eventType,
                Timestamp = signIn.CreatedDateTime?.DateTime ?? DateTime.UtcNow,
                UserPrincipalName = signIn.UserPrincipalName ?? "",
                AppDisplayName = signIn.AppDisplayName ?? "",
                ClientAppUsed = signIn.ClientAppUsed ?? "",
                IpAddress = signIn.IpAddress ?? "",
                Location = signIn.Location?.City ?? "",
                DeviceDetail = $"{signIn.DeviceDetail?.OperatingSystem} {signIn.DeviceDetail?.Browser}".Trim(),
                Status = signIn.Status?.ErrorCode?.ToString() ?? "Success",
                RiskLevelDuringSignIn = signIn.RiskLevelDuringSignIn?.ToString() ?? "None",
                RiskState = signIn.RiskState?.ToString() ?? "None",
                ConditionalAccessStatus = signIn.ConditionalAccessStatus?.ToString() ?? "NotApplied",
                CorrelationId = signIn.CorrelationId?.ToString() ?? "",
                Details = System.Text.Json.JsonSerializer.Serialize(signIn)
            };
        }

        private EntraLogEntry MapAuditToLogEntry(DirectoryAudit audit)
        {
            return new EntraLogEntry
            {
                Id = audit.Id ?? Guid.NewGuid().ToString(),
                LogType = "Audit",
                EventType = "DirectoryAudit",
                Timestamp = audit.ActivityDateTime?.DateTime ?? DateTime.UtcNow,
                UserPrincipalName = audit.InitiatedBy?.User?.UserPrincipalName ?? "",
                AppDisplayName = audit.InitiatedBy?.App?.DisplayName ?? "",
                ActivityDisplayName = audit.ActivityDisplayName ?? "",
                Category = audit.Category ?? "",
                Result = audit.Result?.ToString() ?? "Success",
                ResultReason = audit.ResultReason ?? "",
                CorrelationId = audit.CorrelationId?.ToString() ?? "",
                Details = System.Text.Json.JsonSerializer.Serialize(audit)
            };
        }

        private async Task ExportLogsAsync(
            List<EntraLogEntry> results,
            EntraLogSummary summary,
            CancellationToken cancellationToken)
        {
            Directory.CreateDirectory(OutputDirectory!);

            if (MergeOutput.IsPresent)
            {
                // Export all logs to single file
                await ExportLogFile(results, "Combined", cancellationToken);
            }
            else
            {
                // Export by log type
                var signInLogs = results.Where(r => r.LogType == "SignIn").ToList();
                var auditLogs = results.Where(r => r.LogType == "Audit").ToList();

                if (signInLogs.Any())
                {
                    await ExportLogFile(signInLogs, "SignIn", cancellationToken);
                }

                if (auditLogs.Any())
                {
                    await ExportLogFile(auditLogs, "Audit", cancellationToken);
                }
            }

            // Export summary
            var summaryPath = Path.Combine(OutputDirectory!, $"{DateTime.UtcNow:yyyyMMddHHmmss}-EntraLogSummary.json");
            var summaryJson = System.Text.Json.JsonSerializer.Serialize(summary, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });
            using (var writer = new StreamWriter(summaryPath)) { await writer.WriteAsync(summaryJson); }
        }

        private async Task ExportLogFile(
            List<EntraLogEntry> logs,
            string logType,
            CancellationToken cancellationToken)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            var fileName = Path.Combine(OutputDirectory!, $"{timestamp}-{logType}Logs.json");

            using var stream = File.Create(fileName);
            using var processor = new HighPerformanceJsonProcessor();
            await processor.SerializeAsync(stream, logs, true, cancellationToken);

            WriteVerboseWithTimestamp($"Exported {logs.Count} {logType} log entries to {fileName}");
        }
    }

    public class EntraLogEntry
    {
        public string Id { get; set; } = string.Empty;
        public string LogType { get; set; } = string.Empty; // SignIn or Audit
        public string EventType { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string UserPrincipalName { get; set; } = string.Empty;
        public string AppDisplayName { get; set; } = string.Empty;
        public string ClientAppUsed { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string Location { get; set; } = string.Empty;
        public string DeviceDetail { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string RiskLevelDuringSignIn { get; set; } = string.Empty;
        public string RiskState { get; set; } = string.Empty;
        public string ConditionalAccessStatus { get; set; } = string.Empty;
        public string ActivityDisplayName { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Result { get; set; } = string.Empty;
        public string ResultReason { get; set; } = string.Empty;
        public string CorrelationId { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
    }

    public class EntraLogSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public int TotalRecords { get; set; }
        public int SignInRecords { get; set; }
        public int AuditRecords { get; set; }
        public List<string> EventTypesProcessed { get; set; } = new();
    }
}