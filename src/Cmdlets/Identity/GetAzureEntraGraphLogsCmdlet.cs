namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
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


    /// <summary>
    /// Gets Entra ID sign-in and audit logs via Microsoft Graph API.
    /// Supports multiple event types including interactive user, non-interactive user, service principal, and managed identity sign-ins.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AzureEntraGraphLogs")]
    [OutputType(typeof(EntraLogEntry))]
    public class GetAzureEntraGraphLogsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "Start date for log collection. Default: 30 days ago")]
#pragma warning disable SA1600
        public DateTime? StartDate { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "End date for log collection. Default: Now")]
#pragma warning disable SA1600
        public DateTime? EndDate { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Type of logs to collect: SignIn, Audit, or Both. Default: Both")]
        [ValidateSet("SignIn", "Audit", "Both")]
#pragma warning disable SA1600
        public string LogType { get; set; } = "Both";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Event types to collect for sign-in logs")]
        [ValidateSet("All", "InteractiveUser", "NonInteractiveUser", "ServicePrincipal", "ManagedIdentity")]
#pragma warning disable SA1600
        public string[] EventTypes { get; set; } = new[] { "All" };
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Comma-separated list of user IDs to filter results")]
#pragma warning disable SA1600
        public string[]? UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Include target resources in audit log filtering when UserIds is specified")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeTargetResources { get; set; }

        [Parameter(HelpMessage = "Output format for the results. Default: JSON")]
        [ValidateSet("JSON", "SOF-ELK")]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "JSON";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Merge output into single files per log type")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter MergeOutput { get; set; }

        [Parameter(HelpMessage = "Text encoding for the output file. Default: UTF8")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

#pragma warning disable SA1600
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
            var results = RunAsyncOperation(GetEntraGraphLogsAsync, "Getting Entra Graph Logs");

#pragma warning disable SA1101
            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
#pragma warning restore SA1101
        }

        private async Task<List<EntraLogEntry>> GetEntraGraphLogsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Entra ID Graph Log Collection");

#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Not connected to Microsoft Graph. Please run Connect-M365 first.");
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            var graphClient = AuthManager.GraphClient!;
#pragma warning restore SA1101

            // Set default dates
#pragma warning disable SA1101
            var startDate = StartDate ?? DateTime.UtcNow.AddDays(-30);
#pragma warning restore SA1101
#pragma warning disable SA1101
            var endDate = EndDate ?? DateTime.UtcNow;
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Start Date: {startDate:yyyy-MM-dd HH:mm:ss}");
            WriteVerboseWithTimestamp($"End Date: {endDate:yyyy-MM-dd HH:mm:ss}");
#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Log Type: {LogType}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            if (UserIds?.Length > 0)
            {
#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"Filtering for Users: {string.Join(", ", UserIds)}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            var allResults = new List<EntraLogEntry>();
            var summary = new EntraLogSummary
            {
                StartTime = DateTime.UtcNow
            };

            // Collect Sign-In Logs
#pragma warning disable SA1101
            if (LogType == "SignIn" || LogType == "Both")
            {
                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Collecting Sign-In Logs",
                    PercentComplete = 10
                });

#pragma warning disable SA1101
                var signInResults = await CollectSignInLogsAsync(graphClient, startDate, endDate, progress, cancellationToken);
#pragma warning restore SA1101
                allResults.AddRange(signInResults);
                summary.SignInRecords = signInResults.Count;

                WriteVerboseWithTimestamp($"Collected {signInResults.Count} sign-in log entries");
            }
#pragma warning restore SA1101

            // Collect Audit Logs
#pragma warning disable SA1101
            if (LogType == "Audit" || LogType == "Both")
            {
                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Collecting Audit Logs",
                    PercentComplete = 60
                });

#pragma warning disable SA1101
                var auditResults = await CollectAuditLogsAsync(graphClient, startDate, endDate, progress, cancellationToken);
#pragma warning restore SA1101
                allResults.AddRange(auditResults);
                summary.AuditRecords = auditResults.Count;

                WriteVerboseWithTimestamp($"Collected {auditResults.Count} audit log entries");
            }
#pragma warning restore SA1101

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Exporting results",
                PercentComplete = 90
            });

            // Export results if output directory is specified
#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(OutputDirectory))
            {
#pragma warning disable SA1101
                await ExportLogsAsync(allResults, summary, cancellationToken);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

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
#pragma warning disable SA1101
            var eventTypesToProcess = DetermineEventTypes();
#pragma warning restore SA1101

            var currentEventType = 1;
            foreach (var eventType in eventTypesToProcess)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                WriteVerboseWithTimestamp($"Acquiring {eventType} sign-in logs");

#pragma warning disable SA1101
                var filter = BuildSignInFilter(startDate, endDate, eventType);
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                                results.Add(MapSignInToLogEntry(signIn, eventType));
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                    WriteErrorWithTimestamp($"Error collecting {eventType} sign-in logs: {ex.Message}", ex);
#pragma warning restore SA1101
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

#pragma warning disable SA1101
            var filter = BuildAuditFilter(startDate, endDate);
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                            results.Add(MapAuditToLogEntry(audit));
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Error collecting audit logs: {ex.Message}", ex);
#pragma warning restore SA1101
            }

            return results;
        }

        private List<string> DetermineEventTypes()
        {
#pragma warning disable SA1101
            if (EventTypes.Contains("All"))
            {
#pragma warning disable SA1101
                if (UserIds?.Length > 0)
                {
                    // When filtering by users, skip service principal and managed identity as they won't have results
                    return new List<string> { "InteractiveUser", "NonInteractiveUser" };
                }
                else
                {
                    return new List<string> { "InteractiveUser", "NonInteractiveUser", "ServicePrincipal", "ManagedIdentity" };
                }
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            return EventTypes.ToList();
#pragma warning restore SA1101
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
#pragma warning disable SA1101
            if (UserIds?.Length > 0 && (eventType.ToLowerInvariant().Contains("user")))
            {
#pragma warning disable SA1101
                var userFilters = UserIds.Select(u => $"startsWith(userPrincipalName, '{u}')");
#pragma warning restore SA1101
                filter += $" and ({string.Join(" or ", userFilters)})";
            }
#pragma warning restore SA1101

            return filter;
        }

        private string BuildAuditFilter(DateTime startDate, DateTime endDate)
        {
            var startDateStr = startDate.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var endDateStr = endDate.ToString("yyyy-MM-ddTHH:mm:ssZ");

            var filter = $"activityDateTime ge {startDateStr} and activityDateTime le {endDateStr}";

#pragma warning disable SA1101
            if (UserIds?.Length > 0)
            {
#pragma warning disable SA1101
                var userFilters = UserIds.Select(u => $"startsWith(initiatedBy/user/userPrincipalName, '{u}')");
#pragma warning restore SA1101
                filter += $" and ({string.Join(" or ", userFilters)})";

#pragma warning disable SA1101
                if (IncludeTargetResources.IsPresent)
                {
#pragma warning disable SA1101
                    var targetFilters = UserIds.Select(u => $"targetResources/any(tr: tr/userPrincipalName eq '{u}')");
#pragma warning restore SA1101
                    filter = $"({filter}) or ({string.Join(" or ", targetFilters)})";
                }
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

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
#pragma warning disable SA1101
            Directory.CreateDirectory(OutputDirectory!);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (MergeOutput.IsPresent)
            {
                // Export all logs to single file
#pragma warning disable SA1101
                await ExportLogFile(results, "Combined", cancellationToken);
#pragma warning restore SA1101
            }
            else
            {
                // Export by log type
                var signInLogs = results.Where(r => r.LogType == "SignIn").ToList();
                var auditLogs = results.Where(r => r.LogType == "Audit").ToList();

                if (signInLogs.Any())
                {
#pragma warning disable SA1101
                    await ExportLogFile(signInLogs, "SignIn", cancellationToken);
#pragma warning restore SA1101
                }

                if (auditLogs.Any())
                {
#pragma warning disable SA1101
                    await ExportLogFile(auditLogs, "Audit", cancellationToken);
#pragma warning restore SA1101
                }
            }
#pragma warning restore SA1101

            // Export summary
#pragma warning disable SA1101
            var summaryPath = Path.Combine(OutputDirectory!, $"{DateTime.UtcNow:yyyyMMddHHmmss}-EntraLogSummary.json");
#pragma warning restore SA1101
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
#pragma warning disable SA1101
            var fileName = Path.Combine(OutputDirectory!, $"{timestamp}-{logType}Logs.json");
#pragma warning restore SA1101

            using var stream = File.Create(fileName);
            using var processor = new HighPerformanceJsonProcessor();
            await processor.SerializeAsync(stream, logs, true, cancellationToken);

            WriteVerboseWithTimestamp($"Exported {logs.Count} {logType} log entries to {fileName}");
        }
    }

#pragma warning disable SA1600
    public class EntraLogEntry
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string Id { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string LogType { get; set; } = string.Empty; // SignIn or Audit
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string EventType { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime Timestamp { get; set; }
        public string UserPrincipalName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string AppDisplayName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ClientAppUsed { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string IpAddress { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Location { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string DeviceDetail { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Status { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string RiskLevelDuringSignIn { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string RiskState { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ConditionalAccessStatus { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ActivityDisplayName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Category { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Result { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ResultReason { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string CorrelationId { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Details { get; set; } = string.Empty;
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class EntraLogSummary
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public TimeSpan ProcessingTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalRecords { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int SignInRecords { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int AuditRecords { get; set; }
        public List<string> EventTypesProcessed { get; set; } = new();
#pragma warning restore SA1600
    }
}
