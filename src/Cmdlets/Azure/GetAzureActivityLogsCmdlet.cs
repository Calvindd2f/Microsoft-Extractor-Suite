using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Json;

namespace Microsoft.ExtractorSuite.Cmdlets.Azure
{
    /// <summary>
    /// Retrieves Azure Activity logs from specified subscriptions.
    /// Collects management events from Azure subscriptions within a specified date range.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AzureActivityLogs")]
    [OutputType(typeof(ActivityLogEntry))]
    public class GetAzureActivityLogsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "Start date for log collection. Default: 89 days ago")]
        public DateTime? StartDate { get; set; }

        [Parameter(HelpMessage = "End date for log collection. Default: Now")]
        public DateTime? EndDate { get; set; }

        [Parameter(HelpMessage = "Specific subscription ID to collect logs from. If not provided, all accessible subscriptions will be processed")]
        public string? SubscriptionId { get; set; }

        [Parameter(HelpMessage = "Output format for the results. Default: JSON")]
        [ValidateSet("JSON")]
        public string OutputFormat { get; set; } = "JSON";

        [Parameter(HelpMessage = "Text encoding for the output file. Default: UTF8")]
        public string Encoding { get; set; } = "UTF8";

        private readonly HttpClient _httpClient;

        public GetAzureActivityLogsCmdlet()
        {
            _httpClient = new HttpClient();
        }

        protected override void ProcessRecord()
        {
            var results = RunAsyncOperation(GetAzureActivityLogsAsync, "Getting Azure Activity Logs");

            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
        }

        private async Task<List<ActivityLogEntry>> GetAzureActivityLogsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Azure Activity Log Collection");

            // Set default dates
            var startDate = StartDate ?? DateTime.UtcNow.AddDays(-89);
            var endDate = EndDate ?? DateTime.UtcNow;

            WriteVerboseWithTimestamp($"Start Date: {startDate:yyyy-MM-dd HH:mm:ss}");
            WriteVerboseWithTimestamp($"End Date: {endDate:yyyy-MM-dd HH:mm:ss}");

            var summary = new ActivityLogSummary
            {
                StartTime = DateTime.UtcNow,
                DateRange = $"{startDate:yyyy-MM-dd} to {endDate:yyyy-MM-dd}"
            };

            // Check Azure connection
            if (!RequireAzureConnection())
            {
                throw new InvalidOperationException("Not connected to Azure. Please run Connect-AzureAz first.");
            }

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Getting Azure access token",
                PercentComplete = 5
            });

            // Get access token
            var accessToken = await GetAzureAccessTokenAsync(cancellationToken);

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Retrieving subscriptions",
                PercentComplete = 10
            });

            // Get subscriptions to process
            var subscriptions = await GetSubscriptionsAsync(accessToken, cancellationToken);
            WriteVerboseWithTimestamp($"Found {subscriptions.Count} subscription(s) to process");

            var allResults = new List<ActivityLogEntry>();
            var subscriptionCount = 0;

            foreach (var subscription in subscriptions)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                subscriptionCount++;
                summary.SubscriptionsProcessed++;

                var subscriptionProgress = 10 + (int)((subscriptionCount / (double)subscriptions.Count) * 80);
                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = $"Processing subscription {subscriptionCount}/{subscriptions.Count}: {subscription.DisplayName}",
                    PercentComplete = subscriptionProgress
                });

                WriteVerboseWithTimestamp($"Processing subscription: {subscription.DisplayName} ({subscription.SubscriptionId})");

                var subscriptionResults = await GetSubscriptionActivityLogsAsync(
                    subscription, accessToken, startDate, endDate, cancellationToken);

                if (subscriptionResults.Any())
                {
                    allResults.AddRange(subscriptionResults);
                    summary.TotalRecords += subscriptionResults.Count;
                    summary.SubscriptionsWithData++;

                    WriteVerboseWithTimestamp($"Found {subscriptionResults.Count} activity logs in subscription: {subscription.SubscriptionId}");

                    // Export per subscription if output directory is specified
                    if (!string.IsNullOrEmpty(OutputDirectory))
                    {
                        await ExportSubscriptionLogsAsync(subscription, subscriptionResults, cancellationToken);
                        summary.TotalFiles++;
                    }
                }
                else
                {
                    summary.EmptySubscriptions++;
                    WriteWarningWithTimestamp($"No activity logs found in subscription: {subscription.SubscriptionId}");
                }
            }

            summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Collection completed",
                PercentComplete = 100
            });

            // Log summary
            WriteVerboseWithTimestamp($"Activity Log Collection Summary:");
            WriteVerboseWithTimestamp($"  Total Records: {summary.TotalRecords}");
            WriteVerboseWithTimestamp($"  Files Created: {summary.TotalFiles}");
            WriteVerboseWithTimestamp($"  Subscriptions Processed: {summary.SubscriptionsProcessed}");
            WriteVerboseWithTimestamp($"  Subscriptions with Data: {summary.SubscriptionsWithData}");
            WriteVerboseWithTimestamp($"  Empty Subscriptions: {summary.EmptySubscriptions}");
            WriteVerboseWithTimestamp($"  Processing Time: {summary.ProcessingTime:mm\\:ss}");

            return allResults;
        }

        private async Task<string> GetAzureAccessTokenAsync(CancellationToken cancellationToken)
        {
            // This would integrate with the AuthenticationManager to get Azure tokens
            // For now, we'll simulate
            await Task.Delay(100, cancellationToken);
            return "simulated-token";
        }

        private async Task<List<AzureSubscription>> GetSubscriptionsAsync(string accessToken, CancellationToken cancellationToken)
        {
            var subscriptions = new List<AzureSubscription>();

            if (!string.IsNullOrEmpty(SubscriptionId))
            {
                // Get specific subscription
                subscriptions.Add(new AzureSubscription
                {
                    SubscriptionId = SubscriptionId,
                    DisplayName = $"Subscription {SubscriptionId}",
                    State = "Enabled"
                });
            }
            else
            {
                // Get all subscriptions
                var subscriptionsUri = "https://management.azure.com/subscriptions?api-version=2020-01-01";

                try
                {
                    _httpClient.DefaultRequestHeaders.Clear();
                    _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                    _httpClient.DefaultRequestHeaders.Add("Content-Type", "application/json");

                    var response = await _httpClient.GetAsync(subscriptionsUri, cancellationToken);
                    response.EnsureSuccessStatusCode();

                    var content = await response.Content.ReadAsStringAsync();
                    var subscriptionResponse = JsonSerializer.Deserialize<SubscriptionResponse>(content);

                    if (subscriptionResponse?.Value != null)
                    {
                        subscriptions.AddRange(subscriptionResponse.Value);
                    }
                }
                catch (Exception ex)
                {
                    WriteErrorWithTimestamp($"Failed to retrieve subscriptions: {ex.Message}", ex);
                    throw;
                }
            }

            return subscriptions;
        }

        private async Task<List<ActivityLogEntry>> GetSubscriptionActivityLogsAsync(
            AzureSubscription subscription,
            string accessToken,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken)
        {
            var events = new List<ActivityLogEntry>();
            var startDateStr = startDate.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var endDateStr = endDate.ToString("yyyy-MM-ddTHH:mm:ssZ");

            var uriBase = $"https://management.azure.com/subscriptions/{subscription.SubscriptionId}/providers/Microsoft.Insights/eventtypes/management/values" +
                         $"?api-version=2015-04-01&$filter=eventTimestamp ge '{startDateStr}' and eventTimestamp le '{endDateStr}'";

            var apiCallCount = 0;

            try
            {
                do
                {
                    apiCallCount++;
                    WriteVerboseWithTimestamp($"Making API call #{apiCallCount} for subscription {subscription.SubscriptionId}");

                    _httpClient.DefaultRequestHeaders.Clear();
                    _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                    _httpClient.DefaultRequestHeaders.Add("Content-Type", "application/json");

                    var response = await _httpClient.GetAsync(uriBase, cancellationToken);
                    response.EnsureSuccessStatusCode();

                    var content = await response.Content.ReadAsStringAsync();
                    var activityResponse = JsonSerializer.Deserialize<ActivityLogResponse>(content);

                    if (activityResponse?.Value != null && activityResponse.Value.Any())
                    {
                        events.AddRange(activityResponse.Value);
                        WriteVerboseWithTimestamp($"Retrieved {activityResponse.Value.Count} events in batch {apiCallCount}");
                    }

                    uriBase = activityResponse?.NextLink;

                } while (!string.IsNullOrEmpty(uriBase) && !cancellationToken.IsCancellationRequested);

                WriteVerboseWithTimestamp($"Completed API calls for subscription. Total calls: {apiCallCount}, Total events: {events.Count}");
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Error retrieving activity logs for subscription {subscription.SubscriptionId}: {ex.Message}", ex);
                throw;
            }

            return events;
        }

        private async Task ExportSubscriptionLogsAsync(
            AzureSubscription subscription,
            List<ActivityLogEntry> events,
            CancellationToken cancellationToken)
        {
            var fileName = Path.Combine(
                OutputDirectory!,
                $"{DateTime.UtcNow:yyyyMMddHHmmss}-{subscription.SubscriptionId}-ActivityLog.json");

            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

            using var stream = File.Create(fileName);
            using var processor = new HighPerformanceJsonProcessor();
            await processor.SerializeAsync(stream, events, true, cancellationToken);

            WriteVerboseWithTimestamp($"Exported {events.Count} activity log entries to {fileName}");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _httpClient?.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    public class ActivityLogEntry
    {
        public string Id { get; set; } = string.Empty;
        public DateTime EventTimestamp { get; set; }
        public string EventName { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string ResourceGroupName { get; set; } = string.Empty;
        public string ResourceProviderName { get; set; } = string.Empty;
        public string ResourceType { get; set; } = string.Empty;
        public string ResourceId { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string SubStatus { get; set; } = string.Empty;
        public string Caller { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Level { get; set; } = string.Empty;
        public string OperationName { get; set; } = string.Empty;
        public string SubscriptionId { get; set; } = string.Empty;
        public string TenantId { get; set; } = string.Empty;
        public Dictionary<string, object> Properties { get; set; } = new();
    }

    public class AzureSubscription
    {
        public string SubscriptionId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public string TenantId { get; set; } = string.Empty;
    }

    public class ActivityLogSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public string DateRange { get; set; } = string.Empty;
        public int TotalRecords { get; set; }
        public int TotalFiles { get; set; }
        public int SubscriptionsProcessed { get; set; }
        public int SubscriptionsWithData { get; set; }
        public int EmptySubscriptions { get; set; }
    }

    public class SubscriptionResponse
    {
        public List<AzureSubscription>? Value { get; set; }
        public string? NextLink { get; set; }
    }

    public class ActivityLogResponse
    {
        public List<ActivityLogEntry>? Value { get; set; }
        public string? NextLink { get; set; }
    }
}
