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
using CsvHelper;
using System.Globalization;

namespace Microsoft.ExtractorSuite.Cmdlets.Azure
{
    /// <summary>
    /// Retrieves Azure Directory Activity logs.
    /// Collects directory management events from Azure Active Directory within a specified date range.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AzureDirectoryActivityLogs")]
    [OutputType(typeof(DirectoryActivityLogEntry))]
    public class GetAzureDirectoryActivityLogsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "Start date for log collection. Default: 90 days ago")]
        public DateTime? StartDate { get; set; }

        [Parameter(HelpMessage = "End date for log collection. Default: Now")]
        public DateTime? EndDate { get; set; }

        [Parameter(HelpMessage = "Output format for the results. Default: CSV")]
        [ValidateSet("CSV", "JSON", "JSONL")]
        public string OutputFormat { get; set; } = "CSV";

        [Parameter(HelpMessage = "Text encoding for the output file. Default: UTF8")]
        public string Encoding { get; set; } = "UTF8";

        private readonly HttpClient _httpClient;

        public GetAzureDirectoryActivityLogsCmdlet()
        {
            _httpClient = new HttpClient();
        }

        protected override void ProcessRecord()
        {
            var results = RunAsyncOperation(GetDirectoryActivityLogsAsync, "Getting Directory Activity Logs");

            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
        }

        private async Task<List<DirectoryActivityLogEntry>> GetDirectoryActivityLogsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Directory Activity Log Analysis");

            // Set default dates
            var startDate = StartDate ?? DateTime.UtcNow.AddDays(-90);
            var endDate = EndDate ?? DateTime.UtcNow;

            WriteVerboseWithTimestamp($"Start Date: {startDate:yyyy-MM-dd HH:mm:ss}");
            WriteVerboseWithTimestamp($"End Date: {endDate:yyyy-MM-dd HH:mm:ss}");

            var summary = new DirectoryActivityLogSummary
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
                CurrentOperation = "Retrieving Directory Activity logs",
                PercentComplete = 20
            });

            var events = await GetDirectoryActivityEventsAsync(accessToken, startDate, endDate, cancellationToken);

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Processing and exporting results",
                PercentComplete = 80
            });

            summary.TotalRecords = events.Count;
            summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

            WriteVerboseWithTimestamp($"Retrieved {events.Count} directory activity log entries");

            // Export results if output directory is specified
            if (!string.IsNullOrEmpty(OutputDirectory))
            {
                await ExportDirectoryLogsAsync(events, cancellationToken);
                summary.FilesCreated = 1;
            }

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Collection completed",
                PercentComplete = 100
            });

            // Log summary
            WriteVerboseWithTimestamp($"Directory Activity Log Collection Summary:");
            WriteVerboseWithTimestamp($"  Total Records: {summary.TotalRecords}");
            WriteVerboseWithTimestamp($"  Date Range: {summary.DateRange}");
            WriteVerboseWithTimestamp($"  Processing Time: {summary.ProcessingTime:mm\\:ss}");

            return events;
        }

        private async Task<string> GetAzureAccessTokenAsync(CancellationToken cancellationToken)
        {
            // This would integrate with the AuthenticationManager to get Azure tokens
            // For now, we'll simulate
            await Task.Delay(100, cancellationToken);
            return "simulated-token";
        }

        private async Task<List<DirectoryActivityLogEntry>> GetDirectoryActivityEventsAsync(
            string accessToken,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken)
        {
            var events = new List<DirectoryActivityLogEntry>();
            var startDateStr = startDate.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var endDateStr = endDate.ToString("yyyy-MM-ddTHH:mm:ssZ");

            // Use Azure Management API for directory activity logs
            var uriBase = "https://management.azure.com/providers/microsoft.insights/eventtypes/management/values" +
                         $"?api-version=2015-04-01&$filter=eventTimestamp ge '{startDateStr}' and eventTimestamp le '{endDateStr}'";

            var apiCallCount = 0;

            try
            {
                do
                {
                    apiCallCount++;
                    WriteVerboseWithTimestamp($"Making API call #{apiCallCount} for directory activity logs");

                    _httpClient.DefaultRequestHeaders.Clear();
                    _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                    _httpClient.DefaultRequestHeaders.Add("Content-Type", "application/json");

                    var response = await _httpClient.GetAsync(uriBase, cancellationToken);
                    response.EnsureSuccessStatusCode();

                    var content = await response.Content.ReadAsStringAsync();
                    var activityResponse = JsonSerializer.Deserialize<DirectoryActivityLogResponse>(content);

                    if (activityResponse?.Value != null && activityResponse.Value.Any())
                    {
                        // Process and transform the events
                        var processedEvents = activityResponse.Value.Select(ProcessEvent).ToList();
                        events.AddRange(processedEvents);

                        WriteVerboseWithTimestamp($"Retrieved {activityResponse.Value.Count} events in batch {apiCallCount}");
                    }

                    uriBase = activityResponse?.NextLink;

                } while (!string.IsNullOrEmpty(uriBase) && !cancellationToken.IsCancellationRequested);

                WriteVerboseWithTimestamp($"Completed API calls. Total calls: {apiCallCount}, Total events: {events.Count}");
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Error retrieving directory activity logs: {ex.Message}", ex);
                throw;
            }

            return events;
        }

        private DirectoryActivityLogEntry ProcessEvent(dynamic eventData)
        {
            // Transform the raw event data into our structured format
            return new DirectoryActivityLogEntry
            {
                Id = GetStringProperty(eventData, "id") ?? Guid.NewGuid().ToString(),
                EventTimestamp = GetDateTimeProperty(eventData, "eventTimestamp") ?? DateTime.UtcNow,
                EventName = GetStringProperty(eventData, "eventName") ?? "Unknown",
                Category = GetStringProperty(eventData, "category") ?? "Administrative",
                Level = GetStringProperty(eventData, "level") ?? "Informational",
                OperationName = GetStringProperty(eventData, "operationName") ?? "Unknown",
                Status = GetStringProperty(eventData, "status") ?? "Unknown",
                SubStatus = GetStringProperty(eventData, "subStatus") ?? "",
                Caller = GetStringProperty(eventData, "caller") ?? "Unknown",
                Description = GetStringProperty(eventData, "description") ?? "",
                ResourceGroupName = GetStringProperty(eventData, "resourceGroupName") ?? "",
                ResourceProviderName = GetStringProperty(eventData, "resourceProviderName") ?? "",
                ResourceType = GetStringProperty(eventData, "resourceType") ?? "",
                ResourceId = GetStringProperty(eventData, "resourceId") ?? "",
                TenantId = GetStringProperty(eventData, "tenantId") ?? "",
                SubscriptionId = GetStringProperty(eventData, "subscriptionId") ?? "",
                CorrelationId = GetStringProperty(eventData, "correlationId") ?? "",
                Properties = ExtractProperties(eventData)
            };
        }

        private string? GetStringProperty(dynamic obj, string propertyName)
        {
            try
            {
                if (obj is JsonElement element && element.TryGetProperty(propertyName, out JsonElement prop))
                {
                    return prop.ValueKind == JsonValueKind.String ? prop.GetString() : prop.ToString();
                }
                return obj?.GetType().GetProperty(propertyName)?.GetValue(obj)?.ToString();
            }
            catch
            {
                return null;
            }
        }

        private DateTime? GetDateTimeProperty(dynamic obj, string propertyName)
        {
            try
            {
                var value = GetStringProperty(obj, propertyName);
                return DateTime.TryParse(value, out DateTime result) ? result : null;
            }
            catch
            {
                return null;
            }
        }

        private Dictionary<string, object> ExtractProperties(dynamic eventData)
        {
            var properties = new Dictionary<string, object>();

            try
            {
                if (eventData is JsonElement element)
                {
                    foreach (var prop in element.EnumerateObject())
                    {
                        // Skip properties we've already extracted
                        if (IsStandardProperty(prop.Name))
                            continue;

                        properties[prop.Name] = prop.Value.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                WriteVerboseWithTimestamp($"Error extracting properties: {ex.Message}");
            }

            return properties;
        }

        private bool IsStandardProperty(string propertyName)
        {
            var standardProps = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "id", "eventTimestamp", "eventName", "category", "level", "operationName",
                "status", "subStatus", "caller", "description", "resourceGroupName",
                "resourceProviderName", "resourceType", "resourceId", "tenantId",
                "subscriptionId", "correlationId"
            };

            return standardProps.Contains(propertyName);
        }

        private async Task ExportDirectoryLogsAsync(
            List<DirectoryActivityLogEntry> events,
            CancellationToken cancellationToken)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            string fileName;

            Directory.CreateDirectory(OutputDirectory!);

            switch (OutputFormat.ToUpperInvariant())
            {
                case "JSON":
                    fileName = Path.Combine(OutputDirectory!, $"{timestamp}-DirectoryActivityLogs.json");
                    using (var stream = File.Create(fileName))
                    using (var processor = new HighPerformanceJsonProcessor())
                    {
                        await processor.SerializeAsync(stream, events, true, cancellationToken);
                    }
                    break;

                case "JSONL":
                    fileName = Path.Combine(OutputDirectory!, $"{timestamp}-DirectoryActivityLogs.jsonl");
                    using (var writer = new StreamWriter(fileName, false, System.Text.Encoding.GetEncoding(Encoding)))
                    {
                        foreach (var eventEntry in events)
                        {
                            var json = JsonSerializer.Serialize(eventEntry, new JsonSerializerOptions
                            {
                                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                            });
                            await writer.WriteLineAsync(json);
                        }
                    }
                    break;

                default: // CSV
                    fileName = Path.Combine(OutputDirectory!, $"{timestamp}-DirectoryActivityLogs.csv");
                    using (var writer = new StreamWriter(fileName, false, System.Text.Encoding.GetEncoding(Encoding)))
                    using (var csv = new CsvWriter(writer, CultureInfo.InvariantCulture))
                    {
                        await csv.WriteRecordsAsync(events, cancellationToken);
                    }
                    break;
            }

            WriteVerboseWithTimestamp($"Exported {events.Count} directory activity log entries to {fileName}");
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

    public class DirectoryActivityLogEntry
    {
        public string Id { get; set; } = string.Empty;
        public DateTime EventTimestamp { get; set; }
        public string EventName { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Level { get; set; } = string.Empty;
        public string OperationName { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string SubStatus { get; set; } = string.Empty;
        public string Caller { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string ResourceGroupName { get; set; } = string.Empty;
        public string ResourceProviderName { get; set; } = string.Empty;
        public string ResourceType { get; set; } = string.Empty;
        public string ResourceId { get; set; } = string.Empty;
        public string TenantId { get; set; } = string.Empty;
        public string SubscriptionId { get; set; } = string.Empty;
        public string CorrelationId { get; set; } = string.Empty;
        public Dictionary<string, object> Properties { get; set; } = new();
    }

    public class DirectoryActivityLogSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public string DateRange { get; set; } = string.Empty;
        public int TotalRecords { get; set; }
        public int FilesCreated { get; set; }
    }

    public class DirectoryActivityLogResponse
    {
        public List<dynamic>? Value { get; set; }
        public string? NextLink { get; set; }
    }
}
