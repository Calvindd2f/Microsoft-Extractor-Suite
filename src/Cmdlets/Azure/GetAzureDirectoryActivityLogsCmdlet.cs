namespace Microsoft.ExtractorSuite.Cmdlets.Azure
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Net.Http;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using CsvHelper;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Json;


    /// <summary>
    /// Retrieves Azure Directory Activity logs.
    /// Collects directory management events from Azure Active Directory within a specified date range.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AzureDirectoryActivityLogs")]
    [OutputType(typeof(DirectoryActivityLogEntry))]
    public class GetAzureDirectoryActivityLogsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "Start date for log collection. Default: 90 days ago")]
#pragma warning disable SA1600
        public DateTime? StartDate { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "End date for log collection. Default: Now")]
#pragma warning disable SA1600
        public DateTime? EndDate { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Output format for the results. Default: CSV")]
        [ValidateSet("CSV", "JSON", "JSONL")]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "CSV";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Text encoding for the output file. Default: UTF8")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

#pragma warning disable SA1309
#pragma warning disable SA1201
        private readonly HttpClient _httpClient;
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning restore SA1309

        public GetAzureDirectoryActivityLogsCmdlet()
        {
#pragma warning disable SA1101
            _httpClient = new HttpClient();
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected override void ProcessRecord()
        {
            var results = RunAsyncOperation(GetDirectoryActivityLogsAsync, "Getting Directory Activity Logs");

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

        private async Task<List<DirectoryActivityLogEntry>> GetDirectoryActivityLogsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Directory Activity Log Analysis");

            // Set default dates
#pragma warning disable SA1101
            var startDate = StartDate ?? DateTime.UtcNow.AddDays(-90);
#pragma warning restore SA1101
#pragma warning disable SA1101
            var endDate = EndDate ?? DateTime.UtcNow;
#pragma warning restore SA1101

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
#pragma warning disable SA1101
            var accessToken = await GetAzureAccessTokenAsync(cancellationToken);
#pragma warning restore SA1101

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Retrieving Directory Activity logs",
                PercentComplete = 20
            });

#pragma warning disable SA1101
            var events = await GetDirectoryActivityEventsAsync(accessToken, startDate, endDate, cancellationToken);
#pragma warning restore SA1101

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Processing and exporting results",
                PercentComplete = 80
            });

            summary.TotalRecords = events.Count;
            summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

            WriteVerboseWithTimestamp($"Retrieved {events.Count} directory activity log entries");

            // Export results if output directory is specified
#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(OutputDirectory))
            {
#pragma warning disable SA1101
                await ExportDirectoryLogsAsync(events, cancellationToken);
#pragma warning restore SA1101
                summary.FilesCreated = 1;
            }
#pragma warning restore SA1101

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
                {
                    apiCallCount++;
                    WriteVerboseWithTimestamp($"Making API call #{apiCallCount} for directory activity logs");

#pragma warning disable SA1101
                    _httpClient.DefaultRequestHeaders.Clear();
#pragma warning restore SA1101
#pragma warning disable SA1101
                    _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    _httpClient.DefaultRequestHeaders.Add("Content-Type", "application/json");
#pragma warning restore SA1101

#pragma warning disable SA1101
                    var response = await _httpClient.GetAsync(uriBase, cancellationToken);
#pragma warning restore SA1101
                    response.EnsureSuccessStatusCode();

                    var content = await response.Content.ReadAsStringAsync();
                    var activityResponse = JsonSerializer.Deserialize<DirectoryActivityLogResponse>(content);

                    if (activityResponse?.Value != null && activityResponse.Value.Any())
                    {
                        // Process and transform the events
#pragma warning disable SA1101
                        var processedEvents = activityResponse.Value.Select(ProcessEvent).ToList();
#pragma warning restore SA1101
                        events.AddRange(processedEvents);

                        WriteVerboseWithTimestamp($"Retrieved {activityResponse.Value.Count} events in batch {apiCallCount}");
                    }

                    uriBase = activityResponse?.NextLink;

                } while (!string.IsNullOrEmpty(uriBase) && !cancellationToken.IsCancellationRequested);

                WriteVerboseWithTimestamp($"Completed API calls. Total calls: {apiCallCount}, Total events: {events.Count}");
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Error retrieving directory activity logs: {ex.Message}", ex);
#pragma warning restore SA1101
                throw;
            }

            return events;
        }

        private DirectoryActivityLogEntry ProcessEvent(dynamic eventData)
        {
            // Transform the raw event data into our structured format
#pragma warning disable SA1101
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
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                var value = GetStringProperty(obj, propertyName);
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                        if (IsStandardProperty(prop.Name))
                            continue;
#pragma warning restore SA1101

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

#pragma warning disable SA1101
            Directory.CreateDirectory(OutputDirectory!);
#pragma warning restore SA1101

#pragma warning disable SA1101
            switch (OutputFormat.ToUpperInvariant())
            {
                case "JSON":
#pragma warning disable SA1101
                    fileName = Path.Combine(OutputDirectory!, $"{timestamp}-DirectoryActivityLogs.json");
#pragma warning restore SA1101
                    using (var stream = File.Create(fileName))
                    using (var processor = new HighPerformanceJsonProcessor())
                    {
                        await processor.SerializeAsync(stream, events, true, cancellationToken);
                    }
                    break;

                case "JSONL":
#pragma warning disable SA1101
                    fileName = Path.Combine(OutputDirectory!, $"{timestamp}-DirectoryActivityLogs.jsonl");
#pragma warning restore SA1101
#pragma warning disable SA1101
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
#pragma warning restore SA1101
                    break;

                default: // CSV
#pragma warning disable SA1101
                    fileName = Path.Combine(OutputDirectory!, $"{timestamp}-DirectoryActivityLogs.csv");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    using (var writer = new StreamWriter(fileName, false, System.Text.Encoding.GetEncoding(Encoding)))
                    using (var csv = new CsvWriter(writer, CultureInfo.InvariantCulture))
                    {
                        await csv.WriteRecordsAsync(events, cancellationToken);
                    }
#pragma warning restore SA1101
                    break;
            }
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Exported {events.Count} directory activity log entries to {fileName}");
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
#pragma warning disable SA1101
                _httpClient?.Dispose();
#pragma warning restore SA1101
            }
            base.Dispose(disposing);
        }
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class DirectoryActivityLogEntry
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Id { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime EventTimestamp { get; set; }
        public string EventName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Category { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Level { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string OperationName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Status { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string SubStatus { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Caller { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Description { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ResourceGroupName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ResourceProviderName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ResourceType { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ResourceId { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string TenantId { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string SubscriptionId { get; set; } = string.Empty;
#pragma warning restore SA1600
        public string CorrelationId { get; set; } = string.Empty;
        public Dictionary<string, object> Properties { get; set; } = new();
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class DirectoryActivityLogSummary
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public TimeSpan ProcessingTime { get; set; }
        public string DateRange { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public int TotalRecords { get; set; }public int FilesCreated { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class DirectoryActivityLogResponse
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
        public List<dynamic>? Value { get; set; }
        public string? NextLink { get; set; }
    }
}
