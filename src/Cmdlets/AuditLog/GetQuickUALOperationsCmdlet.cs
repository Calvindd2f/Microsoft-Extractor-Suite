namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
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


    [Cmdlet(VerbsCommon.Get, "QuickUALOperations")]
    [OutputType(typeof(PSObject))]
#pragma warning disable SA1600
    public class GetQuickUALOperationsCmdlet : AsyncBaseCmdlet
#pragma warning restore SA1600
    {
        [Parameter(Mandatory = true, HelpMessage = "Array of specific operations to search for (e.g., 'SearchQueryInitiated', 'MailItemsAccessed')")]
#pragma warning disable SA1600
        public string[] Operations { get; set; } = Array.Empty<string>();
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Comma-separated list of user IDs to filter on")]
#pragma warning disable SA1600
        public string? UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Start date for the search (defaults to 7 days ago)")]
#pragma warning disable SA1600
        public DateTime? StartDate { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "End date for the search (defaults to now)")]
#pragma warning disable SA1600
        public DateTime? EndDate { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Output directory for results")]
#pragma warning disable SA1600
        public new string OutputDirectory { get; set; } = "Output\\QuickUAL";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Maximum number of results to retrieve per operation (default: 5000)")]
#pragma warning disable SA1600
        public int MaxResults { get; set; } = 5000;
#pragma warning restore SA1600

        [Parameter(HelpMessage = "The level of logging.")]
        [ValidateSet("None", "Minimal", "Standard", "Debug")]
#pragma warning disable SA1600
        public new string LogLevel { get; set; } = "Standard";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Output format (CSV or JSON)")]
        [ValidateSet("CSV", "JSON")]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "CSV";
#pragma warning restore SA1600

#pragma warning disable SA1600
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
            // Set default dates if not provided
#pragma warning disable SA1101
            if (!StartDate.HasValue)
            {
#pragma warning disable SA1101
                StartDate = DateTime.UtcNow.AddDays(-7);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!EndDate.HasValue)
            {
#pragma warning disable SA1101
                EndDate = DateTime.UtcNow;
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            var results = RunAsyncOperation(GetQuickUALOperationsAsync, "Quick UAL Operations Search");

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

        private async Task<List<PSObject>> GetQuickUALOperationsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("=== Starting Quick UAL Operations Search ===");
#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Operations: {string.Join(", ", Operations)}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Date Range: {StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(UserIds))
            {
#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"User Filter: {UserIds}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

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

            var allResults = new List<PSObject>();
            var operationResults = new Dictionary<string, List<PSObject>>();
#pragma warning disable SA1101
            var summary = new UALOperationsSummary
            {
                StartTime = DateTime.UtcNow,
                Operations = Operations.ToList(),
                DateRange = $"{StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}"
            };
#pragma warning restore SA1101

            var processedOperations = 0;
#pragma warning disable SA1101
            foreach (var operation in Operations)
            {
                WriteVerboseWithTimestamp($"Searching for operation: {operation}");

                try
                {
#pragma warning disable SA1101
                    var results = await SearchOperationAsync(operation, cancellationToken);
#pragma warning restore SA1101

                    if (results.Any())
                    {
                        operationResults[operation] = results;
                        allResults.AddRange(results);
                        summary.OperationCounts[operation] = results.Count;
                        WriteVerboseWithTimestamp($"Found {results.Count} events for {operation}");
                    }
                    else
                    {
                        summary.OperationCounts[operation] = 0;
                        WriteVerboseWithTimestamp($"No events found for {operation}");
                    }
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Error searching for {operation}: {ex.Message}");
#pragma warning restore SA1101
                    summary.OperationCounts[operation] = -1; // Indicate error
                }

                processedOperations++;
#pragma warning disable SA1101
                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = $"Processing operations",
                    ItemsProcessed = processedOperations,
                    TotalItems = Operations.Length,
                    PercentComplete = (processedOperations * 100) / Operations.Length
                });
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            summary.TotalEvents = allResults.Count;
            summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

            // Export results
            if (allResults.Any())
            {
#pragma warning disable SA1101
                await ExportResultsAsync(operationResults, cancellationToken);
#pragma warning restore SA1101
            }

            // Write summary
#pragma warning disable SA1101
            WriteSummary(summary);
#pragma warning restore SA1101

            return allResults;
        }

        private async Task<List<PSObject>> SearchOperationAsync(
            string operation,
            CancellationToken cancellationToken)
        {
            var results = new List<PSObject>();

            // Build the PowerShell command to search UAL
            using (var ps = System.Management.Automation.PowerShell.Create(RunspaceMode.CurrentRunspace))
            {
                ps.AddCommand("Search-UnifiedAuditLog");
                ps.AddParameter("Operations", operation);
#pragma warning disable SA1101
                ps.AddParameter("StartDate", StartDate);
#pragma warning restore SA1101
#pragma warning disable SA1101
                ps.AddParameter("EndDate", EndDate);
#pragma warning restore SA1101
#pragma warning disable SA1101
                ps.AddParameter("ResultSize", MaxResults);
#pragma warning restore SA1101
                ps.AddParameter("SessionCommand", "ReturnLargeSet");

#pragma warning disable SA1101
                if (!string.IsNullOrEmpty(UserIds))
                {
#pragma warning disable SA1101
                    ps.AddParameter("UserIds", UserIds);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                try
                {
                    var searchResults = await Task.Run(() => ps.Invoke(), cancellationToken);

                    if (ps.HadErrors)
                    {
                        foreach (var error in ps.Streams.Error)
                        {
#pragma warning disable SA1101
                            WriteWarningWithTimestamp($"Search error: {error}");
#pragma warning restore SA1101
                        }
                    }

                    foreach (var result in searchResults)
                    {
                        // Extract and process the audit data
#pragma warning disable SA1101
                        var processedResult = ProcessAuditLogEntry(result, operation);
#pragma warning restore SA1101
                        if (processedResult != null)
                        {
                            results.Add(processedResult);
                        }
                    }
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteErrorWithTimestamp($"Failed to search for operation {operation}", ex);
#pragma warning restore SA1101
                }
            }

            return results;
        }

        private PSObject? ProcessAuditLogEntry(PSObject entry, string operation)
        {
            try
            {
                var auditData = entry.Properties["AuditData"]?.Value?.ToString();
                if (string.IsNullOrEmpty(auditData))
                {
                    return null;
                }

                // Parse the JSON audit data
                dynamic? data = Newtonsoft.Json.JsonConvert.DeserializeObject(auditData);
                if (data == null)
                {
                    return null;
                }

                var processedEntry = new PSObject();

                // Add standard fields
                processedEntry.Properties.Add(new PSNoteProperty("Operation", operation));
                processedEntry.Properties.Add(new PSNoteProperty("CreationDate", entry.Properties["CreationDate"]?.Value));
                processedEntry.Properties.Add(new PSNoteProperty("UserIds", entry.Properties["UserIds"]?.Value));
                processedEntry.Properties.Add(new PSNoteProperty("RecordType", entry.Properties["RecordType"]?.Value));
                processedEntry.Properties.Add(new PSNoteProperty("ResultStatus", entry.Properties["ResultStatus"]?.Value));

                // Add parsed audit data fields
                processedEntry.Properties.Add(new PSNoteProperty("UserId", (string?)data.UserId));
                processedEntry.Properties.Add(new PSNoteProperty("ClientIP", (string?)data.ClientIP));
                processedEntry.Properties.Add(new PSNoteProperty("Workload", (string?)data.Workload));
                processedEntry.Properties.Add(new PSNoteProperty("ObjectId", (string?)data.ObjectId));
                processedEntry.Properties.Add(new PSNoteProperty("ResultStatus", (string?)data.ResultStatus));

                // Add operation-specific fields
                switch (operation.ToLower())
                {
                    case "mailitemsaccessed":
                        processedEntry.Properties.Add(new PSNoteProperty("SessionId", (string?)data.SessionId));
                        processedEntry.Properties.Add(new PSNoteProperty("InternetMessageId", (string?)data.InternetMessageId));
                        processedEntry.Properties.Add(new PSNoteProperty("Subject", (string?)data.Subject));
                        break;

                    case "searchqueryinitiated":
                        processedEntry.Properties.Add(new PSNoteProperty("SearchQuery", (string?)data.SearchQuery));
                        processedEntry.Properties.Add(new PSNoteProperty("SearchScope", (string?)data.SearchScope));
                        break;

                    case "new-inboxrule":
                    case "set-inboxrule":
                        processedEntry.Properties.Add(new PSNoteProperty("RuleName", (string?)data.Parameters?.FirstOrDefault((Func<dynamic, bool>)(p => p.Name == "Name"))?.Value));
                        processedEntry.Properties.Add(new PSNoteProperty("ForwardTo", (string?)data.Parameters?.FirstOrDefault((Func<dynamic, bool>)(p => p.Name == "ForwardTo"))?.Value));
                        processedEntry.Properties.Add(new PSNoteProperty("DeleteMessage", (string?)data.Parameters?.FirstOrDefault((Func<dynamic, bool>)(p => p.Name == "DeleteMessage"))?.Value));
                        break;
                }

                // Add the full audit data as a property for detailed analysis
                processedEntry.Properties.Add(new PSNoteProperty("AuditDataJson", auditData));

                return processedEntry;
            }
            catch (Exception ex)
            {
                WriteVerboseWithTimestamp($"Failed to process audit entry: {ex.Message}");
                return null;
            }
        }

        private async Task ExportResultsAsync(
            Dictionary<string, List<PSObject>> operationResults,
            CancellationToken cancellationToken)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");

            foreach (var kvp in operationResults)
            {
                var operation = kvp.Key.Replace("-", "").Replace(" ", "");
                var results = kvp.Value;

                if (!results.Any())
                    continue;

#pragma warning disable SA1101
                var fileName = Path.Combine(OutputDirectory, $"{timestamp}-{operation}.{OutputFormat.ToLower()}");
#pragma warning restore SA1101

                WriteVerboseWithTimestamp($"Exporting {results.Count} results for {kvp.Key} to {fileName}");

#pragma warning disable SA1101
                if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
                {
                    using var stream = File.Create(fileName);
                    using var processor = new HighPerformanceJsonProcessor();
                    await processor.SerializeAsync(stream, results, true, cancellationToken);
                }
                else // CSV
                {
                    // Convert PSObject to dictionary for CSV export
                    var csvData = results.Select(r =>
                    {
                        var dict = new Dictionary<string, object?>();
                        foreach (var prop in r.Properties)
                        {
                            if (prop.Name != "AuditDataJson") // Exclude large JSON from CSV
                            {
                                dict[prop.Name] = prop.Value;
                            }
                        }
                        return dict;
                    });

                    using var writer = new StreamWriter(fileName);
                    using var csv = new CsvWriter(writer, System.Globalization.CultureInfo.InvariantCulture);
                    await csv.WriteRecordsAsync(csvData);
                }
#pragma warning restore SA1101
            }

            // Create a summary file
#pragma warning disable SA1101
            var summaryFile = Path.Combine(OutputDirectory, $"{timestamp}-Summary.txt");
#pragma warning restore SA1101
#pragma warning disable SA1101
            var summaryContent = new List<string>
            {
                "Quick UAL Operations Search Summary",
                "====================================",
                $"Search Date Range: {StartDate:yyyy-MM-dd HH:mm:ss} to {EndDate:yyyy-MM-dd HH:mm:ss}",
                $"User Filter: {UserIds ?? "All Users"}",
                $"Max Results per Operation: {MaxResults}",
                "",
                "Results by Operation:",
                "--------------------"
            };
#pragma warning restore SA1101

            foreach (var kvp in operationResults.OrderByDescending(x => x.Value.Count))
            {
                summaryContent.Add($"  {kvp.Key}: {kvp.Value.Count} events");
            }

            using (var writer = new StreamWriter(summaryFile)) { foreach (var line in summaryContent) await writer.WriteLineAsync(line); }
        }

        private void WriteSummary(UALOperationsSummary summary)
        {
#pragma warning disable SA1101
            WriteHost("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost("=== Quick UAL Operations Summary ===", ConsoleColor.Cyan);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Date Range: {summary.DateRange}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Total Events Found: {summary.TotalEvents}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost("Events by Operation:");
#pragma warning restore SA1101

            foreach (var op in summary.OperationCounts.OrderByDescending(x => x.Value))
            {
                var color = op.Value switch
                {
                    -1 => ConsoleColor.Red,
                    0 => ConsoleColor.Yellow,
                    _ => ConsoleColor.Green
                };

                var status = op.Value switch
                {
                    -1 => "ERROR",
                    0 => "No events",
                    _ => $"{op.Value} events"
                };

#pragma warning disable SA1101
                WriteHost($"  {op.Key}: {status}", color);
#pragma warning restore SA1101
            }

#pragma warning disable SA1101
            WriteHost("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Processing Time: {summary.ProcessingTime:mm\\:ss}", ConsoleColor.Green);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost("=====================================", ConsoleColor.Cyan);
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
    internal class UALOperationsSummary
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public TimeSpan ProcessingTime { get; set; }
        public List<string> Operations { get; set; } = new();
#pragma warning restore SA1600
#pragma warning disable SA1600
        public Dictionary<string, int> OperationCounts { get; set; } = new();
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalEvents { get; set; }
        public string DateRange { get; set; } = string.Empty;
#pragma warning restore SA1600
    }
}
