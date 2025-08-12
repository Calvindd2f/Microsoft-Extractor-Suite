using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Json;
using CsvHelper;

namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
    [Cmdlet(VerbsCommon.Get, "QuickUALOperations")]
    [OutputType(typeof(PSObject))]
    public class GetQuickUALOperationsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "Array of specific operations to search for (e.g., 'SearchQueryInitiated', 'MailItemsAccessed')")]
        public string[] Operations { get; set; } = Array.Empty<string>();

        [Parameter(HelpMessage = "Comma-separated list of user IDs to filter on")]
        public string? UserIds { get; set; }

        [Parameter(HelpMessage = "Start date for the search (defaults to 7 days ago)")]
        public DateTime? StartDate { get; set; }

        [Parameter(HelpMessage = "End date for the search (defaults to now)")]
        public DateTime? EndDate { get; set; }

        [Parameter(HelpMessage = "Output directory for results")]
        public new string OutputDirectory { get; set; } = "Output\\QuickUAL";

        [Parameter(HelpMessage = "Maximum number of results to retrieve per operation (default: 5000)")]
        public int MaxResults { get; set; } = 5000;

        [Parameter(HelpMessage = "The level of logging.")]
        [ValidateSet("None", "Minimal", "Standard", "Debug")]
        public new string LogLevel { get; set; } = "Standard";

        [Parameter(HelpMessage = "Output format (CSV or JSON)")]
        [ValidateSet("CSV", "JSON")]
        public string OutputFormat { get; set; } = "CSV";

        protected override void ProcessRecord()
        {
            // Set default dates if not provided
            if (!StartDate.HasValue)
            {
                StartDate = DateTime.UtcNow.AddDays(-7);
            }

            if (!EndDate.HasValue)
            {
                EndDate = DateTime.UtcNow;
            }

            var results = RunAsyncOperation(GetQuickUALOperationsAsync, "Quick UAL Operations Search");

            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
        }

        private async Task<List<PSObject>> GetQuickUALOperationsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("=== Starting Quick UAL Operations Search ===");
            WriteVerboseWithTimestamp($"Operations: {string.Join(", ", Operations)}");
            WriteVerboseWithTimestamp($"Date Range: {StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}");

            if (!string.IsNullOrEmpty(UserIds))
            {
                WriteVerboseWithTimestamp($"User Filter: {UserIds}");
            }

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

            var allResults = new List<PSObject>();
            var operationResults = new Dictionary<string, List<PSObject>>();
            var summary = new UALOperationsSummary
            {
                StartTime = DateTime.UtcNow,
                Operations = Operations.ToList(),
                DateRange = $"{StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}"
            };

            var processedOperations = 0;
            foreach (var operation in Operations)
            {
                WriteVerboseWithTimestamp($"Searching for operation: {operation}");

                try
                {
                    var results = await SearchOperationAsync(operation, cancellationToken);

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
                    WriteWarningWithTimestamp($"Error searching for {operation}: {ex.Message}");
                    summary.OperationCounts[operation] = -1; // Indicate error
                }

                processedOperations++;
                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = $"Processing operations",
                    ItemsProcessed = processedOperations,
                    TotalItems = Operations.Length,
                    PercentComplete = (processedOperations * 100) / Operations.Length
                });
            }

            summary.TotalEvents = allResults.Count;
            summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

            // Export results
            if (allResults.Any())
            {
                await ExportResultsAsync(operationResults, cancellationToken);
            }

            // Write summary
            WriteSummary(summary);

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
                ps.AddParameter("StartDate", StartDate);
                ps.AddParameter("EndDate", EndDate);
                ps.AddParameter("ResultSize", MaxResults);
                ps.AddParameter("SessionCommand", "ReturnLargeSet");

                if (!string.IsNullOrEmpty(UserIds))
                {
                    ps.AddParameter("UserIds", UserIds);
                }

                try
                {
                    var searchResults = await Task.Run(() => ps.Invoke(), cancellationToken);

                    if (ps.HadErrors)
                    {
                        foreach (var error in ps.Streams.Error)
                        {
                            WriteWarningWithTimestamp($"Search error: {error}");
                        }
                    }

                    foreach (var result in searchResults)
                    {
                        // Extract and process the audit data
                        var processedResult = ProcessAuditLogEntry(result, operation);
                        if (processedResult != null)
                        {
                            results.Add(processedResult);
                        }
                    }
                }
                catch (Exception ex)
                {
                    WriteErrorWithTimestamp($"Failed to search for operation {operation}", ex);
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

                var fileName = Path.Combine(OutputDirectory, $"{timestamp}-{operation}.{OutputFormat.ToLower()}");

                WriteVerboseWithTimestamp($"Exporting {results.Count} results for {kvp.Key} to {fileName}");

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
            }

            // Create a summary file
            var summaryFile = Path.Combine(OutputDirectory, $"{timestamp}-Summary.txt");
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

            foreach (var kvp in operationResults.OrderByDescending(x => x.Value.Count))
            {
                summaryContent.Add($"  {kvp.Key}: {kvp.Value.Count} events");
            }

            using (var writer = new StreamWriter(summaryFile)) { foreach (var line in summaryContent) await writer.WriteLineAsync(line); }
        }

        private void WriteSummary(UALOperationsSummary summary)
        {
            WriteHost("");
            WriteHost("=== Quick UAL Operations Summary ===", ConsoleColor.Cyan);
            WriteHost($"Date Range: {summary.DateRange}");
            WriteHost($"Total Events Found: {summary.TotalEvents}");
            WriteHost("");
            WriteHost("Events by Operation:");

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

                WriteHost($"  {op.Key}: {status}", color);
            }

            WriteHost("");
            WriteHost($"Processing Time: {summary.ProcessingTime:mm\\:ss}", ConsoleColor.Green);
            WriteHost("=====================================", ConsoleColor.Cyan);
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

    internal class UALOperationsSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public List<string> Operations { get; set; } = new();
        public Dictionary<string, int> OperationCounts { get; set; } = new();
        public int TotalEvents { get; set; }
        public string DateRange { get; set; } = string.Empty;
    }
}
