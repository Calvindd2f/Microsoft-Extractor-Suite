using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Exchange;

namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
    /// <summary>
    /// Cmdlet to retrieve mailbox audit log entries for security investigations
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "MailboxAuditLog")]
    [OutputType(typeof(MailboxAuditLogResult))]
    public class GetMailboxAuditLogCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve mailbox audit log entries from. Use '*' for all users")]
        public string UserIds { get; set; } = "*";

        [Parameter(
            HelpMessage = "Start date for the search range")]
        public DateTime? StartDate { get; set; }

        [Parameter(
            HelpMessage = "End date for the search range")]
        public DateTime? EndDate { get; set; }

        [Parameter(
            HelpMessage = "Interval in minutes for UAL processing")]
        public decimal Interval { get; set; } = 1440;

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
        public string OutputDir { get; set; } = "Output\\MailboxAuditLog";

        [Parameter(
            HelpMessage = "Output format: CSV, JSON, or SOF-ELK")]
        [ValidateSet("CSV", "JSON", "SOF-ELK")]
        public string Output { get; set; } = "CSV";

        [Parameter(
            HelpMessage = "Merge output files into single files")]
        public SwitchParameter MergeOutput { get; set; }

        [Parameter(
            HelpMessage = "File encoding for output files")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(
            HelpMessage = "Use legacy Search-MailboxAuditLog method instead of UAL")]
        public SwitchParameter UseLegacyMethod { get; set; }

        private readonly ExchangeRestClient _exchangeClient;

        public GetMailboxAuditLogCmdlet()
        {
            _exchangeClient = new ExchangeRestClient();
        }

        protected override async Task ProcessRecordAsync()
        {
            WriteVerbose("=== Starting Mailbox Audit Log Collection ===");

            // Check for authentication
            if (!await _exchangeClient.IsConnectedAsync())
            {
                WriteErrorWithTimestamp("Not connected to Exchange Online. Please run Connect-M365 first.");
                return;
            }

            // Create timestamped output directory
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            var outputDirectory = GetOutputDirectory(timestamp);

            if (UseLegacyMethod)
            {
                await ProcessLegacyMethodAsync(outputDirectory);
            }
            else
            {
                await ProcessUALMethodAsync(outputDirectory);
            }
        }

        private async Task ProcessUALMethodAsync(string outputDirectory)
        {
            WriteVerbose("== Starting the Mailbox Audit Log Collection (utilizing Get-UAL) ==");

            var ualParams = new Dictionary<string, object>
            {
                ["RecordType"] = "ExchangeItem",
                ["UserIds"] = UserIds,
                ["Output"] = Output,
                ["OutputDir"] = outputDirectory,
                ["Encoding"] = Encoding,
                ["Interval"] = Interval
            };

            // Add optional parameters if provided
            if (StartDate.HasValue)
                ualParams["StartDate"] = StartDate.Value;

            if (EndDate.HasValue)
                ualParams["EndDate"] = EndDate.Value;

            if (MergeOutput)
                ualParams["MergeOutput"] = MergeOutput.IsPresent;

            try
            {
                // Call the UAL collection method
                await CallGetUALAsync(ualParams);

                WriteVerbose($"Mailbox audit log collection completed successfully.");
                WriteVerbose($"Results saved to: {outputDirectory}");
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Failed to collect mailbox audit logs: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessLegacyMethodAsync(string outputDirectory)
        {
            WriteVerbose("== Starting Mailbox Audit Log Collection (Legacy Method) ==");

            var summary = new MailboxAuditLogSummary
            {
                StartTime = DateTime.Now,
                ProcessedMailboxes = 0,
                TotalRecords = 0,
                OutputDirectory = outputDirectory
            };

            try
            {
                // Test connection with a simple command
                await TestConnectionAsync();

                var startDate = StartDate ?? DateTime.Now.AddDays(-90);
                var endDate = EndDate ?? DateTime.Now;

                WriteVerbose($"Date range: {startDate:yyyy-MM-dd} to {endDate:yyyy-MM-dd}");

                if (string.IsNullOrEmpty(UserIds) || UserIds == "*")
                {
                    WriteVerbose("No specific users provided. Getting the MailboxAuditLog for all users");
                    await ProcessAllMailboxesAsync(outputDirectory, startDate, endDate, summary);
                }
                else if (UserIds.Contains(","))
                {
                    var userList = UserIds.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var user in userList)
                    {
                        var trimmedUser = user.Trim();
                        await ProcessSingleMailboxAsync(outputDirectory, trimmedUser, startDate, endDate, summary);
                    }
                }
                else
                {
                    await ProcessSingleMailboxAsync(outputDirectory, UserIds, startDate, endDate, summary);
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
                LogSummary(summary);
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during mailbox audit log collection: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessAllMailboxesAsync(string outputDirectory, DateTime startDate, DateTime endDate, MailboxAuditLogSummary summary)
        {
            var mailboxes = await _exchangeClient.GetMailboxesAsync(unlimited: true);

            WriteVerbose($"Found {mailboxes.Count} mailboxes to process");

            foreach (var mailbox in mailboxes)
            {
                try
                {
                    await ProcessMailboxAuditLog(outputDirectory, mailbox.UserPrincipalName, startDate, endDate, summary);
                    summary.ProcessedMailboxes++;
                }
                catch (Exception ex)
                {
                    WriteWarningWithTimestamp($"Failed to process mailbox {mailbox.UserPrincipalName}: {ex.Message}");
                }

                // Progress reporting
                if (summary.ProcessedMailboxes % 10 == 0)
                {
                    WriteVerbose($"Processed {summary.ProcessedMailboxes}/{mailboxes.Count} mailboxes");
                }
            }
        }

        private async Task ProcessSingleMailboxAsync(string outputDirectory, string userPrincipalName, DateTime startDate, DateTime endDate, MailboxAuditLogSummary summary)
        {
            WriteVerbose($"Collecting the MailboxAuditLog for {userPrincipalName}");

            try
            {
                await ProcessMailboxAuditLog(outputDirectory, userPrincipalName, startDate, endDate, summary);
                summary.ProcessedMailboxes++;
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Failed to process mailbox {userPrincipalName}: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessMailboxAuditLog(string outputDirectory, string userPrincipalName, DateTime startDate, DateTime endDate, MailboxAuditLogSummary summary)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmm");
            var outputFile = Path.Combine(outputDirectory, $"{timestamp}-mailboxAuditLog-{userPrincipalName}.csv");

            var searchParams = new Dictionary<string, object>
            {
                ["Identity"] = userPrincipalName,
                ["LogonTypes"] = new[] { "Delegate", "Admin", "Owner" },
                ["StartDate"] = startDate,
                ["EndDate"] = endDate,
                ["ShowDetails"] = true,
                ["ResultSize"] = 250000
            };

            try
            {
                var results = await _exchangeClient.SearchMailboxAuditLogAsync(searchParams);

                if (results != null && results.Count > 0)
                {
                    await WriteResultsToFileAsync(results, outputFile);
                    summary.TotalRecords += results.Count;

                    WriteVerbose($"Output written to: {outputFile} ({results.Count} records)");
                }
                else
                {
                    WriteVerbose($"No audit log entries found for {userPrincipalName}");
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Error retrieving audit logs for {userPrincipalName}: {ex.Message}");
                throw;
            }
        }

        private async Task TestConnectionAsync()
        {
            try
            {
                // Test with a simple search command
                var testParams = new Dictionary<string, object>
                {
                    ["ResultSize"] = 1
                };

                await _exchangeClient.SearchMailboxAuditLogAsync(testParams);
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp("Connection test failed. Ensure you are connected to M365 by running the Connect-M365 command.");
                throw new InvalidOperationException("Exchange Online connection required", ex);
            }
        }

        private async Task CallGetUALAsync(Dictionary<string, object> parameters)
        {
            // This would call the existing Get-UAL cmdlet functionality
            // For now, we'll simulate the call with a placeholder
            WriteVerbose("Calling Get-UAL with ExchangeItem record type...");

            try
            {
                var searchParams = new Dictionary<string, object>
                {
                    ["StartDate"] = parameters.ContainsKey("StartDate") ? parameters["StartDate"] : DateTime.Now.AddDays(-90),
                    ["EndDate"] = parameters.ContainsKey("EndDate") ? parameters["EndDate"] : DateTime.Now,
                    ["RecordType"] = "ExchangeItem",
                    ["UserIds"] = parameters["UserIds"],
                    ["ResultSize"] = 5000
                };

                if (UserIds != "*")
                {
                    searchParams["UserIds"] = UserIds;
                }

                var records = await _exchangeClient.SearchUnifiedAuditLogAsync(searchParams);

                if (records != null && records.Count > 0)
                {
                    var outputPath = Path.Combine((string)parameters["OutputDir"],
                        $"{DateTime.Now:yyyyMMddHHmmss}-ExchangeItem-UAL.{Output.ToLower()}");

                    await WriteResultsToFileAsync(records, outputPath);
                    WriteVerbose($"UAL records written to: {outputPath} ({records.Count} records)");
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Failed to execute UAL collection: {ex.Message}");
                throw;
            }
        }

        private string GetOutputDirectory(string timestamp)
        {
            var directory = OutputDir;

            if (OutputDir == "Output\\MailboxAuditLog")
            {
                directory = Path.Combine(OutputDir, timestamp);
            }

            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
                WriteVerbose($"Created output directory: {directory}");
            }

            return directory;
        }

        private void LogSummary(MailboxAuditLogSummary summary)
        {
            WriteVerbose("");
            WriteVerbose("=== Mailbox Audit Log Collection Summary ===");
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
            WriteVerbose($"Mailboxes Processed: {summary.ProcessedMailboxes:N0}");
            WriteVerbose($"Total Records: {summary.TotalRecords:N0}");
            WriteVerbose($"Output Directory: {summary.OutputDirectory}");
            WriteVerbose("============================================");
        }

        private async Task WriteResultsToFileAsync<T>(IEnumerable<T> results, string filePath)
        {
            try
            {
                var directory = Path.GetDirectoryName(filePath);
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Write results based on the output format
                switch (Output.ToUpperInvariant())
                {
                    case "JSON":
                        await WriteJsonAsync(results, filePath);
                        break;
                    case "SOF-ELK":
                        await WriteSofElkAsync(results, filePath);
                        break;
                    default: // CSV
                        await WriteCsvAsync(results, filePath);
                        break;
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Failed to write results to file {filePath}: {ex.Message}");
                throw;
            }
        }

        private async Task WriteCsvAsync<T>(IEnumerable<T> results, string filePath)
        {
            // Implement CSV writing logic
            var csv = ConvertToCsv(results);
            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteJsonAsync<T>(IEnumerable<T> results, string filePath)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(results, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });
            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(json); }
        }

        private async Task WriteSofElkAsync<T>(IEnumerable<T> results, string filePath)
        {
            // SOF-ELK format - one JSON object per line
            var lines = new List<string>();
            foreach (var result in results)
            {
                var json = System.Text.Json.JsonSerializer.Serialize(result);
                lines.Add(json);
            }
            using (var writer = new StreamWriter(filePath)) { foreach (var line in lines) await writer.WriteLineAsync(line); }
        }

        private string ConvertToCsv<T>(IEnumerable<T> results)
        {
            // Simple CSV conversion - in practice, you'd want a more robust implementation
            var properties = typeof(T).GetProperties();
            var csv = string.Join(",", properties.Select(p => p.Name)) + Environment.NewLine;

            foreach (var item in results)
            {
                var values = properties.Select(p =>
                {
                    var value = p.GetValue(item)?.ToString() ?? "";
                    return value.Contains(",") ? $"\"{value}\"" : value;
                });
                csv += string.Join(",", values) + Environment.NewLine;
            }

            return csv;
        }
    }

    public class MailboxAuditLogResult
    {
        public List<MailboxAuditEntry> Entries { get; set; } = new List<MailboxAuditEntry>();
        public MailboxAuditLogSummary Summary { get; set; }
    }

    public class MailboxAuditEntry
    {
        public DateTime CreationTime { get; set; }
        public string UserId { get; set; }
        public string Operation { get; set; }
        public string AuditData { get; set; }
        public string ResultIndex { get; set; }
        public int ResultCount { get; set; }
        public string Identity { get; set; }
        public bool IsValid { get; set; }
        public string ObjectState { get; set; }
    }

    public class MailboxAuditLogSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public int ProcessedMailboxes { get; set; }
        public int TotalRecords { get; set; }
        public string OutputDirectory { get; set; }
    }
}