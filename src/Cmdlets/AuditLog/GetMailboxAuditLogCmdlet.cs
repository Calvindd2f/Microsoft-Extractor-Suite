namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Exchange;


    /// <summary>
    /// Cmdlet to retrieve mailbox audit log entries for security investigations
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "MailboxAuditLog")]
    [OutputType(typeof(MailboxAuditLogResult))]
    public class GetMailboxAuditLogCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve mailbox audit log entries from. Use '*' for all users")]
#pragma warning disable SA1600
        public string UserIds { get; set; } = "*";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Start date for the search range")]
#pragma warning disable SA1600
        public DateTime? StartDate { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "End date for the search range")]
#pragma warning disable SA1600
        public DateTime? EndDate { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Interval in minutes for UAL processing")]
#pragma warning disable SA1600
        public decimal Interval { get; set; } = 1440;
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
#pragma warning disable SA1600
        public string OutputDir { get; set; } = "Output\\MailboxAuditLog";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output format: CSV, JSON, or SOF-ELK")]
        [ValidateSet("CSV", "JSON", "SOF-ELK")]
#pragma warning disable SA1600
        public string Output { get; set; } = "CSV";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Merge output files into single files")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter MergeOutput { get; set; }

        [Parameter(
            HelpMessage = "File encoding for output files")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Use legacy Search-MailboxAuditLog method instead of UAL")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1309
        public SwitchParameter UseLegacyMethod { get; set; }
#pragma warning disable SA1201
        private ExchangeRestClient? _exchangeClient;
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning restore SA1309
sho

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
#pragma warning disable SA1101
            _exchangeClient = new ExchangeRestClient(AuthManager);
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected override async Task ProcessRecordAsync()
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting Mailbox Audit Log Collection ===");
#pragma warning restore SA1101

            // Check for authentication
#pragma warning disable SA1101
            if (_exchangeClient == null || !await _exchangeClient.IsConnectedAsync())
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp("Not connected to Exchange Online. Please run Connect-M365 first.");
#pragma warning restore SA1101
                return;
            }
#pragma warning restore SA1101

            // Create timestamped output directory
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
#pragma warning disable SA1101
            var outputDirectory = GetOutputDirectory(timestamp);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (UseLegacyMethod)
            {
#pragma warning disable SA1101
                await ProcessLegacyMethodAsync(outputDirectory);
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                await ProcessUALMethodAsync(outputDirectory);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        private async Task ProcessUALMethodAsync(string outputDirectory)
        {
#pragma warning disable SA1101
            WriteVerbose("== Starting the Mailbox Audit Log Collection (utilizing Get-UAL) ==");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var ualParams = new Dictionary<string, object>
            {
                ["RecordType"] = "ExchangeItem",
                ["UserIds"] = UserIds,
                ["Output"] = Output,
                ["OutputDir"] = outputDirectory,
                ["Encoding"] = Encoding,
                ["Interval"] = Interval
            };
#pragma warning restore SA1101

            // Add optional parameters if provided
#pragma warning disable SA1101
            if (StartDate.HasValue)
#pragma warning disable SA1101
                ualParams["StartDate"] = StartDate.Value;
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (EndDate.HasValue)
#pragma warning disable SA1101
                ualParams["EndDate"] = EndDate.Value;
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (MergeOutput)
#pragma warning disable SA1101
                ualParams["MergeOutput"] = MergeOutput.IsPresent;
#pragma warning restore SA1101

            try
            {
                // Call the UAL collection method
#pragma warning disable SA1101
                await CallGetUALAsync(ualParams);
#pragma warning restore SA1101

#pragma warning disable SA1101
                WriteVerbose($"Mailbox audit log collection completed successfully.");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"Results saved to: {outputDirectory}");
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to collect mailbox audit logs: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task ProcessLegacyMethodAsync(string outputDirectory)
        {
#pragma warning disable SA1101
            WriteVerbose("== Starting Mailbox Audit Log Collection (Legacy Method) ==");
#pragma warning restore SA1101

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
#pragma warning disable SA1101
                await TestConnectionAsync();
#pragma warning restore SA1101

#pragma warning disable SA1101
                var startDate = StartDate ?? DateTime.Now.AddDays(-90);
#pragma warning restore SA1101
#pragma warning disable SA1101
                var endDate = EndDate ?? DateTime.Now;
#pragma warning restore SA1101

#pragma warning disable SA1101
                WriteVerbose($"Date range: {startDate:yyyy-MM-dd} to {endDate:yyyy-MM-dd}");
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (string.IsNullOrEmpty(UserIds) || UserIds == "*")
                {
#pragma warning disable SA1101
                    WriteVerbose("No specific users provided. Getting the MailboxAuditLog for all users");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    await ProcessAllMailboxesAsync(outputDirectory, startDate, endDate, summary);
#pragma warning restore SA1101
                }
                else if (UserIds.Contains(","))
                {
#pragma warning disable SA1101
                    var userList = UserIds.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
#pragma warning restore SA1101
                    foreach (var user in userList)
                    {
                        var trimmedUser = user.Trim();
#pragma warning disable SA1101
                        await ProcessSingleMailboxAsync(outputDirectory, trimmedUser, startDate, endDate, summary);
#pragma warning restore SA1101
                    }
                }
                else
                {
#pragma warning disable SA1101
                    await ProcessSingleMailboxAsync(outputDirectory, UserIds, startDate, endDate, summary);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
#pragma warning disable SA1101
                LogSummary(summary);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during mailbox audit log collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task ProcessAllMailboxesAsync(string outputDirectory, DateTime startDate, DateTime endDate, MailboxAuditLogSummary summary)
        {
#pragma warning disable SA1101
            var mailboxUsers = await _exchangeClient!.GetMailboxesAsync();
#pragma warning restore SA1101
            var mailboxes = mailboxUsers.Select(u => new { UserPrincipalName = u }).ToList();

#pragma warning disable SA1101
            WriteVerbose($"Found {mailboxes.Count} mailboxes to process");
#pragma warning restore SA1101

            foreach (var mailbox in mailboxes)
            {
                try
                {
#pragma warning disable SA1101
                    await ProcessMailboxAuditLog(outputDirectory, mailbox.UserPrincipalName, startDate, endDate, summary);
#pragma warning restore SA1101
                    summary.ProcessedMailboxes++;
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Failed to process mailbox {mailbox.UserPrincipalName}: {ex.Message}");
#pragma warning restore SA1101
                }

                // Progress reporting
                if (summary.ProcessedMailboxes % 10 == 0)
                {
#pragma warning disable SA1101
                    WriteVerbose($"Processed {summary.ProcessedMailboxes}/{mailboxes.Count} mailboxes");
#pragma warning restore SA1101
                }
            }
        }

        private async Task ProcessSingleMailboxAsync(string outputDirectory, string userPrincipalName, DateTime startDate, DateTime endDate, MailboxAuditLogSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose($"Collecting the MailboxAuditLog for {userPrincipalName}");
#pragma warning restore SA1101

            try
            {
#pragma warning disable SA1101
                await ProcessMailboxAuditLog(outputDirectory, userPrincipalName, startDate, endDate, summary);
#pragma warning restore SA1101
                summary.ProcessedMailboxes++;
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to process mailbox {userPrincipalName}: {ex.Message}");
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                var resultsEnumerable = _exchangeClient!.SearchMailboxAuditLogAsync(userPrincipalName, startDate, endDate);
#pragma warning restore SA1101
                var results = new List<object>();
                await foreach (var result in resultsEnumerable)
                {
                    results.Add(result);
                }

                if (results != null && results.Count > 0)
                {
#pragma warning disable SA1101
                    await WriteResultsToFileAsync(results, outputFile);
#pragma warning restore SA1101
                    summary.TotalRecords += results.Count;

#pragma warning disable SA1101
                    WriteVerbose($"Output written to: {outputFile} ({results.Count} records)");
#pragma warning restore SA1101
                }
                else
                {
#pragma warning disable SA1101
                    WriteVerbose($"No audit log entries found for {userPrincipalName}");
#pragma warning restore SA1101
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Error retrieving audit logs for {userPrincipalName}: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task TestConnectionAsync()
        {
            try
            {
                // Test with a simple search command - get current user
                var testUser = "test@example.com"; // This should be replaced with actual logic to get a test user
                var testStartDate = DateTime.Now.AddDays(-1);
                var testEndDate = DateTime.Now;

                // Just try to enumerate one item to test connection
#pragma warning disable SA1101
                await foreach (var _ in _exchangeClient!.SearchMailboxAuditLogAsync(testUser, testStartDate, testEndDate))
                {
                    break; // Exit after first item to just test connection
                }
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp("Connection test failed. Ensure you are connected to M365 by running the Connect-M365 command.");
#pragma warning restore SA1101
                throw new InvalidOperationException("Exchange Online connection required", ex);
            }
        }

        private async Task CallGetUALAsync(Dictionary<string, object> parameters)
        {
            // This would call the existing Get-UAL cmdlet functionality
            // For now, we'll simulate the call with a placeholder
#pragma warning disable SA1101
            WriteVerbose("Calling Get-UAL with ExchangeItem record type...");
#pragma warning restore SA1101

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

#pragma warning disable SA1101
                if (UserIds != "*")
                {
#pragma warning disable SA1101
                    searchParams["UserIds"] = UserIds;
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                var startDate = parameters.ContainsKey("StartDate") ? (DateTime)parameters["StartDate"] : DateTime.Now.AddDays(-90);
                var endDate = parameters.ContainsKey("EndDate") ? (DateTime)parameters["EndDate"] : DateTime.Now;

#pragma warning disable SA1101
                var recordsResult = await _exchangeClient!.SearchUnifiedAuditLogAsync(startDate, endDate);
#pragma warning restore SA1101
                var records = new List<object>();
                if (recordsResult?.Value != null)
                {
                    foreach (var record in recordsResult.Value)
                    {
                        records.Add(record);
                    }
                }

                if (records != null && records.Count > 0)
                {
#pragma warning disable SA1101
                    var outputPath = Path.Combine((string)parameters["OutputDir"],
                        $"{DateTime.Now:yyyyMMddHHmmss}-ExchangeItem-UAL.{Output.ToLower()}");
#pragma warning restore SA1101

#pragma warning disable SA1101
                    await WriteResultsToFileAsync(records, outputPath);
#pragma warning restore SA1101
#pragma warning disable SA1101
                    WriteVerbose($"UAL records written to: {outputPath} ({records.Count} records)");
#pragma warning restore SA1101
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to execute UAL collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private string GetOutputDirectory(string timestamp)
        {
#pragma warning disable SA1101
            var directory = OutputDir;
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (OutputDir == "Output\\MailboxAuditLog")
            {
#pragma warning disable SA1101
                directory = Path.Combine(OutputDir, timestamp);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
#pragma warning disable SA1101
                WriteVerbose($"Created output directory: {directory}");
#pragma warning restore SA1101
            }

            return directory;
        }

        private void LogSummary(MailboxAuditLogSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("=== Mailbox Audit Log Collection Summary ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Mailboxes Processed: {summary.ProcessedMailboxes:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Total Records: {summary.TotalRecords:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Output Directory: {summary.OutputDirectory}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("============================================");
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                switch (Output.ToUpperInvariant())
                {
                    case "JSON":
#pragma warning disable SA1101
                        await WriteJsonAsync(results, filePath);
#pragma warning restore SA1101
                        break;
                    case "SOF-ELK":
#pragma warning disable SA1101
                        await WriteSofElkAsync(results, filePath);
#pragma warning restore SA1101
                        break;
                    default: // CSV
#pragma warning disable SA1101
                        await WriteCsvAsync(results, filePath);
#pragma warning restore SA1101
                        break;
                }
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to write results to file {filePath}: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task WriteCsvAsync<T>(IEnumerable<T> results, string filePath)
        {
            // Implement CSV writing logic
#pragma warning disable SA1101
            var csv = ConvertToCsv(results);
#pragma warning restore SA1101
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
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class MailboxAuditLogResult
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
        public List<MailboxAuditEntry> Entries { get; set; } = new List<MailboxAuditEntry>();
#pragma warning disable SA1600
        public MailboxAuditLogSummary Summary { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class MailboxAuditEntry
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime CreationTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Operation { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string AuditData { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ResultIndex { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int ResultCount { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Identity { get; set; }
        public bool IsValid { get; set; }public string ObjectState { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class MailboxAuditLogSummary
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get
#pragma warning restore SA1600
set; }
#pragma warning disable SA1600
#pragma warning restore SA1600
        public int ProcessedMailboxes { get; set; }
        public int TotalRecords { get; set; }public string OutputDirectory { get; set; }}
}
