namespace Microsoft.ExtractorSuite.Cmdlets.Mail
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Exchange;
    using Microsoft.ExtractorSuite.Models.Exchange;


    /// <summary>
    /// Cmdlet to collect message trace logs for email flow analysis
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "MessageTraceLog")]
    [OutputType(typeof(MessageTraceLogResult))]
    public class GetMessageTraceLogCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve message trace logs for")]
#pragma warning disable SA1600
        public string[] UserIds { get; set; }
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
            HelpMessage = "Sender email address to filter by")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public string SenderAddress { get; set; }

        [Parameter(
            HelpMessage = "Recipient email address to filter by")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public string RecipientAddress { get; set; }

        [Parameter(
            HelpMessage = "Message subject to filter by")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public string MessageSubject { get; set; }

        [Parameter(
            HelpMessage = "Message ID to search for")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public string MessageId { get; set; }

        [Parameter(
            HelpMessage = "Status to filter by (None, GettingStatus, Failed, Pending, Delivered, Expanded, Quarantined, FilteredAsSpam)")]
        [ValidateSet("None", "GettingStatus", "Failed", "Pending", "Delivered", "Expanded", "Quarantined", "FilteredAsSpam")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public string Status { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
#pragma warning disable SA1600
        public string OutputDir { get; set; } = "Output\\MessageTraceLog";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "File encoding for output files")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Use historical message trace (for data older than 10 days)")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter UseHistoricalTrace { get; set; }

        [Parameter(
            HelpMessage = "Page size for results (1-5000)")]
        [ValidateRange(1, 5000)]
#pragma warning disable SA1600
        public int PageSize { get; set; } = 5000;
#pragma warning restore SA1600

#pragma warning disable SA1309
#pragma warning disable SA1201
        private readonly ExchangeRestClient _exchangeClient;
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning restore SA1309
n

        public GetMessageTraceLogCmdlet()
        {
#pragma warning disable SA1101
            _exchangeClient = new ExchangeRestClient(AuthManager);
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected override async Task ProcessRecordAsync()
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting Message Trace Log Collection ===");
#pragma warning restore SA1101

            // Check for authentication
#pragma warning disable SA1101
            if (!await _exchangeClient.IsConnectedAsync())
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp("Not connected to Exchange Online. Please run Connect-M365 first.");
#pragma warning restore SA1101
                return;
            }
#pragma warning restore SA1101

            // Validate date range
#pragma warning disable SA1101
            var startDate = StartDate ?? DateTime.Now.AddDays(-7);
#pragma warning restore SA1101
#pragma warning disable SA1101
            var endDate = EndDate ?? DateTime.Now;
#pragma warning restore SA1101

            if (startDate >= endDate)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp("StartDate must be before EndDate");
#pragma warning restore SA1101
                return;
            }

            var daysDifference = (DateTime.Now - startDate).Days;
#pragma warning disable SA1101
            var useHistorical = UseHistoricalTrace || daysDifference > 10;
#pragma warning restore SA1101

            if (daysDifference > 90)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp("Message trace logs are only available for the past 90 days");
#pragma warning restore SA1101
                return;
            }

            // Create output directory
#pragma warning disable SA1101
            var outputDirectory = GetOutputDirectory();
#pragma warning restore SA1101
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmm");

            var summary = new MessageTraceLogSummary
            {
                StartTime = DateTime.Now,
                SearchStartDate = startDate,
                SearchEndDate = endDate,
                UseHistoricalTrace = useHistorical,
                TotalMessages = 0,
                StatusBreakdown = new Dictionary<string, int>()
            };

#pragma warning disable SA1101
            WriteVerbose($"Date range: {startDate:yyyy-MM-dd} to {endDate:yyyy-MM-dd}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Using {(useHistorical ? "historical" : "standard")} message trace");
#pragma warning restore SA1101

            try
            {
#pragma warning disable SA1101
                var searchParameters = BuildSearchParameters(startDate, endDate);
#pragma warning restore SA1101
                var messages = new List<MessageTraceEntry>();

                if (useHistorical)
                {
#pragma warning disable SA1101
                    messages = await GetHistoricalMessageTraceAsync(searchParameters, summary);
#pragma warning restore SA1101
                }
                else
                {
#pragma warning disable SA1101
                    messages = await GetStandardMessageTraceAsync(searchParameters, summary);
#pragma warning restore SA1101
                }

                if (messages.Count > 0)
                {
                    var outputFile = Path.Combine(outputDirectory, $"{timestamp}-MessageTrace.csv");
#pragma warning disable SA1101
                    await WriteResultsToFileAsync(messages, outputFile);
#pragma warning restore SA1101

#pragma warning disable SA1101
                    WriteVerbose($"Message trace results written to: {outputFile}");
#pragma warning restore SA1101
                    summary.OutputFile = outputFile;
                }
                else
                {
#pragma warning disable SA1101
                    WriteVerbose("No message trace entries found matching the specified criteria.");
#pragma warning restore SA1101
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
#pragma warning disable SA1101
                LogSummary(summary);
#pragma warning restore SA1101

                var result = new MessageTraceLogResult
                {
                    Messages = messages,
                    Summary = summary
                };

#pragma warning disable SA1101
                WriteObject(result);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during message trace collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private Dictionary<string, object> BuildSearchParameters(DateTime startDate, DateTime endDate)
        {
#pragma warning disable SA1101
            var parameters = new Dictionary<string, object>
            {
                ["StartDate"] = startDate,
                ["EndDate"] = endDate,
                ["PageSize"] = PageSize
            };
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (UserIds != null && UserIds.Length > 0)
            {
#pragma warning disable SA1101
                if (UserIds.Length == 1)
                {
                    // Check if it's a sender or recipient
#pragma warning disable SA1101
                    if (!string.IsNullOrEmpty(SenderAddress) || !string.IsNullOrEmpty(RecipientAddress))
                    {
#pragma warning disable SA1101
                        if (!string.IsNullOrEmpty(SenderAddress))
#pragma warning disable SA1101
                            parameters["SenderAddress"] = SenderAddress;
#pragma warning restore SA1101
#pragma warning disable SA1101
                        if (!string.IsNullOrEmpty(RecipientAddress))
#pragma warning disable SA1101
                            parameters["RecipientAddress"] = RecipientAddress;
#pragma warning restore SA1101
                    }
                    else
                    {
                        // Default to recipient if not specified
#pragma warning disable SA1101
                        parameters["RecipientAddress"] = UserIds[0];
#pragma warning restore SA1101
                    }
#pragma warning restore SA1101
                }
                else
                {
                    // Multiple users - process them individually
#pragma warning disable SA1101
                    WriteVerbose($"Processing {UserIds.Length} users individually");
#pragma warning restore SA1101
                }
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(SenderAddress))
#pragma warning disable SA1101
                parameters["SenderAddress"] = SenderAddress;
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(RecipientAddress))
#pragma warning disable SA1101
                parameters["RecipientAddress"] = RecipientAddress;
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(MessageSubject))
#pragma warning disable SA1101
                parameters["MessageSubject"] = MessageSubject;
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(MessageId))
#pragma warning disable SA1101
                parameters["MessageId"] = MessageId;
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(Status) && Status != "None")
#pragma warning disable SA1101
                parameters["Status"] = Status;
#pragma warning restore SA1101

            return parameters;
        }

        private async Task<List<MessageTraceEntry>> GetStandardMessageTraceAsync(Dictionary<string, object> searchParameters, MessageTraceLogSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Executing standard message trace...");
#pragma warning restore SA1101

            var messages = new List<MessageTraceEntry>();

#pragma warning disable SA1101
            if (UserIds != null && UserIds.Length > 1)
            {
                // Process each user individually
#pragma warning disable SA1101
                foreach (var userId in UserIds)
                {
                    var userParameters = new Dictionary<string, object>(searchParameters)
                    {
                        ["RecipientAddress"] = userId
                    };

                    try
                    {
#pragma warning disable SA1101
                        WriteVerbose($"Processing message trace for: {userId}");
#pragma warning restore SA1101
                        var startDate = (DateTime)userParameters["StartDate"];
                        var endDate = (DateTime)userParameters["EndDate"];

                        var userMessageTraces = new List<MessageTrace>();
#pragma warning disable SA1101
                        await foreach (var result in _exchangeClient.GetMessageTraceAsync(startDate, endDate,
                            userParameters.ContainsKey("SenderAddress") ? userParameters["SenderAddress"]?.ToString() : null,
                            userParameters.ContainsKey("RecipientAddress") ? userParameters["RecipientAddress"]?.ToString() : null,
                            userParameters.ContainsKey("MessageId") ? userParameters["MessageId"]?.ToString() : null))
                        {
                            if (result.Value != null)
                                userMessageTraces.AddRange(result.Value);
                        }
#pragma warning restore SA1101
#pragma warning disable SA1101
                        messages.AddRange(ProcessMessageTraceResults(userMessageTraces, summary));
#pragma warning restore SA1101
                    }
                    catch (Exception ex)
                    {
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"Failed to get message trace for {userId}: {ex.Message}");
#pragma warning restore SA1101
                    }
                }
#pragma warning restore SA1101
            }
            else
            {
                // Single query
                var startDate = (DateTime)searchParameters["StartDate"];
                var endDate = (DateTime)searchParameters["EndDate"];

                var messageTraces = new List<MessageTrace>();
#pragma warning disable SA1101
                await foreach (var result in _exchangeClient.GetMessageTraceAsync(startDate, endDate,
                    searchParameters.ContainsKey("SenderAddress") ? searchParameters["SenderAddress"]?.ToString() : null,
                    searchParameters.ContainsKey("RecipientAddress") ? searchParameters["RecipientAddress"]?.ToString() : null,
                    searchParameters.ContainsKey("MessageId") ? searchParameters["MessageId"]?.ToString() : null))
                {
                    if (result.Value != null)
                        messageTraces.AddRange(result.Value);
                }
#pragma warning restore SA1101
#pragma warning disable SA1101
                messages.AddRange(ProcessMessageTraceResults(messageTraces, summary));
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            return messages;
        }

        private async Task<List<MessageTraceEntry>> GetHistoricalMessageTraceAsync(Dictionary<string, object> searchParameters, MessageTraceLogSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Executing historical message trace...");
#pragma warning restore SA1101

            var messages = new List<MessageTraceEntry>();

#pragma warning disable SA1101
            if (UserIds != null && UserIds.Length > 1)
            {
                // Process each user individually
#pragma warning disable SA1101
                foreach (var userId in UserIds)
                {
                    var userParameters = new Dictionary<string, object>(searchParameters)
                    {
                        ["RecipientAddress"] = userId
                    };

                    try
                    {
#pragma warning disable SA1101
                        WriteVerbose($"Processing historical message trace for: {userId}");
#pragma warning restore SA1101
                        var startDate = (DateTime)userParameters["StartDate"];
                        var endDate = (DateTime)userParameters["EndDate"];

                        var userMessageTraces = new List<MessageTrace>();
#pragma warning disable SA1101
                        await foreach (var result in _exchangeClient.GetMessageTraceAsync(startDate, endDate,
                            userParameters.ContainsKey("SenderAddress") ? userParameters["SenderAddress"]?.ToString() : null,
                            userParameters.ContainsKey("RecipientAddress") ? userParameters["RecipientAddress"]?.ToString() : null,
                            userParameters.ContainsKey("MessageId") ? userParameters["MessageId"]?.ToString() : null))
                        {
                            if (result.Value != null)
                                userMessageTraces.AddRange(result.Value);
                        }
#pragma warning restore SA1101
#pragma warning disable SA1101
                        messages.AddRange(ProcessMessageTraceResults(userMessageTraces, summary));
#pragma warning restore SA1101
                    }
                    catch (Exception ex)
                    {
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"Failed to get historical message trace for {userId}: {ex.Message}");
#pragma warning restore SA1101
                    }
                }
#pragma warning restore SA1101
            }
            else
            {
                // Single query
                var startDate = (DateTime)searchParameters["StartDate"];
                var endDate = (DateTime)searchParameters["EndDate"];

                var messageTraces = new List<MessageTrace>();
#pragma warning disable SA1101
                await foreach (var result in _exchangeClient.GetMessageTraceAsync(startDate, endDate,
                    searchParameters.ContainsKey("SenderAddress") ? searchParameters["SenderAddress"]?.ToString() : null,
                    searchParameters.ContainsKey("RecipientAddress") ? searchParameters["RecipientAddress"]?.ToString() : null,
                    searchParameters.ContainsKey("MessageId") ? searchParameters["MessageId"]?.ToString() : null))
                {
                    if (result.Value != null)
                        messageTraces.AddRange(result.Value);
                }
#pragma warning restore SA1101
#pragma warning disable SA1101
                messages.AddRange(ProcessMessageTraceResults(messageTraces, summary));
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            return messages;
        }

        private List<MessageTraceEntry> ProcessMessageTraceResults(IEnumerable<MessageTrace> results, MessageTraceLogSummary summary)
        {
            var messages = new List<MessageTraceEntry>();

            foreach (var result in results)
            {
                try
                {
                    var entry = new MessageTraceEntry
                    {
                        Received = result.Received,
                        SenderAddress = result.SenderAddress,
                        RecipientAddress = result.RecipientAddress,
                        Subject = result.Subject,
                        Status = result.Status,
                        ToIP = result.ToIP,
                        FromIP = result.FromIP,
                        Size = result.Size,
                        MessageId = result.MessageId,
                        MessageTraceId = result.MessageTraceId.ToString()
                    };

                    messages.Add(entry);
                    summary.TotalMessages++;

                    // Track status breakdown
                    var status = entry.Status ?? "Unknown";
                    if (summary.StatusBreakdown.ContainsKey(status))
                        summary.StatusBreakdown[status]++;
                    else
                        summary.StatusBreakdown[status] = 1;
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Failed to process message trace result: {ex.Message}");
#pragma warning restore SA1101
                }
            }

            return messages;
        }

        private string GetOutputDirectory()
        {
#pragma warning disable SA1101
            var directory = OutputDir;
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

        private void LogSummary(MessageTraceLogSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("=== Message Trace Log Collection Summary ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Search Period: {summary.SearchStartDate:yyyy-MM-dd} to {summary.SearchEndDate:yyyy-MM-dd}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Trace Type: {(summary.UseHistoricalTrace ? "Historical" : "Standard")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Total Messages: {summary.TotalMessages:N0}");
#pragma warning restore SA1101

            if (summary.StatusBreakdown.Count > 0)
            {
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose("Status Breakdown:");
#pragma warning restore SA1101
                foreach (var kvp in summary.StatusBreakdown.OrderByDescending(x => x.Value))
                {
#pragma warning disable SA1101
                    WriteVerbose($"  {kvp.Key}: {kvp.Value:N0}");
#pragma warning restore SA1101
                }
            }

            if (!string.IsNullOrEmpty(summary.OutputFile))
            {
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"Output File: {summary.OutputFile}");
#pragma warning restore SA1101
            }

#pragma warning disable SA1101
            WriteVerbose("============================================");
#pragma warning restore SA1101
        }

        private async Task WriteResultsToFileAsync(IEnumerable<MessageTraceEntry> results, string filePath)
        {
            try
            {
                var directory = Path.GetDirectoryName(filePath);
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Write as CSV
#pragma warning disable SA1101
                var csv = ConvertToCsv(results);
#pragma warning restore SA1101
                using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to write results to file {filePath}: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private string ConvertToCsv(IEnumerable<MessageTraceEntry> results)
        {
            var csv = "Received,SenderAddress,RecipientAddress,Subject,Status,ToIP,FromIP,Size,MessageId,MessageTraceId" + Environment.NewLine;

            foreach (var item in results)
            {
#pragma warning disable SA1101
                var values = new[]
                {
                    item.Received?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(item.SenderAddress),
                    EscapeCsvValue(item.RecipientAddress),
                    EscapeCsvValue(item.Subject),
                    EscapeCsvValue(item.Status),
                    EscapeCsvValue(item.ToIP),
                    EscapeCsvValue(item.FromIP),
                    item.Size.ToString(),
                    EscapeCsvValue(item.MessageId),
                    EscapeCsvValue(item.MessageTraceId)
                };
#pragma warning restore SA1101

                csv += string.Join(",", values) + Environment.NewLine;
            }

            return csv;
        }

        private string EscapeCsvValue(string value)
        {
            if (string.IsNullOrEmpty(value))
                return "";

            if (value.Contains(",") || value.Contains("\"") || value.Contains("\n"))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }

            return value;
        }
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class MessageTraceLogResult
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
        public List<MessageTraceEntry> Messages { get; set; } = new List<MessageTraceEntry>();
#pragma warning disable SA1600
        public MessageTraceLogSummary Summary { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class MessageTraceEntry
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? Received { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string SenderAddress { get; set; }
        public string RecipientAddress { g
#pragma warning restore SA1600
set; }
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Subject { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Status { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ToIP { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string FromIP { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public long Size { get; set; }
        public string MessageId { get; set; }public string MessageTraceId { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class MessageTraceLogSummary
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set;}
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime SearchStartDate { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime SearchEndDate { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool UseHistoricalTrace { get; set; }
#pragma warning restore SA1600
        public int TotalMessages { get; set; }
        public Dictionary<string, int> StatusBreakdown { get; set; } = new Dictionary<string, int>();
        public string OutputFile { get; set; }}
}
