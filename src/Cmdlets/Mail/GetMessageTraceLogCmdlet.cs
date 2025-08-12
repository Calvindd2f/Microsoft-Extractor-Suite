using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Exchange;
using Microsoft.ExtractorSuite.Models.Exchange;

namespace Microsoft.ExtractorSuite.Cmdlets.Mail
{
    /// <summary>
    /// Cmdlet to collect message trace logs for email flow analysis
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "MessageTraceLog")]
    [OutputType(typeof(MessageTraceLogResult))]
    public class GetMessageTraceLogCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve message trace logs for")]
        public string[] UserIds { get; set; }

        [Parameter(
            HelpMessage = "Start date for the search range")]
        public DateTime? StartDate { get; set; }

        [Parameter(
            HelpMessage = "End date for the search range")]
        public DateTime? EndDate { get; set; }

        [Parameter(
            HelpMessage = "Sender email address to filter by")]
        public string SenderAddress { get; set; }

        [Parameter(
            HelpMessage = "Recipient email address to filter by")]
        public string RecipientAddress { get; set; }

        [Parameter(
            HelpMessage = "Message subject to filter by")]
        public string MessageSubject { get; set; }

        [Parameter(
            HelpMessage = "Message ID to search for")]
        public string MessageId { get; set; }

        [Parameter(
            HelpMessage = "Status to filter by (None, GettingStatus, Failed, Pending, Delivered, Expanded, Quarantined, FilteredAsSpam)")]
        [ValidateSet("None", "GettingStatus", "Failed", "Pending", "Delivered", "Expanded", "Quarantined", "FilteredAsSpam")]
        public string Status { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
        public string OutputDir { get; set; } = "Output\\MessageTraceLog";

        [Parameter(
            HelpMessage = "File encoding for output files")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(
            HelpMessage = "Use historical message trace (for data older than 10 days)")]
        public SwitchParameter UseHistoricalTrace { get; set; }

        [Parameter(
            HelpMessage = "Page size for results (1-5000)")]
        [ValidateRange(1, 5000)]
        public int PageSize { get; set; } = 5000;

        private readonly ExchangeRestClient _exchangeClient;

        public GetMessageTraceLogCmdlet()
        {
            _exchangeClient = new ExchangeRestClient(AuthManager);
        }

        protected override async Task ProcessRecordAsync()
        {
            WriteVerbose("=== Starting Message Trace Log Collection ===");

            // Check for authentication
            if (!await _exchangeClient.IsConnectedAsync())
            {
                WriteErrorWithTimestamp("Not connected to Exchange Online. Please run Connect-M365 first.");
                return;
            }

            // Validate date range
            var startDate = StartDate ?? DateTime.Now.AddDays(-7);
            var endDate = EndDate ?? DateTime.Now;

            if (startDate >= endDate)
            {
                WriteErrorWithTimestamp("StartDate must be before EndDate");
                return;
            }

            var daysDifference = (DateTime.Now - startDate).Days;
            var useHistorical = UseHistoricalTrace || daysDifference > 10;

            if (daysDifference > 90)
            {
                WriteErrorWithTimestamp("Message trace logs are only available for the past 90 days");
                return;
            }

            // Create output directory
            var outputDirectory = GetOutputDirectory();
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

            WriteVerbose($"Date range: {startDate:yyyy-MM-dd} to {endDate:yyyy-MM-dd}");
            WriteVerbose($"Using {(useHistorical ? "historical" : "standard")} message trace");

            try
            {
                var searchParameters = BuildSearchParameters(startDate, endDate);
                var messages = new List<MessageTraceEntry>();

                if (useHistorical)
                {
                    messages = await GetHistoricalMessageTraceAsync(searchParameters, summary);
                }
                else
                {
                    messages = await GetStandardMessageTraceAsync(searchParameters, summary);
                }

                if (messages.Count > 0)
                {
                    var outputFile = Path.Combine(outputDirectory, $"{timestamp}-MessageTrace.csv");
                    await WriteResultsToFileAsync(messages, outputFile);

                    WriteVerbose($"Message trace results written to: {outputFile}");
                    summary.OutputFile = outputFile;
                }
                else
                {
                    WriteVerbose("No message trace entries found matching the specified criteria.");
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
                LogSummary(summary);

                var result = new MessageTraceLogResult
                {
                    Messages = messages,
                    Summary = summary
                };

                WriteObject(result);
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during message trace collection: {ex.Message}");
                throw;
            }
        }

        private Dictionary<string, object> BuildSearchParameters(DateTime startDate, DateTime endDate)
        {
            var parameters = new Dictionary<string, object>
            {
                ["StartDate"] = startDate,
                ["EndDate"] = endDate,
                ["PageSize"] = PageSize
            };

            if (UserIds != null && UserIds.Length > 0)
            {
                if (UserIds.Length == 1)
                {
                    // Check if it's a sender or recipient
                    if (!string.IsNullOrEmpty(SenderAddress) || !string.IsNullOrEmpty(RecipientAddress))
                    {
                        if (!string.IsNullOrEmpty(SenderAddress))
                            parameters["SenderAddress"] = SenderAddress;
                        if (!string.IsNullOrEmpty(RecipientAddress))
                            parameters["RecipientAddress"] = RecipientAddress;
                    }
                    else
                    {
                        // Default to recipient if not specified
                        parameters["RecipientAddress"] = UserIds[0];
                    }
                }
                else
                {
                    // Multiple users - process them individually
                    WriteVerbose($"Processing {UserIds.Length} users individually");
                }
            }

            if (!string.IsNullOrEmpty(SenderAddress))
                parameters["SenderAddress"] = SenderAddress;

            if (!string.IsNullOrEmpty(RecipientAddress))
                parameters["RecipientAddress"] = RecipientAddress;

            if (!string.IsNullOrEmpty(MessageSubject))
                parameters["MessageSubject"] = MessageSubject;

            if (!string.IsNullOrEmpty(MessageId))
                parameters["MessageId"] = MessageId;

            if (!string.IsNullOrEmpty(Status) && Status != "None")
                parameters["Status"] = Status;

            return parameters;
        }

        private async Task<List<MessageTraceEntry>> GetStandardMessageTraceAsync(Dictionary<string, object> searchParameters, MessageTraceLogSummary summary)
        {
            WriteVerbose("Executing standard message trace...");

            var messages = new List<MessageTraceEntry>();

            if (UserIds != null && UserIds.Length > 1)
            {
                // Process each user individually
                foreach (var userId in UserIds)
                {
                    var userParameters = new Dictionary<string, object>(searchParameters)
                    {
                        ["RecipientAddress"] = userId
                    };

                    try
                    {
                        WriteVerbose($"Processing message trace for: {userId}");
                        var startDate = (DateTime)userParameters["StartDate"];
                        var endDate = (DateTime)userParameters["EndDate"];
                        
                        var userMessageTraces = new List<MessageTrace>();
                        await foreach (var result in _exchangeClient.GetMessageTraceAsync(startDate, endDate,
                            userParameters.ContainsKey("SenderAddress") ? userParameters["SenderAddress"]?.ToString() : null,
                            userParameters.ContainsKey("RecipientAddress") ? userParameters["RecipientAddress"]?.ToString() : null,
                            userParameters.ContainsKey("MessageId") ? userParameters["MessageId"]?.ToString() : null))
                        {
                            if (result.Value != null)
                                userMessageTraces.AddRange(result.Value);
                        }
                        messages.AddRange(ProcessMessageTraceResults(userMessageTraces, summary));
                    }
                    catch (Exception ex)
                    {
                        WriteWarningWithTimestamp($"Failed to get message trace for {userId}: {ex.Message}");
                    }
                }
            }
            else
            {
                // Single query
                var startDate = (DateTime)searchParameters["StartDate"];
                var endDate = (DateTime)searchParameters["EndDate"];
                
                var messageTraces = new List<MessageTrace>();
                await foreach (var result in _exchangeClient.GetMessageTraceAsync(startDate, endDate,
                    searchParameters.ContainsKey("SenderAddress") ? searchParameters["SenderAddress"]?.ToString() : null,
                    searchParameters.ContainsKey("RecipientAddress") ? searchParameters["RecipientAddress"]?.ToString() : null,
                    searchParameters.ContainsKey("MessageId") ? searchParameters["MessageId"]?.ToString() : null))
                {
                    if (result.Value != null)
                        messageTraces.AddRange(result.Value);
                }
                messages.AddRange(ProcessMessageTraceResults(messageTraces, summary));
            }

            return messages;
        }

        private async Task<List<MessageTraceEntry>> GetHistoricalMessageTraceAsync(Dictionary<string, object> searchParameters, MessageTraceLogSummary summary)
        {
            WriteVerbose("Executing historical message trace...");

            var messages = new List<MessageTraceEntry>();

            if (UserIds != null && UserIds.Length > 1)
            {
                // Process each user individually
                foreach (var userId in UserIds)
                {
                    var userParameters = new Dictionary<string, object>(searchParameters)
                    {
                        ["RecipientAddress"] = userId
                    };

                    try
                    {
                        WriteVerbose($"Processing historical message trace for: {userId}");
                        var startDate = (DateTime)userParameters["StartDate"];
                        var endDate = (DateTime)userParameters["EndDate"];
                        
                        var userMessageTraces = new List<MessageTrace>();
                        await foreach (var result in _exchangeClient.GetMessageTraceAsync(startDate, endDate,
                            userParameters.ContainsKey("SenderAddress") ? userParameters["SenderAddress"]?.ToString() : null,
                            userParameters.ContainsKey("RecipientAddress") ? userParameters["RecipientAddress"]?.ToString() : null,
                            userParameters.ContainsKey("MessageId") ? userParameters["MessageId"]?.ToString() : null))
                        {
                            if (result.Value != null)
                                userMessageTraces.AddRange(result.Value);
                        }
                        messages.AddRange(ProcessMessageTraceResults(userMessageTraces, summary));
                    }
                    catch (Exception ex)
                    {
                        WriteWarningWithTimestamp($"Failed to get historical message trace for {userId}: {ex.Message}");
                    }
                }
            }
            else
            {
                // Single query
                var startDate = (DateTime)searchParameters["StartDate"];
                var endDate = (DateTime)searchParameters["EndDate"];
                
                var messageTraces = new List<MessageTrace>();
                await foreach (var result in _exchangeClient.GetMessageTraceAsync(startDate, endDate,
                    searchParameters.ContainsKey("SenderAddress") ? searchParameters["SenderAddress"]?.ToString() : null,
                    searchParameters.ContainsKey("RecipientAddress") ? searchParameters["RecipientAddress"]?.ToString() : null,
                    searchParameters.ContainsKey("MessageId") ? searchParameters["MessageId"]?.ToString() : null))
                {
                    if (result.Value != null)
                        messageTraces.AddRange(result.Value);
                }
                messages.AddRange(ProcessMessageTraceResults(messageTraces, summary));
            }

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
                    WriteWarningWithTimestamp($"Failed to process message trace result: {ex.Message}");
                }
            }

            return messages;
        }

        private string GetOutputDirectory()
        {
            var directory = OutputDir;

            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
                WriteVerbose($"Created output directory: {directory}");
            }

            return directory;
        }

        private void LogSummary(MessageTraceLogSummary summary)
        {
            WriteVerbose("");
            WriteVerbose("=== Message Trace Log Collection Summary ===");
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
            WriteVerbose($"Search Period: {summary.SearchStartDate:yyyy-MM-dd} to {summary.SearchEndDate:yyyy-MM-dd}");
            WriteVerbose($"Trace Type: {(summary.UseHistoricalTrace ? "Historical" : "Standard")}");
            WriteVerbose($"Total Messages: {summary.TotalMessages:N0}");

            if (summary.StatusBreakdown.Count > 0)
            {
                WriteVerbose("");
                WriteVerbose("Status Breakdown:");
                foreach (var kvp in summary.StatusBreakdown.OrderByDescending(x => x.Value))
                {
                    WriteVerbose($"  {kvp.Key}: {kvp.Value:N0}");
                }
            }

            if (!string.IsNullOrEmpty(summary.OutputFile))
            {
                WriteVerbose("");
                WriteVerbose($"Output File: {summary.OutputFile}");
            }

            WriteVerbose("============================================");
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
                var csv = ConvertToCsv(results);
                using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Failed to write results to file {filePath}: {ex.Message}");
                throw;
            }
        }

        private string ConvertToCsv(IEnumerable<MessageTraceEntry> results)
        {
            var csv = "Received,SenderAddress,RecipientAddress,Subject,Status,ToIP,FromIP,Size,MessageId,MessageTraceId" + Environment.NewLine;

            foreach (var item in results)
            {
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
    }

    public class MessageTraceLogResult
    {
        public List<MessageTraceEntry> Messages { get; set; } = new List<MessageTraceEntry>();
        public MessageTraceLogSummary Summary { get; set; }
    }

    public class MessageTraceEntry
    {
        public DateTime? Received { get; set; }
        public string SenderAddress { get; set; }
        public string RecipientAddress { get; set; }
        public string Subject { get; set; }
        public string Status { get; set; }
        public string ToIP { get; set; }
        public string FromIP { get; set; }
        public long Size { get; set; }
        public string MessageId { get; set; }
        public string MessageTraceId { get; set; }
    }

    public class MessageTraceLogSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public DateTime SearchStartDate { get; set; }
        public DateTime SearchEndDate { get; set; }
        public bool UseHistoricalTrace { get; set; }
        public int TotalMessages { get; set; }
        public Dictionary<string, int> StatusBreakdown { get; set; } = new Dictionary<string, int>();
        public string OutputFile { get; set; }
    }
}
