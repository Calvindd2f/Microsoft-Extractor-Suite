namespace Microsoft.ExtractorSuite.Cmdlets.Mail
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Text.Json;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Exchange;


    /// <summary>
    /// Cmdlet to retrieve mail items accessed sessions and message IDs for security investigations
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "MailItemsAccessed")]
    [OutputType(typeof(MailItemsAccessedResult))]
    public class GetMailItemsAccessedCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            Mandatory = true,
            HelpMessage = "Start date for the search range")]
        public DateTime StartDate { get; set; }

        [Parameter(
            Mandatory = true,
            HelpMessage = "End date for the search range")]
        public DateTime EndDate { get; set; }

        [Parameter(
            HelpMessage = "User IDs to filter by")]


        public string UserIds { get; set; }

        [Parameter(
            HelpMessage = "IP address to filter by")]


        public string IPAddress { get; set; }

        [Parameter(
            HelpMessage = "Session IDs to filter by")]


        public string Sessions { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]

        public string OutputDir { get; set; } = "Output\\MailItemsAccessed";


        [Parameter(
            HelpMessage = "File encoding for output files")]

        public string Encoding { get; set; } = "UTF8";


        [Parameter(
            HelpMessage = "Whether to output results to file")]

        public SwitchParameter Output { get; set; } = true;


        [Parameter(
            HelpMessage = "Whether to download emails and attachments")]


        public SwitchParameter Download { get; set; }

        [Parameter(
            HelpMessage = "Operation mode: Sessions or MessageIDs")]
        [ValidateSet("Sessions", "MessageIDs")]

        public string Mode { get; set; } = "Sessions";


        private readonly ExchangeRestClient _exchangeClient;

        public GetMailItemsAccessedCmdlet()
        {

            _exchangeClient = new ExchangeRestClient(AuthManager);


        }


        protected override async Task ProcessRecordAsync()
        {

            WriteVerbose("=== Starting Mail Items Accessed Collection ===");


            // Validate date range

            if (StartDate >= EndDate)
            {

                WriteErrorWithTimestamp("StartDate must be before EndDate");

                return;
            }


            // Check for authentication

            if (!await _exchangeClient.IsConnectedAsync())
            {

                WriteErrorWithTimestamp("Not connected to Exchange Online. Please run Connect-M365 first.");

                return;
            }


            // Create output directory

            var outputDirectory = GetOutputDirectory();



            var summary = new CollectionSummary
            {
                StartTime = DateTime.Now,
                QueryType = DetermineQueryType(),
                TotalEvents = 0,
                UniqueSessions = new HashSet<string>(),
                OperationCount = 0
            };



            WriteVerbose($"Query Information:");


            WriteVerbose($"  Filter: {summary.QueryType}");


            WriteVerbose($"  Time Range: {StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}");


            try
            {

                if (Mode == "Sessions")
                {

                    await ProcessSessionsAsync(outputDirectory, summary);

                }
                else
                {

                    await ProcessMessageIDsAsync(outputDirectory, summary);

                }


                summary.ProcessingTime = DateTime.Now - summary.StartTime;

                LogCollectionSummary(summary, outputDirectory);

            }
            catch (Exception ex)
            {

                WriteErrorWithTimestamp($"An error occurred during collection: {ex.Message}");

                throw;
            }
        }

        private async Task ProcessSessionsAsync(string outputDirectory, CollectionSummary summary)
        {

            WriteVerbose("Processing MailItemsAccessed sessions...");



            var searchParams = new Dictionary<string, object>
            {
                ["StartDate"] = StartDate,
                ["EndDate"] = EndDate,
                ["Operations"] = "MailItemsAccessed",
                ["ResultSize"] = 1
            };


            // Add filters based on parameters

            if (!string.IsNullOrEmpty(UserIds))

                searchParams["UserIds"] = UserIds;



            if (!string.IsNullOrEmpty(IPAddress))

                searchParams["FreeText"] = IPAddress;


            // Check total result count first

            var resultCount = await GetResultCountAsync(searchParams);


            if (resultCount > 4999)
            {

                WriteWarningWithTimestamp($"A total of {resultCount} events have been identified, surpassing the maximum limit of 5000 results. Please refine your search.");

                return;
            }

            if (resultCount == 0)
            {

                WriteVerbose("No MailItemsAccessed events found for the specified criteria.");

                return;
            }

            // Retrieve the actual records

            var userIds = !string.IsNullOrEmpty(UserIds) ? UserIds.Split(',').Select(u => u.Trim()).ToArray() : null;


            var records = await _exchangeClient.SearchUnifiedAuditLogAsync(
                StartDate,
                EndDate,
                null, // sessionId
                new[] { "MailItemsAccessed" }, // operations
                null, // recordTypes
                userIds,
                5000, // resultSize
                CancellationToken);


            var results = new List<MailItemsAccessedSession>();

            if (records?.Value != null)
            {
                foreach (var record in records.Value)
                {
                    var auditData = JsonDocument.Parse(record.AuditData);

                    var session = new MailItemsAccessedSession
                    {
                        Timestamp = auditData.RootElement.GetProperty("CreationTime").GetDateTime(),
                        User = auditData.RootElement.GetProperty("UserId").GetString(),
                        Action = auditData.RootElement.GetProperty("Operation").GetString(),
                        SessionId = GetJsonPropertyString(auditData.RootElement, "SessionId"),
                        ClientIP = GetJsonPropertyString(auditData.RootElement, "ClientIPAddress"),
                        OperationCount = GetJsonPropertyInt32(auditData.RootElement, "OperationCount")
                    };

                    summary.TotalEvents++;

                    if (!string.IsNullOrEmpty(session.SessionId))
                    {
                        summary.UniqueSessions.Add(session.SessionId);
                    }

                    summary.OperationCount += session.OperationCount;
                    results.Add(session);
                }
            }

            // Apply additional filtering for IP address if specified

            if (!string.IsNullOrEmpty(IPAddress))
            {

                results = results.Where(r => r.ClientIP == IPAddress).ToList();

            }


            // Output results

            if (Output && results.Count > 0)
            {

                var fileName = GenerateSessionsFileName();

                var filePath = Path.Combine(outputDirectory, fileName);


                await WriteResultsToFileAsync(results, filePath);


                WriteVerbose($"Output written to {filePath}");



                WriteObject(results);

            }

        }

        private async Task ProcessMessageIDsAsync(string outputDirectory, CollectionSummary summary)
        {

            WriteVerbose("Processing MailItemsAccessed message IDs...");



            var searchParams = new Dictionary<string, object>
            {
                ["StartDate"] = StartDate,
                ["EndDate"] = EndDate,
                ["Operations"] = "MailItemsAccessed",
                ["ResultSize"] = 1
            };


            // Add filters based on parameters

            if (!string.IsNullOrEmpty(Sessions))

                searchParams["FreeText"] = Sessions;

            else if (!string.IsNullOrEmpty(IPAddress))

                searchParams["FreeText"] = IPAddress;


            // Check total result count first

            var resultCount = await GetResultCountAsync(searchParams);


            if (resultCount > 4999)
            {

                WriteWarningWithTimestamp($"A total of {resultCount} events have been identified, surpassing the maximum limit of 5000 results. Please refine your search.");

                return;
            }

            if (resultCount == 0)
            {

                WriteVerbose("No MailItemsAccessed events found for the specified criteria.");

                return;
            }

            // Retrieve the actual records

            var userIds = !string.IsNullOrEmpty(Sessions) ? new[] { Sessions } : null;



            var records = await _exchangeClient.SearchUnifiedAuditLogAsync(
                StartDate,
                EndDate,
                null, // sessionId
                new[] { "MailItemsAccessed" }, // operations
                null, // recordTypes
                userIds,
                5000, // resultSize
                CancellationToken);


            var results = new List<MailItemsAccessedMessage>();

            if (records?.Value != null)
            {
                foreach (var record in records.Value)
                {
                    var auditData = JsonDocument.Parse(record.AuditData);

                    var timestamp = auditData.RootElement.GetProperty("CreationTime").GetDateTime();
                    var sessionId = GetJsonPropertyString(auditData.RootElement, "SessionId");
                    var clientIP = GetJsonPropertyString(auditData.RootElement, "ClientIPAddress");
                    var userId = auditData.RootElement.GetProperty("UserId").GetString();
                    var operationCount = GetJsonPropertyInt32(auditData.RootElement, "OperationCount");

                    // Apply session/IP filtering
                    bool includeRecord = true;


                    if (!string.IsNullOrEmpty(Sessions) && !string.IsNullOrEmpty(sessionId))
                    {

                        includeRecord = Sessions.Contains(sessionId);

                    }



                    if (!string.IsNullOrEmpty(IPAddress) && includeRecord)
                    {

                        includeRecord = clientIP == IPAddress;

                    }


                    if (!includeRecord) continue;

                    summary.TotalEvents++;

                    // Process folder items
                    if (auditData.RootElement.TryGetProperty("Folders", out var folders))
                    {
                        if (folders.TryGetProperty("FolderItems", out var folderItems))
                        {
                            if (folderItems.ValueKind == JsonValueKind.Array)
                            {
                                foreach (var item in folderItems.EnumerateArray())
                                {
                                    var messageId = GetJsonPropertyString(item, "InternetMessageId");
                                    var sizeInBytes = GetJsonPropertyInt64(item, "SizeInBytes");

                                    if (!string.IsNullOrEmpty(messageId))
                                    {
                                        var message = new MailItemsAccessedMessage
                                        {
                                            Timestamp = timestamp,
                                            User = userId,
                                            IPAddress = clientIP,
                                            SessionID = sessionId,
                                            InternetMessageId = messageId,
                                            SizeInBytes = sizeInBytes
                                        };

                                        results.Add(message);

                                        // Download emails if requested

                                        if (Download && !string.IsNullOrEmpty(messageId))
                                        {
                                            // TODO: Implement email download functionality

                                            WriteWarningWithTimestamp("Email download functionality not yet implemented in C# version");

                                        }

                                    }
                                }
                            }
                            else
                            {
                                // Single item
                                var messageId = GetJsonPropertyString(folderItems, "InternetMessageId");
                                var sizeInBytes = GetJsonPropertyInt64(folderItems, "SizeInBytes");

                                if (!string.IsNullOrEmpty(messageId))
                                {
                                    var message = new MailItemsAccessedMessage
                                    {
                                        Timestamp = timestamp,
                                        User = userId,
                                        IPAddress = clientIP,
                                        SessionID = sessionId,
                                        InternetMessageId = messageId,
                                        SizeInBytes = sizeInBytes
                                    };

                                    results.Add(message);
                                }
                            }
                        }
                    }
                }
            }

            // Output results

            if (Output && results.Count > 0)
            {

                var fileName = GenerateMessageIDsFileName();

                var filePath = Path.Combine(outputDirectory, fileName);


                await WriteResultsToFileAsync(results, filePath);


                WriteVerbose($"Output written to {filePath}");



                WriteObject(results);

            }

        }

        private async Task<int> GetResultCountAsync(Dictionary<string, object> searchParams)
        {
            var startDate = (DateTime)searchParams["StartDate"];
            var endDate = (DateTime)searchParams["EndDate"];
            var operations = searchParams.ContainsKey("Operations") ? new[] { (string)searchParams["Operations"] } : null;

            var userIds = !string.IsNullOrEmpty(UserIds) ? UserIds.Split(',').Select(u => u.Trim()).ToArray() : null;



            var records = await _exchangeClient.SearchUnifiedAuditLogAsync(
                startDate,
                endDate,
                null, // sessionId
                operations,
                null, // recordTypes
                userIds,
                1, // resultSize
                CancellationToken);


            return records?.ResultCount ?? 0;
        }

        private string DetermineQueryType()
        {

            if (!string.IsNullOrEmpty(UserIds) && !string.IsNullOrEmpty(IPAddress))
                return "User and IP Filter";

            else if (!string.IsNullOrEmpty(UserIds))
                return "User Filter";

            else if (!string.IsNullOrEmpty(IPAddress))
                return "IP Filter";
            else if (!string.IsNullOrEmpty(Sessions))
                return "Session Filter";
            else
                return "All Events";

        }

        private string GetOutputDirectory()
        {

            var directory = string.IsNullOrEmpty(OutputDir) ? "Output\\MailItemsAccessed" : OutputDir;


            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);

                WriteVerbose($"Creating output directory: {directory}");

            }

            return directory;
        }

        private string GenerateSessionsFileName()
        {

            if (!string.IsNullOrEmpty(UserIds) && !string.IsNullOrEmpty(IPAddress))

                return $"Sessions-{UserIds}-{IPAddress}.csv";


            else if (!string.IsNullOrEmpty(UserIds))

                return $"Sessions-{UserIds}.csv";

            else if (!string.IsNullOrEmpty(IPAddress))

                return $"Sessions-{IPAddress}.csv";

            else
                return "Sessions.csv";

        }

        private string GenerateMessageIDsFileName()
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");


            if (!string.IsNullOrEmpty(Sessions))

                return $"MessageIDs-{Sessions}.csv";

            else
                return $"{timestamp}-MessageIDs.csv";

        }

        private void LogCollectionSummary(CollectionSummary summary, string outputDirectory)
        {

            WriteVerbose("");


            WriteVerbose("=== Mail Items Accessed Analysis Summary ===");


            WriteVerbose($"Query Information:");


            WriteVerbose($"  Filter: {summary.QueryType}");


            WriteVerbose($"  Time Range: {StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}");


            WriteVerbose("");


            WriteVerbose("Event Statistics:");


            WriteVerbose($"  Total Events: {summary.TotalEvents:N0}");


            WriteVerbose($"  Unique Sessions: {summary.UniqueSessions.Count:N0}");


            WriteVerbose($"  Total Operations: {summary.OperationCount:N0}");


            WriteVerbose("");


            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");


            WriteVerbose("===============================================");

        }

        private static string GetJsonPropertyString(JsonElement element, string propertyName)
        {
            return element.TryGetProperty(propertyName, out var property)
                ? property.GetString()
                : null;
        }

        private static int GetJsonPropertyInt32(JsonElement element, string propertyName)
        {
            return element.TryGetProperty(propertyName, out var property)
                ? property.GetInt32()
                : 0;
        }

        private static long GetJsonPropertyInt64(JsonElement element, string propertyName)
        {
            return element.TryGetProperty(propertyName, out var property)
                ? property.GetInt64()
                : 0;
        }

        private async Task WriteResultsToFileAsync<T>(List<T> results, string filePath)
        {
            try
            {
                var json = JsonSerializer.Serialize(results, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                using (var writer = new StreamWriter(filePath))
                {
                    await writer.WriteAsync(json);
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Failed to write results to file: {ex.Message}");
                throw;
            }
        }
    }

    public class MailItemsAccessedSession
    {
        public DateTime Timestamp { get; set; }
        public string User { get; set; }
        public string Action { get; set; }
        public string SessionId { get; set; }
        public string ClientIP { get; set; }
        public int OperationCount { get; set; }
    }
    public class MailItemsAccessedMessage
    {
        public DateTime Timestamp { get; set; }
        public string User { get; set; }
        public string IPAddress { get; set; }
        public string SessionID { get; set; }
        public string InternetMessageId { get; set; }
        public long SizeInBytes { get; set; }
    }

    public class MailItemsAccessedResult
    {
        public List<MailItemsAccessedSession> Sessions { get; set; } = new();
        public List<MailItemsAccessedMessage> Messages { get; set; } = new();
        public CollectionSummary Summary { get; set; }
    }

    public class CollectionSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public string QueryType { get; set; }
        public int TotalEvents { get; set; }
        public HashSet<string> UniqueSessions { get; set; } = new();
        public int OperationCount { get; set; }
    }
}
