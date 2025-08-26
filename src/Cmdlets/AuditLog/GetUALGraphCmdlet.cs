namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Net.Http;
    using System.Text;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using CsvHelper;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Json;
    using Microsoft.ExtractorSuite.Models;
    using Microsoft.Graph;
    using Microsoft.Graph.Models;

    /// <summary>
    /// Retrieves Unified Audit Log entries using Microsoft Graph API.
    /// This cmdlet provides an alternative to Exchange-based UAL retrieval using Graph API's security audit log queries.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "UALGraph")]
    [OutputType(typeof(GraphAuditLogRecord))]
    public class GetUALGraphCmdlet : AsyncBaseCmdlet
    {
        #region Parameters

        [Parameter(Mandatory = true, HelpMessage = "Specifies the name of the search query.")]
#pragma warning disable SA1600
        public string SearchName { get; set; } = string.Empty;
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Start date for the audit log search. Default: Today -90 days")]
#pragma warning disable SA1600
        public DateTime? StartDate { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "End date for the audit log search. Default: Now")]
#pragma warning disable SA1600
        public DateTime? EndDate { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Filter by user principal names")]
#pragma warning disable SA1600
        public string[]? UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Filter by record types (e.g., ExchangeItem, ExchangeAdmin)")]
#pragma warning disable SA1600
        public string[]? RecordType { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Filter by specific keywords")]
#pragma warning disable SA1600
        public string? Keyword { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Filter by service (e.g., Exchange, SharePoint, Teams)")]
#pragma warning disable SA1600
        public string? Service { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Filter by operations (e.g., UserLoggedIn, MailItemsAccessed)")]
#pragma warning disable SA1600
        public string[]? Operations { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Filter by IP addresses")]
#pragma warning disable SA1600
        public string[]? IPAddress { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Filter by object IDs")]
#pragma warning disable SA1600
        public string[]? ObjectIDs { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Maximum number of events per output file. Default: 250000")]
#pragma warning disable SA1600
        public int MaxEventsPerFile { get; set; } = 250000;
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Output format: CSV, JSON, JSONL, or SOF-ELK. Default: JSON")]
        [ValidateSet("CSV", "JSON", "JSONL", "SOF-ELK")]
#pragma warning disable SA1600
        public string Output { get; set; } = "JSON";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Text encoding for output files. Default: UTF8")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Split output into multiple files based on MaxEventsPerFile")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter SplitFiles { get; set; }

        #endregion

        #region Private Fields

#pragma warning disable SA1309
#pragma warning disable SA1201
        private GraphServiceClient? _graphClient;
#pragma warning restore SA1201
#pragma warning disable SA1309
        private HighPerformanceJsonProcessor? _jsonProcessor;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private string _searchId = string.Empty;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly GraphAuditLogSummary _summary = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private int _fileCounter = 1;
#pragma warning disable SA1600
#pragma warning restore SA1309
#pragma warning disable SA1309
        private int _currentFileEvents = 0;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private string _currentFilePath = string.Empty;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private StreamWriter? _currentWriter;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private CsvWriter? _csvWriter;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly List<GraphAuditLogRecord> _csvBuffer = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private bool _firstRecordInFile = true;
#pragma warning restore SA1309

        #endregion

        protected override void BeginProcessing()
        {
            base.BeginProcessing();

#pragma warning disable SA1600
#pragma warning disable SA1101
            if (!RequireGraphConnection())
#pragma warning restore SA1600
            {
                throw new InvalidOperationException("Not connected to Microsoft Graph. Please run Connect-M365 first.");
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            _graphClient = AuthManager.GraphClient;
#pragma warning restore SA1101
#pragma warning disable SA1101
            _jsonProcessor = new HighPerformanceJsonProcessor();
#pragma warning restore SA1101

            // Set default dates (Graph API limitation: max 180 days for audit logs)
#pragma warning disable SA1101
            EndDate ??= DateTime.UtcNow;
#pragma warning restore SA1101
#pragma warning disable SA1101
            StartDate ??= EndDate.Value.AddDays(-90);
#pragma warning restore SA1101

            // Validate date range
#pragma warning disable SA1101
            if ((EndDate.Value - StartDate.Value).TotalDays > 180)
            {
#pragma warning disable SA1101
                WriteWarningWithTimestamp("Graph audit logs are limited to 180 days. Adjusting start date.");
#pragma warning restore SA1101
#pragma warning disable SA1101
                StartDate = EndDate.Value.AddDays(-180);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            _summary.StartTime = DateTime.UtcNow;
#pragma warning restore SA1101
        }

        protected override void ProcessRecord()
        {
            var results = RunAsyncOperation(RetrieveGraphAuditLogsAsync, "Graph UAL Retrieval");

#pragma warning disable SA1101
            if (!Async.IsPresent && results != null)
            {
#pragma warning disable SA1101
                WriteObject(results);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        private async Task<GraphAuditLogSummary> RetrieveGraphAuditLogsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("=== Starting Microsoft Graph Audit Log Retrieval ===");
#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Analysis Period: {StartDate:yyyy-MM-dd HH:mm:ss} to {EndDate:yyyy-MM-dd HH:mm:ss}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Output Directory: {OutputDirectory}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Output Format: {Output}");
#pragma warning restore SA1101

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Creating audit log query",
                PercentComplete = 5
            });

            // Create output directory if it doesn't exist
#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(OutputDirectory))
            {
#pragma warning disable SA1101
                Directory.CreateDirectory(OutputDirectory);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            try
            {
                // Step 1: Create the audit log query
#pragma warning disable SA1101
                await CreateAuditLogQueryAsync(cancellationToken);
#pragma warning restore SA1101

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Waiting for query to complete",
                    PercentComplete = 15
                });

                // Step 2: Wait for the query to complete
#pragma warning disable SA1101
                await WaitForQueryCompletionAsync(cancellationToken);
#pragma warning restore SA1101

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Retrieving audit log records",
                    PercentComplete = 30
                });

                // Step 3: Retrieve and export the records
#pragma warning disable SA1101
                await RetrieveAndExportRecordsAsync(progress, cancellationToken);
#pragma warning restore SA1101

                // Finalize output files
#pragma warning disable SA1101
                FinalizeCurrentFile();
#pragma warning restore SA1101

#pragma warning disable SA1101
                _summary.ProcessingTime = DateTime.UtcNow - _summary.StartTime;
#pragma warning restore SA1101

                // Display summary
                WriteVerboseWithTimestamp("=== Audit Log Retrieval Summary ===");
#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"Search Name: {SearchName}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"Search ID: {_searchId}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"Total Records Retrieved: {_summary.TotalRecords:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"Files Created: {_summary.ExportedFiles}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"Processing Time: {_summary.ProcessingTime:hh\\:mm\\:ss}");
#pragma warning restore SA1101

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Completed",
                    PercentComplete = 100
                });

#pragma warning disable SA1101
                return _summary;
#pragma warning restore SA1101
            }
            catch (ServiceException ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Graph API error: {ex.Message}", ex);
#pragma warning restore SA1101
                throw;
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Error retrieving Graph audit logs: {ex.Message}", ex);
#pragma warning restore SA1101
                throw;
            }
            finally
            {
                // Clean up resources
#pragma warning disable SA1101
                _currentWriter?.Dispose();
#pragma warning restore SA1101
#pragma warning disable SA1101
                _csvWriter?.Dispose();
#pragma warning restore SA1101
            }
        }

        private async Task CreateAuditLogQueryAsync(CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            if (_graphClient == null)
                throw new InvalidOperationException("Graph client not initialized");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var requestBody = new
            {
                ODataType = "#microsoft.graph.security.auditLogQuery",
                DisplayName = SearchName,
                FilterStartDateTime = StartDate?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                FilterEndDateTime = EndDate?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                RecordTypeFilters = RecordType ?? Array.Empty<string>(),
                KeywordFilter = Keyword ?? string.Empty,
                ServiceFilter = Service ?? string.Empty,
                OperationFilters = Operations ?? Array.Empty<string>(),
                UserPrincipalNameFilters = UserIds ?? Array.Empty<string>(),
                IpAddressFilters = IPAddress ?? Array.Empty<string>(),
                ObjectIdFilters = ObjectIDs ?? Array.Empty<string>(),
                AdministrativeUnitIdFilters = Array.Empty<string>(),
                Status = string.Empty
            };
#pragma warning restore SA1101

            var jsonBody = JsonSerializer.Serialize(requestBody, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            });

#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Creating audit log query: {SearchName}");
#pragma warning restore SA1101

            using var httpClient = new HttpClient();
#pragma warning disable SA1101
            var accessToken = await AuthManager.GetAccessTokenAsync(new string[] { "https://graph.microsoft.com/.default" }, cancellationToken);
#pragma warning restore SA1101
            httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var response = await httpClient.PostAsync(
                "https://graph.microsoft.com/beta/security/auditLog/queries",
                new StringContent(jsonBody, System.Text.Encoding.UTF8, "application/json"),
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                throw new InvalidOperationException($"Failed to create audit log query: {response.StatusCode} - {error}");
            }

            var responseContent = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(responseContent);

            if (doc.RootElement.TryGetProperty("id", out var idElement))
            {
#pragma warning disable SA1101
                _searchId = idElement.GetString() ?? throw new InvalidOperationException("No search ID returned");
#pragma warning restore SA1101
#pragma warning disable SA1101
                _summary.SearchId = _searchId;
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"Audit log query created with ID: {_searchId}");
#pragma warning restore SA1101
            }
            else
            {
                throw new InvalidOperationException("Failed to get search ID from response");
            }
        }

        private async Task WaitForQueryCompletionAsync(CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            if (string.IsNullOrEmpty(_searchId))
                throw new InvalidOperationException("Search ID not available");
#pragma warning restore SA1101

            WriteVerboseWithTimestamp("Waiting for query to complete...");

            using var httpClient = new HttpClient();
#pragma warning disable SA1101
            var accessToken = await AuthManager.GetAccessTokenAsync(new string[] { "https://graph.microsoft.com/.default" }, cancellationToken);
#pragma warning restore SA1101
            httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

#pragma warning disable SA1101
            var apiUrl = $"https://graph.microsoft.com/beta/security/auditLog/queries/{_searchId}";
#pragma warning restore SA1101
            var status = string.Empty;
            var lastStatus = string.Empty;
            var waitCount = 0;

            {
                var response = await httpClient.GetAsync(apiUrl, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    var error = await response.Content.ReadAsStringAsync();
                    throw new InvalidOperationException($"Failed to check query status: {response.StatusCode} - {error}");
                }

                var responseContent = await response.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(responseContent);

                if (doc.RootElement.TryGetProperty("status", out var statusElement))
                {
                    status = statusElement.GetString() ?? string.Empty;
                }

                if (status != lastStatus)
                {
                    WriteVerboseWithTimestamp($"Query status: {status}");
                    lastStatus = status;
                }

                if (status != "succeeded" && status != "failed")
                {
                    await Task.Delay(5000, cancellationToken); // Wait 5 seconds between checks
                    waitCount++;

                    // Show progress every 30 seconds
                    if (waitCount % 6 == 0)
                    {
                        WriteVerboseWithTimestamp($"Still waiting for query to complete... ({waitCount * 5} seconds elapsed)");
                    }
                }

            } while (status != "succeeded" && status != "failed" && !cancellationToken.IsCancellationRequested);

            if (status == "failed")
            {
                throw new InvalidOperationException("Audit log query failed");
            }

            WriteVerboseWithTimestamp("Query completed successfully");
        }

        private async Task RetrieveAndExportRecordsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            if (string.IsNullOrEmpty(_searchId))
                throw new InvalidOperationException("Search ID not available");
#pragma warning restore SA1101

            WriteVerboseWithTimestamp("Starting to retrieve records...");

            using var httpClient = new HttpClient();
#pragma warning disable SA1101
            var accessToken = await AuthManager.GetAccessTokenAsync(new string[] { "https://graph.microsoft.com/.default" }, cancellationToken);
#pragma warning restore SA1101
            httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

#pragma warning disable SA1101
            var apiUrl = $"https://graph.microsoft.com/beta/security/auditLog/queries/{_searchId}/records";
#pragma warning restore SA1101
            var totalRecords = 0;

            // Initialize first output file
#pragma warning disable SA1101
            InitializeOutputFile();
#pragma warning restore SA1101

            {
                try
                {
                    var response = await httpClient.GetAsync(apiUrl, cancellationToken);

                    if (!response.IsSuccessStatusCode)
                    {
                        var error = await response.Content.ReadAsStringAsync();
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"Failed to retrieve records: {response.StatusCode} - {error}");
#pragma warning restore SA1101

                        // Retry logic
                        await Task.Delay(5000, cancellationToken);
                        continue;
                    }

                    var responseContent = await response.Content.ReadAsStringAsync();
                    using var doc = JsonDocument.Parse(responseContent);

                    if (doc.RootElement.TryGetProperty("value", out var valueElement))
                    {
                        var records = valueElement.EnumerateArray().ToList();

                        if (records.Any())
                        {
                            var batchCount = records.Count;
                            totalRecords += batchCount;

                            // Process each record
                            foreach (var record in records)
                            {
#pragma warning disable SA1101
                                await ProcessRecordAsync(record, cancellationToken);
#pragma warning restore SA1101
#pragma warning disable SA1101
                                _summary.ProcessedRecords++;
#pragma warning restore SA1101

                                // Check if we need to create a new file
#pragma warning disable SA1101
                                if (SplitFiles.IsPresent && _currentFileEvents >= MaxEventsPerFile)
                                {
#pragma warning disable SA1101
                                    FinalizeCurrentFile();
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    _fileCounter++;
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    InitializeOutputFile();
#pragma warning restore SA1101
                                }
#pragma warning restore SA1101
                            }

                            // Report progress
                            if (totalRecords % 1000 == 0)
                            {
                                var progressPercent = Math.Min(30 + (int)((totalRecords / 100000.0) * 60), 90);
                                progress.Report(new Core.AsyncOperations.TaskProgress
                                {
                                    CurrentOperation = $"Retrieved {totalRecords:N0} records",
                                    PercentComplete = progressPercent,
                                    ItemsProcessed = totalRecords
                                });

                                WriteVerboseWithTimestamp($"Progress: {totalRecords:N0} total events processed");
                            }
                        }
                    }

                    // Check for next page
                    if (doc.RootElement.TryGetProperty("@odata.nextLink", out var nextLinkElement))
                    {
                        apiUrl = nextLinkElement.GetString();
                    }
                    else
                    {
                        apiUrl = null;
                    }
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Error retrieving batch: {ex.Message}");
#pragma warning restore SA1101

                    // Retry logic with exponential backoff
                    await Task.Delay(10000, cancellationToken);
                }

            } while (!string.IsNullOrEmpty(apiUrl) && !cancellationToken.IsCancellationRequested);

#pragma warning disable SA1101
            _summary.TotalRecords = totalRecords;
#pragma warning restore SA1101

            if (totalRecords == 0)
            {
#pragma warning disable SA1101
                WriteWarningWithTimestamp("No results matched your search criteria.");
#pragma warning restore SA1101
            }
            else
            {
                WriteVerboseWithTimestamp($"Retrieved {totalRecords:N0} total records");
            }
        }

        private async Task ProcessRecordAsync(JsonElement record, CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            _currentFileEvents++;
#pragma warning restore SA1101

#pragma warning disable SA1101
            switch (Output.ToUpper())
            {
                case "JSON":
#pragma warning disable SA1101
                    await WriteJsonRecordAsync(record, cancellationToken);
#pragma warning restore SA1101
                    break;

                case "JSONL":
#pragma warning disable SA1101
                    await WriteJsonlRecordAsync(record, cancellationToken);
#pragma warning restore SA1101
                    break;

                case "CSV":
#pragma warning disable SA1101
                    await WriteCsvRecordAsync(record, cancellationToken);
#pragma warning restore SA1101
                    break;

                case "SOF-ELK":
#pragma warning disable SA1101
                    await WriteSofElkRecordAsync(record, cancellationToken);
#pragma warning restore SA1101
                    break;
            }
#pragma warning restore SA1101
        }

        private async Task WriteJsonRecordAsync(JsonElement record, CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            if (_currentWriter == null) return;
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!_firstRecordInFile)
            {
#pragma warning disable SA1101
                await _currentWriter.WriteAsync(",");
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                _firstRecordInFile = false;
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            await _currentWriter.WriteLineAsync();
#pragma warning restore SA1101

            var json = record.GetRawText();
#pragma warning disable SA1101
            await _currentWriter.WriteAsync(json);
#pragma warning restore SA1101
        }

        private async Task WriteJsonlRecordAsync(JsonElement record, CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            if (_currentWriter == null) return;
#pragma warning restore SA1101

            // For JSONL, extract the auditData field if it exists
            if (record.TryGetProperty("auditData", out var auditData))
            {
#pragma warning disable SA1101
                await _currentWriter.WriteLineAsync(auditData.GetRawText());
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                await _currentWriter.WriteLineAsync(record.GetRawText());
#pragma warning restore SA1101
            }
        }

        private async Task WriteCsvRecordAsync(JsonElement record, CancellationToken cancellationToken)
        {
            // Buffer CSV records and write in batches
            var csvRecord = new GraphAuditLogRecord
            {
                Id = record.TryGetProperty("id", out var id) ? id.GetString() ?? string.Empty : string.Empty,
                CreatedDateTime = record.TryGetProperty("createdDateTime", out var created) ?
                    created.GetDateTime() : DateTime.MinValue,
                AuditLogRecordType = record.TryGetProperty("auditLogRecordType", out var recordType) ?
                    recordType.GetString() ?? string.Empty : string.Empty,
                Operation = record.TryGetProperty("operation", out var op) ?
                    op.GetString() ?? string.Empty : string.Empty,
                OrganizationId = record.TryGetProperty("organizationId", out var orgId) ?
                    orgId.GetString() ?? string.Empty : string.Empty,
                UserType = record.TryGetProperty("userType", out var userType) ?
                    userType.GetString() ?? string.Empty : string.Empty,
                UserId = record.TryGetProperty("userId", out var userId) ?
                    userId.GetString() ?? string.Empty : string.Empty,
                Service = record.TryGetProperty("service", out var service) ?
                    service.GetString() ?? string.Empty : string.Empty,
                ObjectId = record.TryGetProperty("objectId", out var objectId) ?
                    objectId.GetString() ?? string.Empty : string.Empty,
                UserPrincipalName = record.TryGetProperty("userPrincipalName", out var upn) ?
                    upn.GetString() ?? string.Empty : string.Empty,
                ClientIp = record.TryGetProperty("clientIp", out var clientIp) ?
                    clientIp.GetString() ?? string.Empty : string.Empty,
                AuditData = record.TryGetProperty("auditData", out var auditData) ?
                    auditData.GetRawText() : string.Empty
            };

#pragma warning disable SA1101
            _csvBuffer.Add(csvRecord);
#pragma warning restore SA1101

            // Write buffer when it reaches a certain size
#pragma warning disable SA1101
            if (_csvBuffer.Count >= 1000)
            {
#pragma warning disable SA1101
                await FlushCsvBufferAsync(cancellationToken);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        private async Task WriteSofElkRecordAsync(JsonElement record, CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            if (_currentWriter == null) return;
#pragma warning restore SA1101

            // For SOF-ELK format, write only the auditData field
            if (record.TryGetProperty("auditData", out var auditData))
            {
#pragma warning disable SA1101
                await _currentWriter.WriteLineAsync(auditData.GetRawText());
#pragma warning restore SA1101
            }
        }

        private void InitializeOutputFile()
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
#pragma warning disable SA1101
            var baseFileName = $"{timestamp}-{SearchName}-UnifiedAuditLog";
#pragma warning restore SA1101

            string fileName;
#pragma warning disable SA1101
            if (SplitFiles.IsPresent && _fileCounter > 1)
            {
#pragma warning disable SA1101
                fileName = $"{baseFileName}-part{_fileCounter}";
#pragma warning restore SA1101
            }
            else
            {
                fileName = baseFileName;
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            var extension = Output.ToLower() switch
            {
                "csv" => "csv",
                "jsonl" => "jsonl",
                "sof-elk" => "json",
                _ => "json"
            };
#pragma warning restore SA1101

#pragma warning disable SA1101
            _currentFilePath = Path.Combine(OutputDirectory ?? ".", $"{fileName}.{extension}");
#pragma warning restore SA1101

#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Creating output file: {_currentFilePath}");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var encoding = System.Text.Encoding.GetEncoding(Encoding);
#pragma warning restore SA1101
#pragma warning disable SA1101
            _currentWriter = new StreamWriter(_currentFilePath, false, encoding);
#pragma warning restore SA1101
#pragma warning disable SA1101
            _firstRecordInFile = true;
#pragma warning restore SA1101
#pragma warning disable SA1101
            _currentFileEvents = 0;
#pragma warning restore SA1101

            // Initialize file based on format
#pragma warning disable SA1101
            switch (Output.ToUpper())
            {
                case "JSON":
#pragma warning disable SA1101
                    _currentWriter.Write("[");
#pragma warning restore SA1101
                    break;

                case "CSV":
#pragma warning disable SA1101
                    _csvWriter?.Dispose();
#pragma warning restore SA1101
#pragma warning disable SA1101
                    _csvWriter = new CsvWriter(_currentWriter, CultureInfo.InvariantCulture);
#pragma warning restore SA1101
#pragma warning disable SA1101
                    _csvWriter.WriteHeader<GraphAuditLogRecord>();
#pragma warning restore SA1101
#pragma warning disable SA1101
                    _csvWriter.NextRecord();
#pragma warning restore SA1101
                    break;
            }
#pragma warning restore SA1101
        }

        private void FinalizeCurrentFile()
        {
#pragma warning disable SA1101
            if (_currentWriter == null) return;
#pragma warning restore SA1101

            try
            {
                // Flush any remaining CSV records
#pragma warning disable SA1101
                if (Output.Equals("CSV", StringComparison.OrdinalIgnoreCase) && _csvBuffer.Any())
                {
                    // Run on thread pool to avoid STA thread issues
#pragma warning disable SA1101
                    Task.Run(async () => await FlushCsvBufferAsync(CancellationToken.None).ConfigureAwait(false))
                        .GetAwaiter().GetResult();
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                // Close JSON array if needed
#pragma warning disable SA1101
                if (Output.Equals("JSON", StringComparison.OrdinalIgnoreCase))
                {
#pragma warning disable SA1101
                    _currentWriter.WriteLine();
#pragma warning restore SA1101
#pragma warning disable SA1101
                    _currentWriter.Write("]");
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                _currentWriter.Flush();
#pragma warning restore SA1101
#pragma warning disable SA1101
                _currentWriter.Dispose();
#pragma warning restore SA1101
#pragma warning disable SA1101
                _currentWriter = null;
#pragma warning restore SA1101

#pragma warning disable SA1101
                _csvWriter?.Dispose();
#pragma warning restore SA1101
#pragma warning disable SA1101
                _csvWriter = null;
#pragma warning restore SA1101

#pragma warning disable SA1101
                _summary.ExportedFiles++;
#pragma warning restore SA1101

#pragma warning disable SA1600
#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"File complete: {Path.GetFileName(_currentFilePath)} ({_currentFileEvents} events)");
#pragma warning restore SA1101
#pragma warning restore SA1600
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteWarningWithTimestamp($"Error finalizing file: {ex.Message}");
#pragma warning restore SA1101
            }
        }

        private async Task FlushCsvBufferAsync(CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            if (_csvWriter == null || !_csvBuffer.Any()) return;
#pragma warning restore SA1101

#pragma warning disable SA1101
            foreach (var record in _csvBuffer)
            {
#pragma warning disable SA1101
                _csvWriter.WriteRecord(record);
#pragma warning restore SA1101
#pragma warning disable SA1101
                _csvWriter.NextRecord();
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
#pragma warning disable SA1600

#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning disable SA1101
            await _csvWriter.FlushAsync();
#pragma warning restore SA1101
#pragma warning disable SA1600
#pragma warning disable SA1101
            _csvBuffer.Clear();
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600
#pragma warning disable SA1600

#pragma warning restore SA1600
#pragma warning disable SA1600
        protected override void EndProcessing()
#pragma warning restore SA1600
#pragma warning disable SA1600
        {
#pragma warning restore SA1600
#pragma warning disable SA1600
            // Clean up any remaining resources
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning disable SA1101
            FinalizeCurrentFile();
#pragma warning restore SA1101
#pragma warning disable SA1600
#pragma warning disable SA1101
            _currentWriter?.Dispose();
#pragma warning restore SA1101
#pragma warning disable SA1600
#pragma warning disable SA1101
            _csvWriter?.Dispose();
#pragma warning restore SA1101
#pragma warning disable SA1600
#pragma warning disable SA1101
            _jsonProcessor?.Dispose();
#pragma warning restore SA1101

            base.EndProcessing();
        }
    }

    /// <summary>
    /// Represents a Graph API audit log record
#pragma warning disable SA1600
    /// </summary>
#pragma warning restore SA1600
#pragma warning disable SA1600
    public class GraphAuditLogRecord
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
        public DateTime CreatedDateTime { get; set; }
        public string AuditLogRecordType { get; set; } = string.Empty;
#pragma warning restore SA1600
        public string Operation { get; set; } = string.Empty;
        public string OrganizationId { get; set; } = string.Empty;
        public string UserType { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public string Service { get; set; } = string.Empty;
        public string ObjectId { get; set; } = string.Empty;
        public string UserPrincipalName { get; set; } = string.Empty;
        public string ClientIp { get; set; } = string.Empty;
        public string AuditData { get; set; } = string.Empty;
    }

    /// <summary>
    /// Summary information for Graph audit log retrieval
    /// </summary>
    public class GraphAuditLogSummary
    {
        public string SearchId { get; set; } = string.Empty;
        public int TotalRecords { get; set; }public int ProcessedRecords { get; set; }public int ExportedFiles { get; set; }public DateTime StartTime { get; set; }public TimeSpan ProcessingTime { get; set; }}
}
