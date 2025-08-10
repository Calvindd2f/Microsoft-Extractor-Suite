using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CsvHelper;
using System.Globalization;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Json;
using Microsoft.ExtractorSuite.Models;
using Microsoft.Graph;
using Microsoft.Graph.Models;

namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
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
        public string SearchName { get; set; } = string.Empty;

        [Parameter(HelpMessage = "Start date for the audit log search. Default: Today -90 days")]
        public DateTime? StartDate { get; set; }

        [Parameter(HelpMessage = "End date for the audit log search. Default: Now")]
        public DateTime? EndDate { get; set; }

        [Parameter(HelpMessage = "Filter by user principal names")]
        public string[]? UserIds { get; set; }

        [Parameter(HelpMessage = "Filter by record types (e.g., ExchangeItem, ExchangeAdmin)")]
        public string[]? RecordType { get; set; }

        [Parameter(HelpMessage = "Filter by specific keywords")]
        public string? Keyword { get; set; }

        [Parameter(HelpMessage = "Filter by service (e.g., Exchange, SharePoint, Teams)")]
        public string? Service { get; set; }

        [Parameter(HelpMessage = "Filter by operations (e.g., UserLoggedIn, MailItemsAccessed)")]
        public string[]? Operations { get; set; }

        [Parameter(HelpMessage = "Filter by IP addresses")]
        public string[]? IPAddress { get; set; }

        [Parameter(HelpMessage = "Filter by object IDs")]
        public string[]? ObjectIDs { get; set; }

        [Parameter(HelpMessage = "Maximum number of events per output file. Default: 250000")]
        public int MaxEventsPerFile { get; set; } = 250000;

        [Parameter(HelpMessage = "Output format: CSV, JSON, JSONL, or SOF-ELK. Default: JSON")]
        [ValidateSet("CSV", "JSON", "JSONL", "SOF-ELK")]
        public string Output { get; set; } = "JSON";

        [Parameter(HelpMessage = "Text encoding for output files. Default: UTF8")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(HelpMessage = "Split output into multiple files based on MaxEventsPerFile")]
        public SwitchParameter SplitFiles { get; set; }

        #endregion

        #region Private Fields

        private GraphServiceClient? _graphClient;
        private HighPerformanceJsonProcessor? _jsonProcessor;
        private string _searchId = string.Empty;
        private readonly GraphAuditLogSummary _summary = new();
        private int _fileCounter = 1;
        private int _currentFileEvents = 0;
        private string _currentFilePath = string.Empty;
        private StreamWriter? _currentWriter;
        private CsvWriter? _csvWriter;
        private readonly List<GraphAuditLogRecord> _csvBuffer = new();
        private bool _firstRecordInFile = true;

        #endregion

        protected override void BeginProcessing()
        {
            base.BeginProcessing();

            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Not connected to Microsoft Graph. Please run Connect-M365 first.");
            }

            _graphClient = AuthManager.GraphClient;
            _jsonProcessor = new HighPerformanceJsonProcessor();

            // Set default dates (Graph API limitation: max 180 days for audit logs)
            EndDate ??= DateTime.UtcNow;
            StartDate ??= EndDate.Value.AddDays(-90);

            // Validate date range
            if ((EndDate.Value - StartDate.Value).TotalDays > 180)
            {
                WriteWarningWithTimestamp("Graph audit logs are limited to 180 days. Adjusting start date.");
                StartDate = EndDate.Value.AddDays(-180);
            }

            _summary.StartTime = DateTime.UtcNow;
        }

        protected override void ProcessRecord()
        {
            var results = RunAsyncOperation(RetrieveGraphAuditLogsAsync, "Graph UAL Retrieval");

            if (!Async.IsPresent && results != null)
            {
                WriteObject(results);
            }
        }

        private async Task<GraphAuditLogSummary> RetrieveGraphAuditLogsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("=== Starting Microsoft Graph Audit Log Retrieval ===");
            WriteVerboseWithTimestamp($"Analysis Period: {StartDate:yyyy-MM-dd HH:mm:ss} to {EndDate:yyyy-MM-dd HH:mm:ss}");
            WriteVerboseWithTimestamp($"Output Directory: {OutputDirectory}");
            WriteVerboseWithTimestamp($"Output Format: {Output}");

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Creating audit log query",
                PercentComplete = 5
            });

            // Create output directory if it doesn't exist
            if (!string.IsNullOrEmpty(OutputDirectory))
            {
                Directory.CreateDirectory(OutputDirectory);
            }

            try
            {
                // Step 1: Create the audit log query
                await CreateAuditLogQueryAsync(cancellationToken);

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Waiting for query to complete",
                    PercentComplete = 15
                });

                // Step 2: Wait for the query to complete
                await WaitForQueryCompletionAsync(cancellationToken);

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Retrieving audit log records",
                    PercentComplete = 30
                });

                // Step 3: Retrieve and export the records
                await RetrieveAndExportRecordsAsync(progress, cancellationToken);

                // Finalize output files
                FinalizeCurrentFile();

                _summary.ProcessingTime = DateTime.UtcNow - _summary.StartTime;

                // Display summary
                WriteVerboseWithTimestamp("=== Audit Log Retrieval Summary ===");
                WriteVerboseWithTimestamp($"Search Name: {SearchName}");
                WriteVerboseWithTimestamp($"Search ID: {_searchId}");
                WriteVerboseWithTimestamp($"Total Records Retrieved: {_summary.TotalRecords:N0}");
                WriteVerboseWithTimestamp($"Files Created: {_summary.ExportedFiles}");
                WriteVerboseWithTimestamp($"Processing Time: {_summary.ProcessingTime:hh\\:mm\\:ss}");

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Completed",
                    PercentComplete = 100
                });

                return _summary;
            }
            catch (ServiceException ex)
            {
                WriteErrorWithTimestamp($"Graph API error: {ex.Message}", ex);
                throw;
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Error retrieving Graph audit logs: {ex.Message}", ex);
                throw;
            }
            finally
            {
                // Clean up resources
                _currentWriter?.Dispose();
                _csvWriter?.Dispose();
            }
        }

        private async Task CreateAuditLogQueryAsync(CancellationToken cancellationToken)
        {
            if (_graphClient == null)
                throw new InvalidOperationException("Graph client not initialized");

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

            var jsonBody = JsonSerializer.Serialize(requestBody, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            });

            WriteVerboseWithTimestamp($"Creating audit log query: {SearchName}");

            using var httpClient = new HttpClient();
            var accessToken = await AuthManager.GetAccessTokenAsync(cancellationToken);
            httpClient.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var response = await httpClient.PostAsync(
                "https://graph.microsoft.com/beta/security/auditLog/queries",
                new StringContent(jsonBody, System.Text.Encoding.UTF8, "application/json"),
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync(cancellationToken);
                throw new InvalidOperationException($"Failed to create audit log query: {response.StatusCode} - {error}");
            }

            var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
            using var doc = JsonDocument.Parse(responseContent);
            
            if (doc.RootElement.TryGetProperty("id", out var idElement))
            {
                _searchId = idElement.GetString() ?? throw new InvalidOperationException("No search ID returned");
                _summary.SearchId = _searchId;
                WriteVerboseWithTimestamp($"Audit log query created with ID: {_searchId}");
            }
            else
            {
                throw new InvalidOperationException("Failed to get search ID from response");
            }
        }

        private async Task WaitForQueryCompletionAsync(CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(_searchId))
                throw new InvalidOperationException("Search ID not available");

            WriteVerboseWithTimestamp("Waiting for query to complete...");

            using var httpClient = new HttpClient();
            var accessToken = await AuthManager.GetAccessTokenAsync(cancellationToken);
            httpClient.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var apiUrl = $"https://graph.microsoft.com/beta/security/auditLog/queries/{_searchId}";
            var status = string.Empty;
            var lastStatus = string.Empty;
            var waitCount = 0;

            do
            {
                var response = await httpClient.GetAsync(apiUrl, cancellationToken);
                
                if (!response.IsSuccessStatusCode)
                {
                    var error = await response.Content.ReadAsStringAsync(cancellationToken);
                    throw new InvalidOperationException($"Failed to check query status: {response.StatusCode} - {error}");
                }

                var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
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
            if (string.IsNullOrEmpty(_searchId))
                throw new InvalidOperationException("Search ID not available");

            WriteVerboseWithTimestamp("Starting to retrieve records...");

            using var httpClient = new HttpClient();
            var accessToken = await AuthManager.GetAccessTokenAsync(cancellationToken);
            httpClient.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var apiUrl = $"https://graph.microsoft.com/beta/security/auditLog/queries/{_searchId}/records";
            var totalRecords = 0;

            // Initialize first output file
            InitializeOutputFile();

            do
            {
                try
                {
                    var response = await httpClient.GetAsync(apiUrl, cancellationToken);
                    
                    if (!response.IsSuccessStatusCode)
                    {
                        var error = await response.Content.ReadAsStringAsync(cancellationToken);
                        WriteWarningWithTimestamp($"Failed to retrieve records: {response.StatusCode} - {error}");
                        
                        // Retry logic
                        await Task.Delay(5000, cancellationToken);
                        continue;
                    }

                    var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
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
                                await ProcessRecordAsync(record, cancellationToken);
                                _summary.ProcessedRecords++;

                                // Check if we need to create a new file
                                if (SplitFiles.IsPresent && _currentFileEvents >= MaxEventsPerFile)
                                {
                                    FinalizeCurrentFile();
                                    _fileCounter++;
                                    InitializeOutputFile();
                                }
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
                    WriteWarningWithTimestamp($"Error retrieving batch: {ex.Message}");
                    
                    // Retry logic with exponential backoff
                    await Task.Delay(10000, cancellationToken);
                }

            } while (!string.IsNullOrEmpty(apiUrl) && !cancellationToken.IsCancellationRequested);

            _summary.TotalRecords = totalRecords;

            if (totalRecords == 0)
            {
                WriteWarningWithTimestamp("No results matched your search criteria.");
            }
            else
            {
                WriteVerboseWithTimestamp($"Retrieved {totalRecords:N0} total records");
            }
        }

        private async Task ProcessRecordAsync(JsonElement record, CancellationToken cancellationToken)
        {
            _currentFileEvents++;

            switch (Output.ToUpper())
            {
                case "JSON":
                    await WriteJsonRecordAsync(record, cancellationToken);
                    break;

                case "JSONL":
                    await WriteJsonlRecordAsync(record, cancellationToken);
                    break;

                case "CSV":
                    await WriteCsvRecordAsync(record, cancellationToken);
                    break;

                case "SOF-ELK":
                    await WriteSofElkRecordAsync(record, cancellationToken);
                    break;
            }
        }

        private async Task WriteJsonRecordAsync(JsonElement record, CancellationToken cancellationToken)
        {
            if (_currentWriter == null) return;

            if (!_firstRecordInFile)
            {
                await _currentWriter.WriteAsync(",");
            }
            else
            {
                _firstRecordInFile = false;
            }

            await _currentWriter.WriteLineAsync();
            
            var json = record.GetRawText();
            await _currentWriter.WriteAsync(json);
        }

        private async Task WriteJsonlRecordAsync(JsonElement record, CancellationToken cancellationToken)
        {
            if (_currentWriter == null) return;

            // For JSONL, extract the auditData field if it exists
            if (record.TryGetProperty("auditData", out var auditData))
            {
                await _currentWriter.WriteLineAsync(auditData.GetRawText());
            }
            else
            {
                await _currentWriter.WriteLineAsync(record.GetRawText());
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

            _csvBuffer.Add(csvRecord);

            // Write buffer when it reaches a certain size
            if (_csvBuffer.Count >= 1000)
            {
                await FlushCsvBufferAsync(cancellationToken);
            }
        }

        private async Task WriteSofElkRecordAsync(JsonElement record, CancellationToken cancellationToken)
        {
            if (_currentWriter == null) return;

            // For SOF-ELK format, write only the auditData field
            if (record.TryGetProperty("auditData", out var auditData))
            {
                await _currentWriter.WriteLineAsync(auditData.GetRawText());
            }
        }

        private void InitializeOutputFile()
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            var baseFileName = $"{timestamp}-{SearchName}-UnifiedAuditLog";

            string fileName;
            if (SplitFiles.IsPresent && _fileCounter > 1)
            {
                fileName = $"{baseFileName}-part{_fileCounter}";
            }
            else
            {
                fileName = baseFileName;
            }

            var extension = Output.ToLower() switch
            {
                "csv" => "csv",
                "jsonl" => "jsonl",
                "sof-elk" => "json",
                _ => "json"
            };

            _currentFilePath = Path.Combine(OutputDirectory ?? ".", $"{fileName}.{extension}");
            
            WriteVerboseWithTimestamp($"Creating output file: {_currentFilePath}");

            var encoding = System.Text.Encoding.GetEncoding(Encoding);
            _currentWriter = new StreamWriter(_currentFilePath, false, encoding);
            _firstRecordInFile = true;
            _currentFileEvents = 0;

            // Initialize file based on format
            switch (Output.ToUpper())
            {
                case "JSON":
                    _currentWriter.Write("[");
                    break;

                case "CSV":
                    _csvWriter?.Dispose();
                    _csvWriter = new CsvWriter(_currentWriter, CultureInfo.InvariantCulture);
                    _csvWriter.WriteHeader<GraphAuditLogRecord>();
                    _csvWriter.NextRecord();
                    break;
            }
        }

        private void FinalizeCurrentFile()
        {
            if (_currentWriter == null) return;

            try
            {
                // Flush any remaining CSV records
                if (Output.Equals("CSV", StringComparison.OrdinalIgnoreCase) && _csvBuffer.Any())
                {
                    FlushCsvBufferAsync(CancellationToken.None).Wait();
                }

                // Close JSON array if needed
                if (Output.Equals("JSON", StringComparison.OrdinalIgnoreCase))
                {
                    _currentWriter.WriteLine();
                    _currentWriter.Write("]");
                }

                _currentWriter.Flush();
                _currentWriter.Dispose();
                _currentWriter = null;

                _csvWriter?.Dispose();
                _csvWriter = null;

                _summary.ExportedFiles++;

                WriteVerboseWithTimestamp($"File complete: {Path.GetFileName(_currentFilePath)} ({_currentFileEvents} events)");
            }
            catch (Exception ex)
            {
                WriteWarningWithTimestamp($"Error finalizing file: {ex.Message}");
            }
        }

        private async Task FlushCsvBufferAsync(CancellationToken cancellationToken)
        {
            if (_csvWriter == null || !_csvBuffer.Any()) return;

            foreach (var record in _csvBuffer)
            {
                _csvWriter.WriteRecord(record);
                _csvWriter.NextRecord();
            }

            await _csvWriter.FlushAsync();
            _csvBuffer.Clear();
        }

        protected override void EndProcessing()
        {
            // Clean up any remaining resources
            FinalizeCurrentFile();
            _currentWriter?.Dispose();
            _csvWriter?.Dispose();
            _jsonProcessor?.Dispose();

            base.EndProcessing();
        }
    }

    /// <summary>
    /// Represents a Graph API audit log record
    /// </summary>
    public class GraphAuditLogRecord
    {
        public string Id { get; set; } = string.Empty;
        public DateTime CreatedDateTime { get; set; }
        public string AuditLogRecordType { get; set; } = string.Empty;
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
        public int TotalRecords { get; set; }
        public int ProcessedRecords { get; set; }
        public int ExportedFiles { get; set; }
        public DateTime StartTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }
    }
}