namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Text.Json;
    using System.Threading.Tasks;
    using CsvHelper;
    using CsvHelper.Configuration;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Models;
    using Microsoft.IO;


    [Cmdlet(VerbsCommon.Get, "UAL")]
    [OutputType(typeof(UnifiedAuditLog))]
#pragma warning disable SA1600
    public class GetUALCmdlet : BaseCmdlet
#pragma warning restore SA1600
    {
#pragma warning disable SA1309
        private static readonly RecyclableMemoryStreamManager _memoryStreamManager = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
#pragma warning disable SA1600
        private readonly HttpClient _httpClient
#pragma warning restore SA1600
new();

#pragma warning disable SA1600
        [Parameter(Mandatory = true)]
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime StartDate { get; set; }
        [Parameter(Mandatory = true)]
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime EndDate { get; set; }
        [Parameter]
#pragma warning restore SA1600
        public string[]? Operations { get; set; }

#pragma warning disable SA1600
        [Parameter]
#pragma warning restore SA1600
        public string[]? RecordTypes { get; set; }

#pragma warning disable SA1600
        [Parameter]
#pragma warning restore SA1600
        public string[]? UserIds { get; set; }

#pragma warning disable SA1600
        [Parameter]
#pragma warning restore SA1600
        public string? IPAddress { get; set; }

#pragma warning disable SA1600
        [Parameter]
#pragma warning restore SA1600
        public int BatchSize { get; set; } = 5000;

#pragma warning disable SA1600
        [Parameter]
#pragma warning restore SA1600
        public string? OutputFormat { get; set; } = "JSON";

#pragma warning disable SA1600
        [Parameter]
#pragma warning restore SA1600
        public SwitchParameter MergeOutput { get; set; }[Parameter]
        public int MaxParallelRequests { get; set; } = 10;

#pragma warning disable SA1600
#pragma warning disable SA1309
sho
#pragma warning restore SA1600
#pragma warning disable SA1201
        private string? _sessionId;
#pragma warning restore SA1201
#pragma warning disable SA1309
        private int _totalRecordsProcessed;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly object _writeLock = new();
#pragma warning restore SA1309

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
#pragma warning disable SA1600

#pragma warning restore SA1600
#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Microsoft Graph connection required");
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            _sessionId = Guid.NewGuid().ToString();
#pragma warning restore SA1101
#pragma warning disable SA1101
            _totalRecordsProcessed = 0;
#pragma warning restore SA1101
        }

        protected override void ProcessRecord()
        {
            try
            {
#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"Starting UAL extraction from {StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}");
#pragma warning restore SA1101

#pragma warning disable SA1101
                var extractionTask = ExtractUnifiedAuditLogsAsync();
#pragma warning restore SA1101
#pragma warning disable SA1101
                RunAsync(extractionTask);
#pragma warning restore SA1101

#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"UAL extraction completed. Total records processed: {_totalRecordsProcessed}");
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"UAL extraction failed: {ex.Message}", ex);
#pragma warning restore SA1101
            }
        }

        private async Task ExtractUnifiedAuditLogsAsync()
        {
            // Get Exchange Online token
#pragma warning disable SA1101
            var token = await AuthManager.GetExchangeOnlineTokenAsync(CancellationToken);
#pragma warning restore SA1101
            if (string.IsNullOrEmpty(token))
            {
                throw new InvalidOperationException("Failed to get Exchange Online token");
            }

#pragma warning disable SA1101
            _httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", token);
#pragma warning restore SA1101

            // Split date range into smaller chunks for parallel processing
#pragma warning disable SA1101
            var dateChunks = SplitDateRange(StartDate, EndDate, TimeSpan.FromHours(6));
#pragma warning restore SA1101

            // Process chunks in parallel with controlled concurrency
#pragma warning disable SA1101
            var semaphore = new System.Threading.SemaphoreSlim(MaxParallelRequests);
#pragma warning restore SA1101
            var tasks = dateChunks.Select(async chunk =>
            {
#pragma warning disable SA1101
                await semaphore.WaitAsync(CancellationToken);
#pragma warning restore SA1101
                try
                {
#pragma warning disable SA1101
                    await ProcessDateChunkAsync(chunk.Start, chunk.End);
#pragma warning restore SA1101
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);

            // Merge output files if requested
#pragma warning disable SA1101
            if (MergeOutput.IsPresent)
            {
#pragma warning disable SA1101
                await MergeOutputFilesAsync();
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        private async Task ProcessDateChunkAsync(DateTime chunkStart, DateTime chunkEnd)
        {
#pragma warning disable SA1101
            var outputFileName = GetOutputFileName(chunkStart, chunkEnd);
#pragma warning restore SA1101
            using var outputStream = _memoryStreamManager.GetStream();
            using var writer = new StreamWriter(outputStream, Encoding.UTF8, 65536, true);

            var hasMoreData = true;
            string? resultSetId = null;
            var chunkRecordCount = 0;

#pragma warning disable SA1101
            while (hasMoreData && !CancellationToken.IsCancellationRequested)
            {
#pragma warning disable SA1101
                var requestBody = BuildRequestBody(chunkStart, chunkEnd, resultSetId);
#pragma warning restore SA1101
#pragma warning disable SA1101
                var response = await SendAuditLogRequestAsync(requestBody);
#pragma warning restore SA1101

                if (response == null || response.ResultCount == 0)
                {
                    hasMoreData = false;
                    continue;
                }

                // Process records with memory-efficient streaming
                foreach (var record in response.Results)
                {
#pragma warning disable SA1101
                    await ProcessRecordAsync(record, writer);
#pragma warning restore SA1101
                    chunkRecordCount++;

                    if (chunkRecordCount % 1000 == 0)
                    {
#pragma warning disable SA1101
                        WriteProgressSafe(
                            $"Processing UAL chunk {chunkStart:HH:mm}-{chunkEnd:HH:mm}",
                            $"Records processed: {chunkRecordCount}",
                            -1);
#pragma warning restore SA1101
                    }
                }

                resultSetId = response.ResultSetId;
                hasMoreData = response.HasMoreData;

                // Flush periodically to prevent memory buildup
                if (chunkRecordCount % 5000 == 0)
                {
                    await writer.FlushAsync();
                }
            }
#pragma warning restore SA1101

            await writer.FlushAsync();

            // Write to file
#pragma warning disable SA1101
            await WriteOutputFileAsync(outputFileName, outputStream);
#pragma warning restore SA1101

#pragma warning disable SA1101
            lock (_writeLock)
            {
#pragma warning disable SA1101
                _totalRecordsProcessed += chunkRecordCount;
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Completed chunk {chunkStart:HH:mm}-{chunkEnd:HH:mm}: {chunkRecordCount} records");
#pragma warning restore SA1101
        }

        private async Task<AuditLogResponse?> SendAuditLogRequestAsync(string requestBody)
        {
            try
            {
                var content = new StringContent(requestBody, Encoding.UTF8, "application/json");
#pragma warning disable SA1101
                var tenantId = AuthManager.CurrentTenantId ?? throw new InvalidOperationException("Tenant ID not available");
#pragma warning restore SA1101
#pragma warning disable SA1101
                var response = await _httpClient.PostAsync(
                    $"https://outlook.office365.com/adminapi/beta/{tenantId}/ActivityFeed/SearchAuditLog",
                    content,
                    CancellationToken);
#pragma warning restore SA1101

                if (!response.IsSuccessStatusCode)
                {
                    var error = await response.Content.ReadAsStringAsync();
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"API request failed: {response.StatusCode} - {error}");
#pragma warning restore SA1101
                    return null;
                }

                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<AuditLogResponse>(json)
                    ?? throw new InvalidOperationException("Failed to deserialize audit log response");
            }
            catch (HttpRequestException ex)
            {
#pragma warning disable SA1101
                WriteWarningWithTimestamp($"HTTP request failed: {ex.Message}");
#pragma warning restore SA1101
                return null;
            }
            catch (TaskCanceledException)
            {
#pragma warning disable SA1101
                WriteWarningWithTimestamp("Request timeout or cancelled");
#pragma warning restore SA1101
                return null;
            }
        }

        private string BuildRequestBody(DateTime start, DateTime end, string? resultSetId)
        {
#pragma warning disable SA1101
            var request = new
            {
                StartDate = start.ToString("yyyy-MM-ddTHH:mm:ss"),
                EndDate = end.ToString("yyyy-MM-ddTHH:mm:ss"),
                ResultSize = BatchSize,
                ResultSetId = resultSetId,
                Operations = Operations,
                RecordTypes = RecordTypes,
                UserIds = UserIds,
                IPAddress = IPAddress
            };
#pragma warning restore SA1101

            return JsonSerializer.Serialize(request);
        }

        private async Task ProcessRecordAsync(UnifiedAuditLog record, StreamWriter writer)
        {
#pragma warning disable SA1101
            switch (OutputFormat?.ToUpper())
            {
                case "CSV":
#pragma warning disable SA1101
                    await WriteRecordAsCsvAsync(record, writer);
#pragma warning restore SA1101
                    break;
                case "JSONL":
                    await writer.WriteLineAsync(JsonSerializer.Serialize(record));
                    break;
                default: // JSON
                    await writer.WriteLineAsync(JsonSerializer.Serialize(record, new JsonSerializerOptions
                    {
                        WriteIndented = true
                    }));
                    break;
            }
#pragma warning restore SA1101
        }

        private async Task WriteRecordAsCsvAsync(UnifiedAuditLog record, StreamWriter writer)
        {
            // Implement CSV writing logic
#pragma warning disable SA1101
            var csvConfig = new CsvConfiguration(System.Globalization.CultureInfo.InvariantCulture)
            {
                HasHeaderRecord = _totalRecordsProcessed == 0
            };
#pragma warning restore SA1101

            using var csv = new CsvWriter(writer, csvConfig, true);
            csv.WriteRecord(record);
            await csv.NextRecordAsync();
        }

        private List<(DateTime Start, DateTime End)> SplitDateRange(DateTime start, DateTime end, TimeSpan chunkSize)
        {
            var chunks = new List<(DateTime, DateTime)>();
            var current = start;

            while (current < end)
            {
                var chunkEnd = current.Add(chunkSize);
                if (chunkEnd > end) chunkEnd = end;

                chunks.Add((current, chunkEnd));
                current = chunkEnd;
            }

            return chunks;
        }

        private string GetOutputFileName(DateTime start, DateTime end)
        {
            var timestamp = $"{start:yyyyMMdd_HHmmss}_{end:HHmmss}";
#pragma warning disable SA1101
            var extension = OutputFormat?.ToUpper() switch
            {
                "CSV" => "csv",
                "JSONL" => "jsonl",
                _ => "json"
            };
#pragma warning restore SA1101

#pragma warning disable SA1101
            return Path.Combine(
                OutputDirectory ?? Environment.CurrentDirectory,
                "UAL",
                $"UAL_{timestamp}_{_sessionId}.{extension}"
            );
#pragma warning restore SA1101
        }

        private async Task WriteOutputFileAsync(string fileName, MemoryStream stream)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

            stream.Position = 0;
            using var fileStream = new FileStream(fileName, FileMode.Create, FileAccess.Write, FileShare.None, 65536, true);
#pragma warning disable SA1101
            await stream.CopyToAsync(fileStream, 65536, CancellationToken);
#pragma warning restore SA1101
        }

        private async Task MergeOutputFilesAsync()
        {
#pragma warning disable SA1101
            WriteVerboseWithTimestamp("Merging output files...");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var outputDir = Path.Combine(OutputDirectory ?? Environment.CurrentDirectory, "UAL");
#pragma warning restore SA1101
#pragma warning disable SA1101
            var pattern = $"UAL_*_{_sessionId}.*";
#pragma warning restore SA1101
            var files = Directory.GetFiles(outputDir, pattern);

            if (files.Length == 0) return;

#pragma warning disable SA1101
            var mergedFileName = Path.Combine(outputDir, $"UAL_Merged_{_sessionId}.{Path.GetExtension(files[0])}");
#pragma warning restore SA1101

            using var mergedStream = new FileStream(mergedFileName, FileMode.Create, FileAccess.Write);
            using var writer = new StreamWriter(mergedStream);

            var firstFile = true;
            foreach (var file in files.OrderBy(f => f))
            {
                using var reader = new StreamReader(file);

                // Skip header for CSV files after the first
#pragma warning disable SA1101
                if (!firstFile && OutputFormat?.ToUpper() == "CSV")
                {
                    await reader.ReadLineAsync(); // Skip header
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                await reader.BaseStream.CopyToAsync(mergedStream, 65536, CancellationToken);
#pragma warning restore SA1101
                firstFile = false;
            }

            // Delete individual files after merging
            foreach (var file in files)
            {
                File.Delete(file);
            }

#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Merged {files.Length} files into {mergedFileName}");
#pragma warning restore SA1101
        }
    }
}
