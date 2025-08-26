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

    public class GetUALCmdlet : BaseCmdlet

    {

        private static readonly RecyclableMemoryStreamManager _memoryStreamManager = new();



        private readonly HttpClient _httpClient

new();


        [Parameter(Mandatory = true)]


        public DateTime StartDate { get; set; }
        [Parameter(Mandatory = true)]


        public DateTime EndDate { get; set; }
        [Parameter]

        public string[]? Operations { get; set; }


        [Parameter]

        public string[]? RecordTypes { get; set; }


        [Parameter]

        public string[]? UserIds { get; set; }


        [Parameter]

        public string? IPAddress { get; set; }


        [Parameter]

        public int BatchSize { get; set; } = 5000;


        [Parameter]

        public string? OutputFormat { get; set; } = "JSON";


        [Parameter]

        public SwitchParameter MergeOutput { get; set; }[Parameter]
        public int MaxParallelRequests { get; set; } = 10;



sho


        private string? _sessionId;


        private int _totalRecordsProcessed;


        private readonly object _writeLock = new();


        protected override void BeginProcessing()
        {
            base.BeginProcessing();




            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Microsoft Graph connection required");
            }



            _sessionId = Guid.NewGuid().ToString();


            _totalRecordsProcessed = 0;

        }

        protected override void ProcessRecord()
        {
            try
            {

                WriteVerboseWithTimestamp($"Starting UAL extraction from {StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}");



                var extractionTask = ExtractUnifiedAuditLogsAsync();


                RunAsync(extractionTask);



                WriteVerboseWithTimestamp($"UAL extraction completed. Total records processed: {_totalRecordsProcessed}");

            }
            catch (Exception ex)
            {

                WriteErrorWithTimestamp($"UAL extraction failed: {ex.Message}", ex);

            }
        }

        private async Task ExtractUnifiedAuditLogsAsync()
        {
            // Get Exchange Online token

            var token = await AuthManager.GetExchangeOnlineTokenAsync(CancellationToken);

            if (string.IsNullOrEmpty(token))
            {
                throw new InvalidOperationException("Failed to get Exchange Online token");
            }


            _httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", token);


            // Split date range into smaller chunks for parallel processing

            var dateChunks = SplitDateRange(StartDate, EndDate, TimeSpan.FromHours(6));


            // Process chunks in parallel with controlled concurrency

            var semaphore = new System.Threading.SemaphoreSlim(MaxParallelRequests);

            var tasks = dateChunks.Select(async chunk =>
            {

                await semaphore.WaitAsync(CancellationToken);

                try
                {

                    await ProcessDateChunkAsync(chunk.Start, chunk.End);

                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);

            // Merge output files if requested

            if (MergeOutput.IsPresent)
            {

                await MergeOutputFilesAsync();

            }

        }

        private async Task ProcessDateChunkAsync(DateTime chunkStart, DateTime chunkEnd)
        {

            var outputFileName = GetOutputFileName(chunkStart, chunkEnd);

            using var outputStream = _memoryStreamManager.GetStream();
            using var writer = new StreamWriter(outputStream, Encoding.UTF8, 65536, true);

            var hasMoreData = true;
            string? resultSetId = null;
            var chunkRecordCount = 0;


            while (hasMoreData && !CancellationToken.IsCancellationRequested)
            {

                var requestBody = BuildRequestBody(chunkStart, chunkEnd, resultSetId);


                var response = await SendAuditLogRequestAsync(requestBody);


                if (response == null || response.ResultCount == 0)
                {
                    hasMoreData = false;
                    continue;
                }

                // Process records with memory-efficient streaming
                foreach (var record in response.Results)
                {

                    await ProcessRecordAsync(record, writer);

                    chunkRecordCount++;

                    if (chunkRecordCount % 1000 == 0)
                    {

                        WriteProgressSafe(
                            $"Processing UAL chunk {chunkStart:HH:mm}-{chunkEnd:HH:mm}",
                            $"Records processed: {chunkRecordCount}",
                            -1);

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


            await writer.FlushAsync();

            // Write to file

            await WriteOutputFileAsync(outputFileName, outputStream);



            lock (_writeLock)
            {

                _totalRecordsProcessed += chunkRecordCount;

            }



            WriteVerboseWithTimestamp($"Completed chunk {chunkStart:HH:mm}-{chunkEnd:HH:mm}: {chunkRecordCount} records");

        }

        private async Task<AuditLogResponse?> SendAuditLogRequestAsync(string requestBody)
        {
            try
            {
                var content = new StringContent(requestBody, Encoding.UTF8, "application/json");

                var tenantId = AuthManager.CurrentTenantId ?? throw new InvalidOperationException("Tenant ID not available");


                var response = await _httpClient.PostAsync(
                    $"https://outlook.office365.com/adminapi/beta/{tenantId}/ActivityFeed/SearchAuditLog",
                    content,
                    CancellationToken);


                if (!response.IsSuccessStatusCode)
                {
                    var error = await response.Content.ReadAsStringAsync();

                    WriteWarningWithTimestamp($"API request failed: {response.StatusCode} - {error}");

                    return null;
                }

                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<AuditLogResponse>(json)
                    ?? throw new InvalidOperationException("Failed to deserialize audit log response");
            }
            catch (HttpRequestException ex)
            {

                WriteWarningWithTimestamp($"HTTP request failed: {ex.Message}");

                return null;
            }
            catch (TaskCanceledException)
            {

                WriteWarningWithTimestamp("Request timeout or cancelled");

                return null;
            }
        }

        private string BuildRequestBody(DateTime start, DateTime end, string? resultSetId)
        {

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


            return JsonSerializer.Serialize(request);
        }

        private async Task ProcessRecordAsync(UnifiedAuditLog record, StreamWriter writer)
        {

            switch (OutputFormat?.ToUpper())
            {
                case "CSV":

                    await WriteRecordAsCsvAsync(record, writer);

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

        }

        private async Task WriteRecordAsCsvAsync(UnifiedAuditLog record, StreamWriter writer)
        {
            // Implement CSV writing logic

            var csvConfig = new CsvConfiguration(System.Globalization.CultureInfo.InvariantCulture)
            {
                HasHeaderRecord = _totalRecordsProcessed == 0
            };


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

            var extension = OutputFormat?.ToUpper() switch
            {
                "CSV" => "csv",
                "JSONL" => "jsonl",
                _ => "json"
            };



            return Path.Combine(
                OutputDirectory ?? Environment.CurrentDirectory,
                "UAL",
                $"UAL_{timestamp}_{_sessionId}.{extension}"
            );

        }

        private async Task WriteOutputFileAsync(string fileName, MemoryStream stream)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

            stream.Position = 0;
            using var fileStream = new FileStream(fileName, FileMode.Create, FileAccess.Write, FileShare.None, 65536, true);

            await stream.CopyToAsync(fileStream, 65536, CancellationToken);

        }

        private async Task MergeOutputFilesAsync()
        {

            WriteVerboseWithTimestamp("Merging output files...");



            var outputDir = Path.Combine(OutputDirectory ?? Environment.CurrentDirectory, "UAL");


            var pattern = $"UAL_*_{_sessionId}.*";

            var files = Directory.GetFiles(outputDir, pattern);

            if (files.Length == 0) return;


            var mergedFileName = Path.Combine(outputDir, $"UAL_Merged_{_sessionId}.{Path.GetExtension(files[0])}");


            using var mergedStream = new FileStream(mergedFileName, FileMode.Create, FileAccess.Write);
            using var writer = new StreamWriter(mergedStream);

            var firstFile = true;
            foreach (var file in files.OrderBy(f => f))
            {
                using var reader = new StreamReader(file);

                // Skip header for CSV files after the first

                if (!firstFile && OutputFormat?.ToUpper() == "CSV")
                {
                    await reader.ReadLineAsync(); // Skip header
                }



                await reader.BaseStream.CopyToAsync(mergedStream, 65536, CancellationToken);

                firstFile = false;
            }

            // Delete individual files after merging
            foreach (var file in files)
            {
                File.Delete(file);
            }


            WriteVerboseWithTimestamp($"Merged {files.Length} files into {mergedFileName}");

        }
    }
}
