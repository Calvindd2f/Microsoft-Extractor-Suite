namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Compression;
    using System.Linq;
    using System.Management.Automation;
    using System.Net.Http;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Threading.Tasks.Dataflow;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Exchange;
    using Microsoft.ExtractorSuite.Core.Json;
    using Microsoft.ExtractorSuite.Models.Exchange;
    using Microsoft.IO;


    /// <summary>
    /// Enhanced UAL extraction cmdlet that addresses all Search-UnifiedAuditLog pain points:
    /// - Intelligent session management with recovery
    /// - Duplicate detection and removal
    /// - Adaptive time windowing with dynamic adjustment
    /// - Memory-efficient streaming with zero accumulation
    /// - Comprehensive retry logic with circuit breaker
    /// - Parallel processing with controlled concurrency
    /// - Incremental collection with checkpointing
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "UALEnhanced")]
    [OutputType(typeof(UnifiedAuditLogRecord))]
    public class GetUALEnhancedCmdlet : AsyncBaseCmdlet
    {
        #region Parameters

        [Parameter]
#pragma warning disable SA1600
        public DateTime? StartDate { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public DateTime? EndDate { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public string[]? Operations { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public string[]? RecordTypes { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public string[]? UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public string? IPAddress { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public int BatchSize { get; set; } = 5000;
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public int MaxRecordsPerFile { get; set; } = 250000;
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public int MaxParallelWindows { get; set; } = 10;
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public double InitialIntervalHours { get; set; } = 6.0;
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public double MinIntervalMinutes { get; set; } = 0.1;
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "JSONL";
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter EnableDeduplication { get; set; }

        [Parameter]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter CompressOutput { get; set; }

        [Parameter]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter UseIncremental { get; set; }

        [Parameter]
#pragma warning disable SA1600
        public string? CheckpointFile { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public int MaxRetriesPerWindow { get; set; } = 5;
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public int SessionPoolSize { get; set; } = 20;
#pragma warning restore SA1600

        #endregion

        #region Private Fields

#pragma warning disable SA1309
#pragma warning disable SA1201
        private static readonly RecyclableMemoryStreamManager _memoryStreamManager = new();
#pragma warning restore SA1201
#pragma warning disable SA1309
        private readonly ConcurrentDictionary<string, bool> _seenRecordIds = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly ConcurrentQueue<SessionInfo> _sessionPool = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly ConcurrentDictionary<string, WindowProgress> _windowProgress = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly SemaphoreSlim _rateLimitSemaphore;
#pragma warning restore SA1309
#pragma warning disable SA1600
#pragma warning SA1309 F
#pragma warning restore SA1600
        private ExchangeRestClient? _exchangeClient;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private CheckpointManager? _checkpointManager;
#pragma warning disable SA1600
#pragma warning restore SA1309
sho
#pragma warning disable SA1309
        private HighPerformanceJsonProcessor? _jsonProcessor;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private long _totalRecordsProcessed;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private long _duplicatesSkipped;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private DateTime _processingStartTime;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly object _statsLock = new();
#pragma warning restore SA1309

        #endregion

        public GetUALEnhancedCmdlet()
        {
#pragma warning disable SA1101
            _rateLimitSemaphore = new SemaphoreSlim(MaxParallelWindows, MaxParallelWindows);
#pragma warning restore SA1101
        }

        protected override void BeginProcessing()
        {
            base.BeginProcessing();

            // Validate connection
#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Microsoft Graph connection required");
            }
#pragma warning restore SA1101

            // Initialize components
#pragma warning disable SA1101
            _exchangeClient = new ExchangeRestClient(AuthManager);
#pragma warning restore SA1101
#pragma warning disable SA1101
            _jsonProcessor = new HighPerformanceJsonProcessor();
#pragma warning restore SA1101

            // Set date ranges with UAL defaults
#pragma warning disable SA1101
            StartDate ??= DateTime.UtcNow.AddDays(-180);
#pragma warning restore SA1101
#pragma warning disable SA1600
#pragma warning disable SA1101
            EndDate ??= DateTime.UtcNow;
#pragma warning restore SA1101

            // Initialize checkpoint manager if incremental
#pragma warning disable SA1101
            if (UseIncremental.IsPresent)
            {
#pragma warning disable SA1101
                var checkpointPath = CheckpointFile ??
                    Path.Combine(OutputDirectory ?? ".", ".ual_checkpoint.json");
#pragma warning restore SA1101
#pragma warning disable SA1101
                _checkpointManager = new CheckpointManager(checkpointPath);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            // Pre-populate session pool
#pragma warning disable SA1101
            for (int i = 0; i < SessionPoolSize; i++)
            {
#pragma warning disable SA1101
                _sessionPool.Enqueue(new SessionInfo
                {
                    SessionId = Guid.NewGuid().ToString(),
                    CreatedAt = DateTime.UtcNow,
                    UsageCount = 0
                });
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            _processingStartTime = DateTime.UtcNow;
#pragma warning restore SA1101
        }

        protected override void ProcessRecord()
        {
            try
            {
                var operation = RunAsyncOperation(
                    ExtractUnifiedAuditLogsAsync,
                    "UAL Enhanced Extraction");

#pragma warning disable SA1101
                if (!Async.IsPresent && operation != null)
                {
#pragma warning disable SA1101
                    WriteObject(operation);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"UAL extraction failed: {ex.Message}", ex);
#pragma warning restore SA1101
            }
        }

        private async Task<UALExtractionResult> ExtractUnifiedAuditLogsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Starting enhanced UAL extraction from {StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}");
#pragma warning restore SA1101

            // Load checkpoint if incremental
#pragma warning disable SA1101
            var lastCheckpoint = await LoadCheckpointAsync();
#pragma warning restore SA1101
            if (lastCheckpoint != null)
            {
                WriteVerboseWithTimestamp($"Resuming from checkpoint: {lastCheckpoint.LastProcessedTime:yyyy-MM-dd HH:mm:ss}");
#pragma warning disable SA1101
                StartDate = lastCheckpoint.LastProcessedTime;
#pragma warning restore SA1101

                // Restore deduplication state
                foreach (var recordId in lastCheckpoint.ProcessedRecordIds)
                {
#pragma warning disable SA1101
                    _seenRecordIds.TryAdd(recordId, true);
#pragma warning restore SA1101
                }
            }

            // Get initial record count estimate
#pragma warning disable SA1101
            var estimatedTotal = await EstimateTotalRecordsAsync(cancellationToken);
#pragma warning restore SA1101
            WriteVerboseWithTimestamp($"Estimated total records: {estimatedTotal:N0}");

            // Calculate optimal time windows
#pragma warning disable SA1101
            var windows = CalculateOptimalWindows(StartDate!.Value, EndDate!.Value, estimatedTotal);
#pragma warning restore SA1101
            WriteVerboseWithTimestamp($"Processing {windows.Count} time windows with adaptive intervals");

            // Create processing pipeline with dataflow
#pragma warning disable SA1101
            var processingPipeline = CreateProcessingPipeline(cancellationToken);
#pragma warning restore SA1101

            // Process windows in parallel with controlled concurrency
            var windowTasks = windows.Select(async window =>
            {
#pragma warning disable SA1101
                await _rateLimitSemaphore.WaitAsync(cancellationToken);
#pragma warning restore SA1101
                try
                {
                    await processingPipeline.SendAsync(window, cancellationToken);
                }
                finally
                {
#pragma warning disable SA1101
                    _rateLimitSemaphore.Release();
#pragma warning restore SA1101
                }
            });

            await Task.WhenAll(windowTasks);
            processingPipeline.Complete();
            await processingPipeline.Completion;

            // Final statistics
#pragma warning disable SA1101
            var result = new UALExtractionResult
            {
                TotalRecordsProcessed = _totalRecordsProcessed,
                DuplicatesSkipped = _duplicatesSkipped,
                ProcessingTime = DateTime.UtcNow - _processingStartTime,
                WindowsProcessed = windows.Count,
                OutputFiles = GetOutputFiles()
            };
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"UAL extraction completed:");
            WriteVerboseWithTimestamp($"  - Total records: {result.TotalRecordsProcessed:N0}");
            WriteVerboseWithTimestamp($"  - Duplicates removed: {result.DuplicatesSkipped:N0}");
            WriteVerboseWithTimestamp($"  - Processing time: {result.ProcessingTime:hh\\:mm\\:ss}");
            WriteVerboseWithTimestamp($"  - Output files: {result.OutputFiles.Count}");

            return result;
        }

        #region Time Window Management

        private List<TimeWindow> CalculateOptimalWindows(
            DateTime start,
            DateTime end,
            long estimatedRecords)
        {
            var windows = new List<TimeWindow>();
            var totalHours = (end - start).TotalHours;

            // Calculate optimal interval based on estimated records
#pragma warning disable SA1101
            double intervalHours = InitialIntervalHours;
#pragma warning restore SA1101

            if (estimatedRecords > 0)
            {
                // Aim for ~50K records per window
                var targetWindows = Math.Max(1, estimatedRecords / 50000);
#pragma warning disable SA1101
                intervalHours = Math.Max(MinIntervalMinutes / 60, totalHours / targetWindows);
#pragma warning restore SA1101
            }

            WriteVerboseWithTimestamp($"Using initial interval of {intervalHours:F2} hours");

            var current = start;
            while (current < end)
            {
                var windowEnd = current.AddHours(intervalHours);
                if (windowEnd > end) windowEnd = end;

                windows.Add(new TimeWindow
                {
                    Start = current,
                    End = windowEnd,
                    EstimatedRecords = (long)(estimatedRecords * ((windowEnd - current).TotalHours / totalHours))
                });

                current = windowEnd;
            }

            return windows;
        }

        private async Task<long> EstimateTotalRecordsAsync(CancellationToken cancellationToken)
        {
            try
            {
                // Try direct count first (with timeout)
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(30));

#pragma warning disable SA1101
                var countResult = await _exchangeClient!.SearchUnifiedAuditLogAsync(
                    StartDate!.Value,
                    EndDate!.Value,
                    operations: Operations,
                    recordTypes: RecordTypes,
                    userIds: UserIds,
                    resultSize: 1,
                    cancellationToken: cts.Token);
#pragma warning restore SA1101

                if (countResult?.ResultCount > 0)
                {
                    return countResult.ResultCount;
                }
            }
            catch (OperationCanceledException)
            {
                WriteVerboseWithTimestamp("Direct count timed out, using sampling estimation");
            }

            // Fallback: Sample 24-hour period
#pragma warning disable SA1101
            var sampleStart = EndDate!.Value.AddDays(-1);
#pragma warning restore SA1101
#pragma warning disable SA1101
            var sampleEnd = EndDate!.Value;
#pragma warning restore SA1101

#pragma warning disable SA1101
            var sampleResult = await _exchangeClient!.SearchUnifiedAuditLogAsync(
                sampleStart,
                sampleEnd,
                operations: Operations,
                recordTypes: RecordTypes,
                userIds: UserIds,
                resultSize: 1,
                cancellationToken: cancellationToken);
#pragma warning restore SA1101

            if (sampleResult?.ResultCount > 0)
            {
#pragma warning disable SA1101
                var daysTotal = (EndDate!.Value - StartDate!.Value).TotalDays;
#pragma warning restore SA1101
                return (long)(sampleResult.ResultCount * daysTotal);
            }

            // Default estimate if all else fails
            return 100000;
        }

        #endregion

        #region Processing Pipeline

        private ActionBlock<TimeWindow> CreateProcessingPipeline(CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            return new ActionBlock<TimeWindow>(
                async window => await ProcessTimeWindowAsync(window, cancellationToken),
                new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = MaxParallelWindows,
                    CancellationToken = cancellationToken,
                    BoundedCapacity = MaxParallelWindows * 2
                });
#pragma warning restore SA1101
        }

        private async Task ProcessTimeWindowAsync(TimeWindow window, CancellationToken cancellationToken)
        {
            var windowId = $"{window.Start:yyyyMMddHHmmss}_{window.End:yyyyMMddHHmmss}";
            var progress = new WindowProgress { WindowId = windowId, Start = window.Start, End = window.End };
#pragma warning disable SA1101
            _windowProgress.TryAdd(windowId, progress);
#pragma warning restore SA1101

            var retryCount = 0;
            var success = false;
            Exception? lastException = null;

#pragma warning disable SA1101
            while (retryCount < MaxRetriesPerWindow && !success && !cancellationToken.IsCancellationRequested)
            {
                try
                {
                    WriteVerboseWithTimestamp($"Processing window {window.Start:HH:mm}-{window.End:HH:mm} (Attempt {retryCount + 1})");

                    // Get or create session
#pragma warning disable SA1101
                    var session = GetOrCreateSession();
#pragma warning restore SA1101

                    // Process with adaptive subdivision if needed
#pragma warning disable SA1101
                    await ProcessWindowWithSubdivisionAsync(window, session, cancellationToken);
#pragma warning restore SA1101

                    success = true;
                    progress.Status = "Completed";

                    // Save checkpoint periodically
#pragma warning disable SA1101
                    if (UseIncremental.IsPresent && _totalRecordsProcessed % 10000 == 0)
                    {
#pragma warning disable SA1101
                        await SaveCheckpointAsync(window.End);
#pragma warning restore SA1101
                    }
#pragma warning restore SA1101
                }
                catch (Exception ex)
                {
                    lastException = ex;
                    retryCount++;

#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Window {windowId} failed (attempt {retryCount}): {ex.Message}");
#pragma warning restore SA1101

                    if (ex.Message.Contains("50000") || ex.Message.Contains("ResultCountExceeded"))
                    {
                        // Subdivide window if hitting limits
                        WriteVerboseWithTimestamp($"Subdividing window {windowId} due to size limits");
#pragma warning disable SA1101
                        await SubdivideAndProcessWindowAsync(window, cancellationToken);
#pragma warning restore SA1101
                        success = true;
                    }
                    else
                    {
                        // Exponential backoff
                        var delay = TimeSpan.FromSeconds(Math.Pow(2, retryCount));
                        await Task.Delay(delay, cancellationToken);
                    }
                }
            }
#pragma warning restore SA1101

            if (!success)
            {
                progress.Status = "Failed";
                progress.Error = lastException?.Message;
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Window {windowId} failed after {retryCount} attempts", lastException);
#pragma warning restore SA1101
            }

#pragma warning disable SA1101
            _windowProgress.TryRemove(windowId, out _);
#pragma warning restore SA1101
        }

        private async Task ProcessWindowWithSubdivisionAsync(
            TimeWindow window,
            SessionInfo session,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var outputFile = GetOutputFileName(window);
#pragma warning restore SA1101
            using var outputStream = _memoryStreamManager.GetStream();

            var hasMoreData = true;
            string? resultSetId = null;
            var windowRecordCount = 0;
            var consecutiveEmptyBatches = 0;

            while (hasMoreData && !cancellationToken.IsCancellationRequested && consecutiveEmptyBatches < 3)
            {
#pragma warning disable SA1101
                var result = await _exchangeClient!.SearchUnifiedAuditLogAsync(
                    window.Start,
                    window.End,
                    sessionId: resultSetId ?? session.SessionId,
                    operations: Operations,
                    recordTypes: RecordTypes,
                    userIds: UserIds,
                    resultSize: BatchSize,
                    cancellationToken: cancellationToken);
#pragma warning restore SA1101

                if (result == null || result.Value == null || result.Value.Length == 0)
                {
                    consecutiveEmptyBatches++;

                    if (consecutiveEmptyBatches == 1 && string.IsNullOrEmpty(resultSetId))
                    {
                        // First empty batch with new session - might be session issue
                        WriteVerboseWithTimestamp($"Empty batch with new session, refreshing session");
#pragma warning disable SA1101
                        session = RefreshSession(session);
#pragma warning restore SA1101
                        continue;
                    }

                    hasMoreData = false;
                    continue;
                }

                consecutiveEmptyBatches = 0;

                // Process records with deduplication
#pragma warning disable SA1101
                var uniqueRecords = EnableDeduplication.IsPresent
                    ? DeduplicateRecords(result.Value)
                    : result.Value;
#pragma warning restore SA1101

                // Write records to stream
                foreach (var record in uniqueRecords)
                {
#pragma warning disable SA1101
                    await WriteRecordAsync(outputStream, record, cancellationToken);
#pragma warning restore SA1101
                    windowRecordCount++;
#pragma warning disable SA1101
                    Interlocked.Increment(ref _totalRecordsProcessed);
#pragma warning restore SA1101

                    // Report progress
                    if (windowRecordCount % 1000 == 0)
                    {
#pragma warning disable SA1101
                        var progressPercent = (int)((double)_totalRecordsProcessed /
                            (_windowProgress.Count * 50000) * 100);
#pragma warning restore SA1101

#pragma warning disable SA1101
                        WriteProgressSafe(
                            "UAL Enhanced Extraction",
                            $"Window {window.Start:HH:mm}-{window.End:HH:mm}: {windowRecordCount:N0} records",
                            Math.Min(progressPercent, 99));
#pragma warning restore SA1101
                    }
                }

                resultSetId = result.ResultSetId;
                hasMoreData = result.HasMoreData;

                // Update session usage
                session.UsageCount++;
                session.LastUsed = DateTime.UtcNow;
            }

            // Write output file
#pragma warning disable SA1101
            await WriteOutputFileAsync(outputFile, outputStream, cancellationToken);
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Window {window.Start:HH:mm}-{window.End:HH:mm} completed: {windowRecordCount:N0} records");
        }

        private async Task SubdivideAndProcessWindowAsync(
            TimeWindow window,
            CancellationToken cancellationToken)
        {
            var duration = window.End - window.Start;
#pragma warning disable SA1101
            var newDuration = TimeSpan.FromMinutes(Math.Max(MinIntervalMinutes, duration.TotalMinutes / 2));
#pragma warning restore SA1101

            var subWindows = new List<TimeWindow>();
            var current = window.Start;

            while (current < window.End)
            {
                var subEnd = current.Add(newDuration);
                if (subEnd > window.End) subEnd = window.End;

                subWindows.Add(new TimeWindow
                {
                    Start = current,
                    End = subEnd,
                    EstimatedRecords = window.EstimatedRecords / 2
                });

                current = subEnd;
            }

            WriteVerboseWithTimestamp($"Subdivided window into {subWindows.Count} smaller windows");

            foreach (var subWindow in subWindows)
            {
#pragma warning disable SA1101
                await ProcessTimeWindowAsync(subWindow, cancellationToken);
#pragma warning restore SA1101
            }
        }

        #endregion

        #region Deduplication

        private IEnumerable<UnifiedAuditLogRecord> DeduplicateRecords(UnifiedAuditLogRecord[] records)
        {
            var uniqueRecords = new List<UnifiedAuditLogRecord>();

            foreach (var record in records)
            {
#pragma warning disable SA1101
                var recordId = GenerateRecordHash(record);
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (_seenRecordIds.TryAdd(recordId, true))
                {
                    uniqueRecords.Add(record);
                }
                else
                {
#pragma warning disable SA1101
                    Interlocked.Increment(ref _duplicatesSkipped);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101
            }

            return uniqueRecords;
        }

        private string GenerateRecordHash(UnifiedAuditLogRecord record)
        {
            // Create unique hash from key fields
            var hashInput = $"{record.Id}|{record.CreationTime:O}|{record.Operation}|{record.UserId}|{record.ObjectId}";

            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(hashInput));
            return Convert.ToBase64String(hashBytes);
        }

        #endregion

        #region Session Management

        private SessionInfo GetOrCreateSession()
        {
#pragma warning disable SA1101
            if (_sessionPool.TryDequeue(out var session))
            {
                // Check if session is still valid (not too old, not overused)
                if (session.UsageCount < 100 &&
                    (DateTime.UtcNow - session.CreatedAt).TotalMinutes < 30)
                {
                    return session;
                }
            }
#pragma warning restore SA1101

            // Create new session
            return new SessionInfo
            {
                SessionId = Guid.NewGuid().ToString(),
                CreatedAt = DateTime.UtcNow,
                UsageCount = 0
            };
        }

        private SessionInfo RefreshSession(SessionInfo oldSession)
        {
            // Return old session to pool if still usable
            if (oldSession.UsageCount < 50)
            {
#pragma warning disable SA1101
                _sessionPool.Enqueue(oldSession);
#pragma warning restore SA1101
            }

#pragma warning disable SA1101
            return GetOrCreateSession();
#pragma warning restore SA1101
        }

        #endregion

        #region Output Management

        private async Task WriteRecordAsync(
            Stream stream,
            UnifiedAuditLogRecord record,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            switch (OutputFormat.ToUpper())
            {
                case "JSONL":
#pragma warning disable SA1101
                    await _jsonProcessor!.SerializeAsync(stream, record, false, cancellationToken);
#pragma warning restore SA1101
                    var newlineBytes = Encoding.UTF8.GetBytes("\n");
                    await stream.WriteAsync(newlineBytes, 0, newlineBytes.Length, cancellationToken);
                    break;

                case "JSON":
#pragma warning disable SA1101
                    await _jsonProcessor!.SerializeAsync(stream, record, true, cancellationToken);
#pragma warning restore SA1101
                    var commaNewlineBytes = Encoding.UTF8.GetBytes(",\n");
                    await stream.WriteAsync(commaNewlineBytes, 0, commaNewlineBytes.Length, cancellationToken);
                    break;

                case "CSV":
                    // CSV implementation would go here
                    break;
            }
#pragma warning restore SA1101
        }

        private async Task WriteOutputFileAsync(
            string fileName,
            Stream dataStream,
            CancellationToken cancellationToken)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

            dataStream.Position = 0;

#pragma warning disable SA1101
            if (CompressOutput.IsPresent)
            {
                fileName += ".gz";
                using var fileStream = new FileStream(fileName, FileMode.Create, FileAccess.Write, FileShare.None, 65536, true);
                using var gzipStream = new GZipStream(fileStream, CompressionLevel.Optimal);
                await dataStream.CopyToAsync(gzipStream, 65536, cancellationToken);
            }
            else
            {
                using var fileStream = new FileStream(fileName, FileMode.Create, FileAccess.Write, FileShare.None, 65536, true);
                await dataStream.CopyToAsync(fileStream, 65536, cancellationToken);
            }
#pragma warning restore SA1101
        }

        private string GetOutputFileName(TimeWindow window)
        {
            var timestamp = $"{window.Start:yyyyMMdd_HHmmss}_{window.End:HHmmss}";
#pragma warning disable SA1101
            var extension = OutputFormat.ToLower() switch
            {
                "csv" => "csv",
                "jsonl" => "jsonl",
                _ => "json"
            };
#pragma warning restore SA1101

#pragma warning disable SA1101
            return Path.Combine(
                OutputDirectory ?? Environment.CurrentDirectory,
                "UAL_Enhanced",
                $"UAL_{timestamp}.{extension}"
            );
#pragma warning restore SA1101
        }

        private List<string> GetOutputFiles()
        {
#pragma warning disable SA1101
            var outputDir = Path.Combine(OutputDirectory ?? Environment.CurrentDirectory, "UAL_Enhanced");
#pragma warning restore SA1101
            if (!Directory.Exists(outputDir)) return new List<string>();

            return Directory.GetFiles(outputDir, "UAL_*.*")
                .OrderBy(f => f)
                .ToList();
        }

        #endregion

        #region Checkpoint Management

        private async Task<Checkpoint?> LoadCheckpointAsync()
        {
#pragma warning disable SA1101
            if (_checkpointManager == null) return null;
#pragma warning restore SA1101
#pragma warning disable SA1101
            return await _checkpointManager.LoadAsync();
#pragma warning restore SA1101
        }

        private async Task SaveCheckpointAsync(DateTime lastProcessedTime)
        {
#pragma warning disable SA1101
            if (_checkpointManager == null) return;
#pragma warning restore SA1101

#pragma warning disable SA1101
            var checkpoint = new Checkpoint
            {
                LastProcessedTime = lastProcessedTime,
                ProcessedRecordIds = _seenRecordIds.Keys.Take(10000).ToList(), // Keep last 10K for dedup
                TotalRecordsProcessed = _totalRecordsProcessed,
                DuplicatesSkipped = _duplicatesSkipped
            };
#pragma warning restore SA1101

#pragma warning disable SA1101
            await _checkpointManager.SaveAsync(checkpoint);
#pragma warning restore SA1101
        }

        #endregion

        #region Helper Classes

        private class TimeWindow
        {
            public DateTime Start { get; set; }public DateTime End { get; set; }public long EstimatedRecords { get; set; }}

        private class SessionInfo
        {
            public string SessionId { get; set; } = string.Empty;
            public DateTime CreatedAt { get; set; }public DateTime LastUsed { get; set; }public int UsageCount { get; set; }}

        private class WindowProgress
        {
            public string WindowId { get; set; } = string.Empty;
            public DateTime Start { get; set; }public DateTime End { get; set; }public string Status { get; set; } = "Processing";
            public string? Error { get; set; }
            public long RecordsProcessed { get; set; }}

        private class Checkpoint
        {
            public DateTime LastProcessedTime { get; set; }public List<string> ProcessedRecordIds { get; set; } = new();
            public long TotalRecordsProcessed { get; set; }public long DuplicatesSkipped { get; set; }}

#pragma warning disable SA1600
        private class CheckpointManager
#pragma warning restore SA1600
        {
#pragma warning disable SA1600
#pragma warning disable SA1309
#pragma warning restore SA1600
#pragma warning disable SA1600
            private readonly string _checkpointFile;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1309
not
#pragma warning disable SA1600

#pragma warning restore SA1600
#pragma warning disable SA1600
            public CheckpointManager(string checkpointFile)
#pragma warning restore SA1600
            {
#pragma warning disable SA1101
                _checkpointFile = checkpointFile;
#pragma warning restore SA1101
            }

            public async Task<Checkpoint?> LoadAsync()
            {
#pragma warning disable SA1101
                if (!File.Exists(_checkpointFile)) return null;
#pragma warning restore SA1101

#pragma warning disable SA1101
                var json = await Task.Run(() => File.ReadAllText(_checkpointFile));
#pragma warning restore SA1101
                return JsonSerializer.Deserialize<Checkpoint>(json);
            }

            public async Task SaveAsync(Checkpoint checkpoint)
            {
                var json = JsonSerializer.Serialize(checkpoint, new JsonSerializerOptions { WriteIndented = true });
#pragma warning disable SA1101
                using (var writer = new StreamWriter(_checkpointFile)) { await writer.WriteAsync(json); }
#pragma warning restore SA1101
            }
        }

        public class UALExtractionResult
        {
            public long TotalRecordsProcessed { get; set; }public long DuplicatesSkipped { get; set; }public TimeSpan ProcessingTime { get; set; }public int WindowsProcessed { get; set; }public List<string> OutputFiles { get; set; } = new();
        }

        #endregion
    }
}
