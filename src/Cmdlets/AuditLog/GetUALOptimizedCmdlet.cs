namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Text;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Threading.Tasks.Dataflow;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Exchange;
    using Microsoft.ExtractorSuite.Core.Logging;
    using Microsoft.ExtractorSuite.Models.Exchange;


    /// <summary>
    /// Optimized Unified Audit Log extraction cmdlet.
    /// Addresses all Search-UnifiedAuditLog limitations with enterprise-grade features.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "UALOptimized")]
    [OutputType(typeof(UnifiedAuditLogRecord))]
    [Alias("Get-UAL")]
    public class GetUALOptimizedCmdlet : BaseCmdlet
    {
        #region Parameters

        [Parameter(
            HelpMessage = "Start date for log extraction. Default: -180 days from today")]
#pragma warning disable SA1600
        public DateTime? StartDate { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "End date for log extraction. Default: Now")]
#pragma warning disable SA1600
        public DateTime? EndDate { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Filter by specific operations (e.g., New-InboxRule, MailItemsAccessed)")]
#pragma warning disable SA1600
        public string[]? Operations { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Filter by record types (e.g., ExchangeItem, AzureActiveDirectory)")]
#pragma warning disable SA1600
        public string[]? RecordTypes { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Filter by user IDs. Use '*' for all users")]
#pragma warning disable SA1600
        public string[] UserIds { get; set; } = new[] { "*" };
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Filter by object IDs")]
#pragma warning disable SA1600
        public string[]? ObjectIds { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Filter by IP address")]
#pragma warning disable SA1600
        public string? IPAddress { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Initial time interval in hours for chunking. Default: 12")]
        [ValidateRange(0.1, 168)]
#pragma warning disable SA1600
        public double IntervalHours { get; set; } = 12;
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Minimum interval in minutes when auto-adjusting. Default: 5")]
        [ValidateRange(1, 60)]
#pragma warning disable SA1600
        public double MinIntervalMinutes { get; set; } = 5;
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Maximum records per API request. Default: 5000")]
        [ValidateRange(1000, 5000)]
#pragma warning disable SA1600
        public int BatchSize { get; set; } = 5000;
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Maximum parallel time windows to process. Default: 10")]
        [ValidateRange(1, 50)]
#pragma warning disable SA1600
        public int MaxParallelWindows { get; set; } = 10;
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output format: CSV, JSON, JSONL. Default: JSONL")]
        [ValidateSet("CSV", "JSON", "JSONL")]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "JSONL";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output directory for results")]
#pragma warning disable SA1600
        public string? OutputDir { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Merge all output files into a single file")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter MergeOutput { get; set; }

        [Parameter(
            HelpMessage = "Enable deduplication of records")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter Deduplicate { get; set; }

        [Parameter(
            HelpMessage = "Resume from checkpoint file")]
#pragma warning disable SA1600
        public string? ResumeFrom { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Group filter: Exchange, Azure, SharePoint, Skype, Defender")]
        [ValidateSet("Exchange", "Azure", "SharePoint", "Skype", "Defender")]
#pragma warning disable SA1600
        public string? Group { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Maximum retries per time window. Default: 5")]
        [ValidateRange(1, 10)]
#pragma warning disable SA1600
        public int MaxRetries { get; set; } = 5;
#pragma warning restore SA1600

        #endregion

        #region Private Fields

#pragma warning disable SA1309
#pragma warning disable SA1201
        private ExchangeRestClient? _exchangeClient;
#pragma warning restore SA1201
#pragma warning disable SA1309
        private readonly ConcurrentDictionary<string, bool> _processedRecordIds = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly ConcurrentDictionary<string, WindowState> _windowStates = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly Statistics _stats = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private string _sessionId = string.Empty;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private string _outputDirectory = string.Empty;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private CheckpointManager? _checkpointManager;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly object _fileLock = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private StreamWriter? _mergedWriter;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private bool _csvHeaderWritten;
#pragma warning restore SA1309

        private static readonly Dictionary<string, string[]> GroupRecordTypes = new()
        {
            ["Exchange"] = new[] {
                "ExchangeAdmin", "ExchangeAggregatedOperation", "ExchangeItem",
                "ExchangeItemGroup", "ExchangeItemAggregated", "ComplianceDLPExchange",
                "ComplianceSupervisionExchange", "MipAutoLabelExchangeItem", "ExchangeSearch"
            },
            ["Azure"] = new[] {
                "AzureActiveDirectory", "AzureActiveDirectoryAccountLogon",
                "AzureActiveDirectoryStsLogon"
            },
            ["SharePoint"] = new[] {
                "ComplianceDLPSharePoint", "SharePoint", "SharePointFileOperation",
                "SharePointSharingOperation", "SharepointListOperation",
                "SharePointCommentOperation", "SharePointListItemOperation"
            },
            ["Skype"] = new[] {
                "SkypeForBusinessCmdlets", "SkypeForBusinessPSTNUsage",
                "SkypeForBusinessUsersBlocked"
            },
            ["Defender"] = new[] {
                "ThreatIntelligence", "ThreatFinder", "ThreatIntelligenceUrl",
                "Campaign", "AirInvestigation", "WDATPAlerts", "MCASAlerts"
            }
        };

        #endregion

        protected override void BeginProcessing()
        {
            base.BeginProcessing();

#pragma warning disable SA1101
            if (!AuthManager.IsExchangeConnected)
            {
                throw new PSInvalidOperationException(
                    "Not connected to Exchange Online. Please run Connect-M365 -Service ExchangeOnline first.");
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            _exchangeClient = new ExchangeRestClient(AuthManager);
#pragma warning restore SA1101
#pragma warning disable SA1101
            _sessionId = Guid.NewGuid().ToString("N").Substring(0, 8);
#pragma warning restore SA1101

            // Set default dates if not provided
#pragma warning disable SA1101
            EndDate ??= DateTime.UtcNow;
#pragma warning restore SA1101
#pragma warning disable SA1101
            StartDate ??= EndDate.Value.AddDays(-180);
#pragma warning restore SA1101

            // Validate date range
#pragma warning disable SA1101
            if (StartDate > EndDate)
            {
                throw new PSArgumentException("StartDate cannot be after EndDate");
            }
#pragma warning restore SA1101

            // Setup output directory
#pragma warning disable SA1101
            SetupOutputDirectory();
#pragma warning restore SA1101

            // Initialize checkpoint manager if resuming
#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(ResumeFrom))
            {
#pragma warning disable SA1600
#pragma warning disable SA1101
                _checkpointManager = new CheckpointManager(ResumeFrom);
#pragma warning restore SA1101
#pragma warning disable SA1101
                _checkpointManager.Load();
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger?.LogInfo($"Resuming from checkpoint: {ResumeFrom}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            Logger?.LogInfo("=== Starting Unified Audit Log Collection ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.LogInfo($"Date Range: {StartDate:yyyy-MM-dd HH:mm:ss} to {EndDate:yyyy-MM-dd HH:mm:ss}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.LogInfo($"Output Format: {OutputFormat}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.LogInfo($"Output Directory: {_outputDirectory}");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
#pragma warning disable SA1101
                Logger.LogDebug($"Session ID: {_sessionId}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"Interval Hours: {IntervalHours}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"Batch Size: {BatchSize}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"Max Parallel Windows: {MaxParallelWindows}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"Deduplication: {Deduplicate}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        protected override void ProcessRecord()
        {
            try
            {
                var startTime = DateTime.UtcNow;

                // Build record type filter
#pragma warning disable SA1101
                var recordTypesToProcess = BuildRecordTypeFilter();
#pragma warning restore SA1101

                // Process audit logs
#pragma warning disable SA1101
                RunAsync(ProcessAuditLogsAsync(recordTypesToProcess));
#pragma warning restore SA1101

                var duration = DateTime.UtcNow - startTime;

                // Display final statistics
#pragma warning disable SA1101
                DisplayStatistics(duration);
#pragma warning restore SA1101

                // Merge output if requested
#pragma warning disable SA1101
                if (MergeOutput)
                {
                    // Run on thread pool to avoid STA thread issues
#pragma warning disable SA1101
                    Task.Run(async () => await MergeOutputFiles().ConfigureAwait(false))
                        .GetAwaiter().GetResult();
#pragma warning restore SA1101
                }
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                Logger?.WriteErrorWithTimestamp($"Error processing audit logs: {ex.Message}", ex);
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to process audit logs: {ex.Message}", ex);
#pragma warning restore SA1101
            }
        }

        private async Task ProcessAuditLogsAsync(List<string> recordTypes)
        {
            foreach (var recordType in recordTypes)
            {
#pragma warning disable SA1101
                _stats.CurrentRecordType = recordType;
#pragma warning restore SA1101

                var displayName = recordType == "*" ? "All Records" : recordType;
#pragma warning disable SA1101
                WriteHost($"\n=== Processing Record Type: {displayName} ===\n", ConsoleColor.Cyan);
#pragma warning restore SA1101

                // Get initial count
#pragma warning disable SA1101
                var totalCount = await GetRecordCountAsync(recordType);
#pragma warning restore SA1101

                if (totalCount == 0)
                {
#pragma warning disable SA1101
                    WriteHost($"No records found for {displayName}\n", ConsoleColor.Yellow);
#pragma warning restore SA1101
                    continue;
                }

#pragma warning disable SA1101
                WriteHost($"Found {totalCount:N0} records to process\n", ConsoleColor.Green);
#pragma warning restore SA1101

                // Create time windows
#pragma warning disable SA1101
                var windows = CreateTimeWindows(StartDate!.Value, EndDate!.Value, totalCount);
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger?.LogInfo($"Created {windows.Count} time windows for processing");
#pragma warning restore SA1101

                // Process windows in parallel
#pragma warning disable SA1101
                await ProcessWindowsAsync(windows, recordType);
#pragma warning restore SA1101
            }
        }

        private async Task<int> GetRecordCountAsync(string recordType)
        {
            try
            {
#pragma warning disable SA1101
                var searchParams = BuildSearchParameters(recordType, StartDate!.Value, EndDate!.Value);
#pragma warning restore SA1101
                searchParams["ResultSize"] = "1";

#pragma warning disable SA1101
                var result = await _exchangeClient!.SearchUnifiedAuditLogAsync(
                    StartDate!.Value,
                    EndDate!.Value,
                    resultSize: 1,
                    recordTypes: recordType == "*" ? null : new[] { recordType },
                    userIds: UserIds?.FirstOrDefault() == "*" ? null : UserIds,
                    operations: Operations,
                    cancellationToken: CancellationToken);
#pragma warning restore SA1101

                return result?.ResultCount ?? 0;
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                Logger?.WriteWarningWithTimestamp($"Failed to get record count: {ex.Message}");
#pragma warning restore SA1101
                // Return a positive number to force processing
                return 1;
            }
        }

        private List<TimeWindow> CreateTimeWindows(DateTime start, DateTime end, int estimatedRecords)
        {
            var windows = new List<TimeWindow>();
#pragma warning disable SA1101
            var intervalHours = IntervalHours;
#pragma warning restore SA1101

            // Adjust interval based on estimated record density
            var totalHours = (end - start).TotalHours;
            var recordsPerHour = estimatedRecords / Math.Max(1, totalHours);

            if (recordsPerHour > 10000)
            {
                // High density - use smaller windows
#pragma warning disable SA1101
                intervalHours = Math.Max(MinIntervalMinutes / 60.0, 1);
#pragma warning restore SA1101
            }
            else if (recordsPerHour > 1000)
            {
                // Medium density
                intervalHours = Math.Min(intervalHours, 6);
            }

            var current = start;
            var windowId = 0;

            while (current < end)
            {
                var windowEnd = current.AddHours(intervalHours);
                if (windowEnd > end) windowEnd = end;

                var window = new TimeWindow
                {
                    Id = $"W{windowId:D4}",
                    Start = current,
                    End = windowEnd,
                    EstimatedRecords = (int)(recordsPerHour * (windowEnd - current).TotalHours)
                };

                // Check if already processed (for resume)
#pragma warning disable SA1101
                if (_checkpointManager?.IsWindowCompleted(window.Id) == true)
                {
                    window.Status = WindowStatus.Completed;
#pragma warning disable SA1101
                    _stats.WindowsCompleted++;
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                windows.Add(window);
                current = windowEnd;
                windowId++;
            }

            return windows;
        }

        private async Task ProcessWindowsAsync(List<TimeWindow> windows, string recordType)
        {
#pragma warning disable SA1101
            var actionBlock = new ActionBlock<TimeWindow>(
                async window => await ProcessWindowAsync(window, recordType),
                new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = MaxParallelWindows,
                    CancellationToken = CancellationToken,
                    BoundedCapacity = MaxParallelWindows * 2
                });
#pragma warning restore SA1101

            // Post windows to process
            foreach (var window in windows.Where(w => w.Status != WindowStatus.Completed))
            {
#pragma warning disable SA1101
                await actionBlock.SendAsync(window, CancellationToken);
#pragma warning restore SA1101
            }

            actionBlock.Complete();
            await actionBlock.Completion;
        }

        private async Task ProcessWindowAsync(TimeWindow window, string recordType)
        {
            var retryCount = 0;
            var success = false;

#pragma warning disable SA1101
            while (!success && retryCount < MaxRetries)
            {
                try
                {
                    window.Status = WindowStatus.Processing;
#pragma warning disable SA1101
                    _windowStates[window.Id] = new WindowState { Window = window };
#pragma warning restore SA1101

#pragma warning disable SA1101
                    WriteVerboseWithTimestamp($"Processing window {window.Id}: {window.Start:HH:mm} - {window.End:HH:mm}");
#pragma warning restore SA1101

                    var windowRecords = 0;
                    var hasMoreData = true;
                    string? sessionId = null;

#pragma warning disable SA1101
                    while (hasMoreData && !CancellationToken.IsCancellationRequested)
                    {
#pragma warning disable SA1101
                        var result = await _exchangeClient!.SearchUnifiedAuditLogAsync(
                            window.Start,
                            window.End,
                            sessionId: sessionId,
                            operations: Operations,
                            recordTypes: recordType == "*" ? null : new[] { recordType },
                            userIds: UserIds?.FirstOrDefault() == "*" ? null : UserIds,
                            resultSize: BatchSize,
                            cancellationToken: CancellationToken);
#pragma warning restore SA1101

                        if (result == null || result.Value == null || result.Value.Length == 0)
                        {
                            hasMoreData = false;
                            continue;
                        }

                        // Process records
#pragma warning disable SA1101
                        var processedInBatch = await ProcessBatchAsync(result.Value, window);
#pragma warning restore SA1101
                        windowRecords += processedInBatch;

                        // Update progress
#pragma warning disable SA1101
                        UpdateProgress(window, windowRecords);
#pragma warning restore SA1101

                        // Setup for next iteration
                        sessionId = result.SessionId;
                        hasMoreData = result.HasMoreData;

                        // Adaptive delay to avoid throttling
                        if (hasMoreData)
                        {
#pragma warning disable SA1101
                            await Task.Delay(100, CancellationToken);
#pragma warning restore SA1101
                        }
                    }
#pragma warning restore SA1101

                    window.Status = WindowStatus.Completed;
                    window.RecordsProcessed = windowRecords;
#pragma warning disable SA1101
                    _stats.WindowsCompleted++;
#pragma warning restore SA1101

                    // Save checkpoint
#pragma warning disable SA1101
                    _checkpointManager?.MarkWindowCompleted(window.Id);
#pragma warning restore SA1101

#pragma warning disable SA1101
                    WriteVerboseWithTimestamp($"Completed window {window.Id}: {windowRecords} records");
#pragma warning restore SA1101
                    success = true;
                }
                catch (Exception ex)
                {
                    retryCount++;
                    window.RetryCount = retryCount;

#pragma warning disable SA1101
                    if (retryCount >= MaxRetries)
                    {
                        window.Status = WindowStatus.Failed;
                        window.Error = ex.Message;
#pragma warning disable SA1101
                        _stats.WindowsFailed++;
#pragma warning restore SA1101

#pragma warning disable SA1101
                        Logger?.WriteErrorWithTimestamp($"Window {window.Id} failed after {MaxRetries} retries: {ex.Message}", ex);
#pragma warning restore SA1101
#pragma warning disable SA1101
                        WriteWarning($"Failed to process window {window.Id}: {ex.Message}");
#pragma warning restore SA1101
                    }
                    else
                    {
                        var delay = Math.Pow(2, retryCount) * 1000;
#pragma warning disable SA1101
                        Logger?.WriteWarningWithTimestamp($"Window {window.Id} failed (attempt {retryCount}), retrying in {delay}ms: {ex.Message}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                        await Task.Delay((int)delay, CancellationToken);
#pragma warning restore SA1101

                        // Reduce window size on retry
#pragma warning disable SA1101
                        if (window.End - window.Start > TimeSpan.FromMinutes(MinIntervalMinutes * 2))
                        {
                            var midpoint = window.Start.AddTicks((window.End - window.Start).Ticks / 2);
                            window.End = midpoint;
#pragma warning disable SA1101
                            Logger?.LogDebug($"Reduced window {window.Id} size to {(window.End - window.Start).TotalMinutes} minutes");
#pragma warning restore SA1101
                        }
#pragma warning restore SA1101
                    }
#pragma warning restore SA1101
                }
            }
#pragma warning restore SA1101
        }

        private async Task<int> ProcessBatchAsync(UnifiedAuditLogRecord[] records, TimeWindow window)
        {
            var processedCount = 0;
#pragma warning disable SA1101
            var outputFile = GetOutputFileName(window);
#pragma warning restore SA1101

            using var stream = new FileStream(outputFile, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, true);
            using var writer = new StreamWriter(stream, Encoding.UTF8, 65536, false);

            foreach (var record in records)
            {
                // Deduplication
#pragma warning disable SA1101
                if (Deduplicate && !string.IsNullOrEmpty(record.Id))
                {
#pragma warning disable SA1101
                    if (!_processedRecordIds.TryAdd(record.Id, true))
                    {
#pragma warning disable SA1101
                        _stats.DuplicatesSkipped++;
#pragma warning restore SA1101
                        continue;
                    }
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                // Write record based on format
#pragma warning disable SA1101
                await WriteRecordAsync(record, writer);
#pragma warning restore SA1101
                processedCount++;
#pragma warning disable SA1101
                _stats.TotalRecords++;
#pragma warning restore SA1101
            }

            await writer.FlushAsync();
            return processedCount;
        }

        private async Task WriteRecordAsync(UnifiedAuditLogRecord record, StreamWriter writer)
        {
#pragma warning disable SA1101
            switch (OutputFormat.ToUpper())
            {
                case "CSV":
#pragma warning disable SA1101
                    await WriteCsvRecordAsync(record, writer);
#pragma warning restore SA1101
                    break;

                case "JSON":
                    var json = JsonSerializer.Serialize(record, new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });
                    await writer.WriteLineAsync(json);
#pragma warning disable SA1101
                    if (_stats.TotalRecords > 1) await writer.WriteLineAsync(",");
#pragma warning restore SA1101
                    break;

                case "JSONL":
                    var jsonl = JsonSerializer.Serialize(record, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });
                    await writer.WriteLineAsync(jsonl);
                    break;
            }
#pragma warning restore SA1101
        }

        private async Task WriteCsvRecordAsync(UnifiedAuditLogRecord record, StreamWriter writer)
        {
            // Write CSV header if needed
#pragma warning disable SA1101
            lock (_fileLock)
            {
#pragma warning disable SA1101
                if (!_csvHeaderWritten)
                {
                    writer.WriteLine("Id,RecordType,CreationTime,Operation,UserType,UserKey,Workload,ResultStatus,ObjectId,UserId,ClientIP,AuditData");
#pragma warning disable SA1101
                    _csvHeaderWritten = true;
#pragma warning restore SA1101
                }
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            var csvLine = $"\"{Escape(record.Id)}\",{record.RecordType},\"{record.CreationTime:yyyy-MM-dd HH:mm:ss}\"," +
                         $"\"{Escape(record.Operation)}\",{record.UserType},\"{Escape(record.UserKey)}\"," +
                         $"\"{Escape(record.Workload)}\",\"{Escape(record.ResultStatus)}\",\"{Escape(record.ObjectId)}\"," +
                         $"\"{Escape(record.UserId)}\",\"{Escape(record.ClientIP)}\",\"{Escape(record.AuditData)}\"";

            await writer.WriteLineAsync(csvLine);
        }

        private void UpdateProgress(TimeWindow window, int recordsProcessed)
        {
#pragma warning disable SA1101
            var totalWindows = _windowStates.Count;
#pragma warning restore SA1101
#pragma warning disable SA1101
            var completedWindows = _windowStates.Values.Count(w => w.Window.Status == WindowStatus.Completed);
#pragma warning restore SA1101
            var percentComplete = totalWindows > 0 ? (completedWindows * 100) / totalWindows : 0;

#pragma warning disable SA1101
            WriteProgressSafe(
                $"Processing UAL - {_stats.CurrentRecordType}",
                $"Window {window.Id}: {recordsProcessed} records | Total: {_stats.TotalRecords:N0}",
                percentComplete);
#pragma warning restore SA1101
        }

        private void SetupOutputDirectory()
        {
#pragma warning disable SA1101
            if (string.IsNullOrEmpty(OutputDir))
            {
                var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
#pragma warning disable SA1101
                _outputDirectory = Path.Combine("Output", "UnifiedAuditLog", timestamp);
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                _outputDirectory = OutputDir;
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!Directory.Exists(_outputDirectory))
            {
#pragma warning disable SA1101
                Directory.CreateDirectory(_outputDirectory);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        private string GetOutputFileName(TimeWindow window)
        {
#pragma warning disable SA1101
            var extension = OutputFormat.ToLower() switch
            {
                "csv" => "csv",
                "jsonl" => "jsonl",
                _ => "json"
            };
#pragma warning restore SA1101

#pragma warning disable SA1101
            var fileName = $"UAL_{_sessionId}_{window.Id}_{window.Start:yyyyMMdd_HHmmss}.{extension}";
#pragma warning restore SA1101
#pragma warning disable SA1101
            return Path.Combine(_outputDirectory, fileName);
#pragma warning restore SA1101
        }

        private async Task MergeOutputFiles()
        {
            try
            {
#pragma warning disable SA1101
                WriteHost("\nMerging output files...\n", ConsoleColor.Cyan);
#pragma warning restore SA1101

#pragma warning disable SA1101
                var pattern = $"UAL_{_sessionId}_*.{OutputFormat.ToLower()}*";
#pragma warning restore SA1101
#pragma warning disable SA1101
                var files = Directory.GetFiles(_outputDirectory, pattern).OrderBy(f => f).ToArray();
#pragma warning restore SA1101

                if (files.Length == 0)
                {
#pragma warning disable SA1101
                    WriteWarning("No files to merge");
#pragma warning restore SA1101
                    return;
                }

#pragma warning disable SA1101
                var mergedFile = Path.Combine(_outputDirectory, $"UAL_Merged_{_sessionId}.{OutputFormat.ToLower()}");
#pragma warning restore SA1101

                using var output = new FileStream(mergedFile, FileMode.Create, FileAccess.Write);
                using var writer = new StreamWriter(output, Encoding.UTF8);

                var firstFile = true;
                foreach (var file in files)
                {
                    using var input = new FileStream(file, FileMode.Open, FileAccess.Read);
                    using var reader = new StreamReader(input);

#pragma warning disable SA1101
                    if (OutputFormat.ToUpper() == "CSV" && !firstFile)
                    {
                        // Skip header line for CSV
                        await reader.ReadLineAsync();
                    }
#pragma warning restore SA1101

                    string? line;
                    while ((line = await reader.ReadLineAsync()) != null)
                    {
                        await writer.WriteLineAsync(line);
                    }

                    firstFile = false;
                }

#pragma warning disable SA1101
                WriteHost($"Merged {files.Length} files into: {mergedFile}\n", ConsoleColor.Green);
#pragma warning restore SA1101

                // Optionally delete individual files
                foreach (var file in files)
                {
                    File.Delete(file);
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteWarning($"Failed to merge files: {ex.Message}");
#pragma warning restore SA1101
            }
        }

        private List<string> BuildRecordTypeFilter()
        {
            var recordTypes = new List<string>();

#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(Group) && GroupRecordTypes.ContainsKey(Group))
            {
#pragma warning disable SA1101
                recordTypes.AddRange(GroupRecordTypes[Group]);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (RecordTypes != null && RecordTypes.Any())
            {
#pragma warning disable SA1101
                recordTypes.AddRange(RecordTypes);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            if (!recordTypes.Any())
            {
                recordTypes.Add("*");
            }

            return recordTypes.Distinct().ToList();
        }

        private Dictionary<string, object> BuildSearchParameters(string recordType, DateTime start, DateTime end)
        {
            var parameters = new Dictionary<string, object>
            {
                ["StartDate"] = start,
                ["EndDate"] = end
            };

            if (recordType != "*")
                parameters["RecordType"] = recordType;

#pragma warning disable SA1101
            if (Operations != null && Operations.Any())
#pragma warning disable SA1101
                parameters["Operations"] = Operations;
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (UserIds != null && UserIds.Any() && UserIds[0] != "*")
#pragma warning disable SA1101
                parameters["UserIds"] = UserIds;
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (ObjectIds != null && ObjectIds.Any())
#pragma warning disable SA1101
                parameters["ObjectIds"] = ObjectIds;
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(IPAddress))
#pragma warning disable SA1101
                parameters["IPAddress"] = IPAddress;
#pragma warning restore SA1101

            return parameters;
        }

        private void DisplayStatistics(TimeSpan duration)
        {
#pragma warning disable SA1101
            WriteHost("\n=== Unified Audit Log Collection Summary ===\n", ConsoleColor.Cyan);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Duration: {duration:hh\\:mm\\:ss}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Total Records Processed: {_stats.TotalRecords:N0}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Windows Completed: {_stats.WindowsCompleted}\n");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.WindowsFailed > 0)
            {
#pragma warning disable SA1101
                WriteHost($"Windows Failed: {_stats.WindowsFailed}\n", ConsoleColor.Red);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.DuplicatesSkipped > 0)
            {
#pragma warning disable SA1101
                WriteHost($"Duplicates Skipped: {_stats.DuplicatesSkipped:N0}\n", ConsoleColor.Yellow);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            var recordsPerSecond = duration.TotalSeconds > 0 ? _stats.TotalRecords / duration.TotalSeconds : 0;
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Processing Rate: {recordsPerSecond:N0} records/second\n");
#pragma warning restore SA1101

#pragma warning disable SA1101
            WriteHost($"\nOutput Directory: {_outputDirectory}\n", ConsoleColor.Green);
#pragma warning restore SA1101
        }

#pragma warning disable SA1600
        private static string Escape(string? va
#pragma warning restore SA1600
documentedlue)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;

            return value.Replace("\"", "\"\"");
        }

        private void WriteHost(string message, ConsoleColor? color = null)
        {
            if (color.HasValue)
            {
#pragma warning disable SA1101
                Host.UI.Write(color.Value, Host.UI.RawUI.BackgroundColor, message);
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                Host.UI.Write(message);
#pragma warning restore SA1101
            }
        }

        protected override void EndProcessing()
        {
#pragma warning disable SA1101
            _mergedWriter?.Dispose();
#pragma warning restore SA1101
#pragma warning disable SA1101
            _exchangeClient?.Dispose();
#pragma warning restore SA1101
#pragma warning disable SA1101
            _checkpointManager?.Save();
#pragma warning restore SA1101
            base.EndProcessing();
        }

        #region Helper Classes

        private class TimeWindow
        {
            public string Id { get; set; } = string.Empty;
            public DateTime Start { get; set; }public DateTime End { get; set; }public WindowStatus Status { get; set; }public int EstimatedRecords { get; set; }public int RecordsProcessed { get; set; }public int RetryCount { get; set; }public string? Error { get; set; }
        }

#pragma warning disable SA1201
        private enum WindowStatus
#pragma warning restore SA1201
        {
            Pending,
            Processing,
            Completed,
            Failed
        }

        private class WindowState
        {
            public TimeWindow Window { get; set; } = new();
            public DateTime LastUpdate { get; set; } = DateTime.UtcNow;
        }

        private class Statistics
        {
            public int TotalRecords { get; set; }public int WindowsCompleted { get; set; }public int WindowsFailed { get; set; }public int DuplicatesSkipped { get; set; }public string CurrentRecordType { get; set; } = string.Empty;
        }

        private class CheckpointManager
        {
#pragma warning disable SA1309
            private readonly string _checkpointFile;
#pragma warning restore SA1309
#pragma warning disable SA1309
            private readonly HashSet<string> _completedWindows = new();
#pragma warning restore SA1309

            public CheckpointManager(string checkpointFile)
            {
#pragma warning disable SA1101
                _checkpointFile = checkpointFile;
#pragma warning restore SA1101
            }

            public void Load()
            {
#pragma warning disable SA1101
                if (File.Exists(_checkpointFile))
                {
#pragma warning disable SA1101
                    var lines = File.ReadAllLines(_checkpointFile);
#pragma warning restore SA1101
                    foreach (var line in lines)
                    {
#pragma warning disable SA1101
                        _completedWindows.Add(line.Trim());
#pragma warning restore SA1101
                    }
                }
#pragma warning restore SA1101
            }

            public void Save()
            {
#pragma warning disable SA1101
                File.WriteAllLines(_checkpointFile, _completedWindows);
#pragma warning restore SA1101
            }

            public bool IsWindowCompleted(string windowId)
            {
#pragma warning disable SA1101
                return _completedWindows.Contains(windowId);
#pragma warning restore SA1101
            }

            public void MarkWindowCompleted(string windowId)
            {
#pragma warning disable SA1101
                _completedWindows.Add(windowId);
#pragma warning restore SA1101
            }
        }

        #endregion
    }
}
