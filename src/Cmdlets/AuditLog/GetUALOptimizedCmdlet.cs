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

namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
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
        public DateTime? StartDate { get; set; }

        [Parameter(
            HelpMessage = "End date for log extraction. Default: Now")]
        public DateTime? EndDate { get; set; }

        [Parameter(
            HelpMessage = "Filter by specific operations (e.g., New-InboxRule, MailItemsAccessed)")]
        public string[]? Operations { get; set; }

        [Parameter(
            HelpMessage = "Filter by record types (e.g., ExchangeItem, AzureActiveDirectory)")]
        public string[]? RecordTypes { get; set; }

        [Parameter(
            HelpMessage = "Filter by user IDs. Use '*' for all users")]
        public string[] UserIds { get; set; } = new[] { "*" };

        [Parameter(
            HelpMessage = "Filter by object IDs")]
        public string[]? ObjectIds { get; set; }

        [Parameter(
            HelpMessage = "Filter by IP address")]
        public string? IPAddress { get; set; }

        [Parameter(
            HelpMessage = "Initial time interval in hours for chunking. Default: 12")]
        [ValidateRange(0.1, 168)]
        public double IntervalHours { get; set; } = 12;

        [Parameter(
            HelpMessage = "Minimum interval in minutes when auto-adjusting. Default: 5")]
        [ValidateRange(1, 60)]
        public double MinIntervalMinutes { get; set; } = 5;

        [Parameter(
            HelpMessage = "Maximum records per API request. Default: 5000")]
        [ValidateRange(1000, 5000)]
        public int BatchSize { get; set; } = 5000;

        [Parameter(
            HelpMessage = "Maximum parallel time windows to process. Default: 10")]
        [ValidateRange(1, 50)]
        public int MaxParallelWindows { get; set; } = 10;

        [Parameter(
            HelpMessage = "Output format: CSV, JSON, JSONL. Default: JSONL")]
        [ValidateSet("CSV", "JSON", "JSONL")]
        public string OutputFormat { get; set; } = "JSONL";

        [Parameter(
            HelpMessage = "Output directory for results")]
        public string? OutputDir { get; set; }

        [Parameter(
            HelpMessage = "Merge all output files into a single file")]
        public SwitchParameter MergeOutput { get; set; }

        [Parameter(
            HelpMessage = "Enable deduplication of records")]
        public SwitchParameter Deduplicate { get; set; }

        [Parameter(
            HelpMessage = "Resume from checkpoint file")]
        public string? ResumeFrom { get; set; }

        [Parameter(
            HelpMessage = "Group filter: Exchange, Azure, SharePoint, Skype, Defender")]
        [ValidateSet("Exchange", "Azure", "SharePoint", "Skype", "Defender")]
        public string? Group { get; set; }

        [Parameter(
            HelpMessage = "Maximum retries per time window. Default: 5")]
        [ValidateRange(1, 10)]
        public int MaxRetries { get; set; } = 5;

        #endregion

        #region Private Fields

        private ExchangeRestClient? _exchangeClient;
        private readonly ConcurrentDictionary<string, bool> _processedRecordIds = new();
        private readonly ConcurrentDictionary<string, WindowState> _windowStates = new();
        private readonly Statistics _stats = new();
        private string _sessionId = string.Empty;
        private string _outputDirectory = string.Empty;
        private CheckpointManager? _checkpointManager;
        private readonly object _fileLock = new();
        private StreamWriter? _mergedWriter;
        private bool _csvHeaderWritten;

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

            if (!AuthManager.IsExchangeConnected)
            {
                throw new PSInvalidOperationException(
                    "Not connected to Exchange Online. Please run Connect-M365 -Service ExchangeOnline first.");
            }

            _exchangeClient = new ExchangeRestClient(AuthManager);
            _sessionId = Guid.NewGuid().ToString("N").Substring(0, 8);

            // Set default dates if not provided
            EndDate ??= DateTime.UtcNow;
            StartDate ??= EndDate.Value.AddDays(-180);

            // Validate date range
            if (StartDate > EndDate)
            {
                throw new PSArgumentException("StartDate cannot be after EndDate");
            }

            // Setup output directory
            SetupOutputDirectory();

            // Initialize checkpoint manager if resuming
            if (!string.IsNullOrEmpty(ResumeFrom))
            {
                _checkpointManager = new CheckpointManager(ResumeFrom);
                _checkpointManager.Load();
                Logger?.LogInfo($"Resuming from checkpoint: {ResumeFrom}");
            }

            Logger?.LogInfo("=== Starting Unified Audit Log Collection ===");
            Logger?.LogInfo($"Date Range: {StartDate:yyyy-MM-dd HH:mm:ss} to {EndDate:yyyy-MM-dd HH:mm:ss}");
            Logger?.LogInfo($"Output Format: {OutputFormat}");
            Logger?.LogInfo($"Output Directory: {_outputDirectory}");

            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
                Logger.LogDebug($"Session ID: {_sessionId}");
                Logger.LogDebug($"Interval Hours: {IntervalHours}");
                Logger.LogDebug($"Batch Size: {BatchSize}");
                Logger.LogDebug($"Max Parallel Windows: {MaxParallelWindows}");
                Logger.LogDebug($"Deduplication: {Deduplicate}");
            }
        }

        protected override void ProcessRecord()
        {
            try
            {
                var startTime = DateTime.UtcNow;

                // Build record type filter
                var recordTypesToProcess = BuildRecordTypeFilter();

                // Process audit logs
                RunAsync(ProcessAuditLogsAsync(recordTypesToProcess));

                var duration = DateTime.UtcNow - startTime;

                // Display final statistics
                DisplayStatistics(duration);

                // Merge output if requested
                if (MergeOutput)
                {
                    MergeOutputFiles().GetAwaiter().GetResult();
                }
            }
            catch (Exception ex)
            {
                Logger?.WriteErrorWithTimestamp($"Error processing audit logs: {ex.Message}", ex);
                WriteErrorWithTimestamp($"Failed to process audit logs: {ex.Message}", ex);
            }
        }

        private async Task ProcessAuditLogsAsync(List<string> recordTypes)
        {
            foreach (var recordType in recordTypes)
            {
                _stats.CurrentRecordType = recordType;

                var displayName = recordType == "*" ? "All Records" : recordType;
                WriteHost($"\n=== Processing Record Type: {displayName} ===\n", ConsoleColor.Cyan);

                // Get initial count
                var totalCount = await GetRecordCountAsync(recordType);

                if (totalCount == 0)
                {
                    WriteHost($"No records found for {displayName}\n", ConsoleColor.Yellow);
                    continue;
                }

                WriteHost($"Found {totalCount:N0} records to process\n", ConsoleColor.Green);

                // Create time windows
                var windows = CreateTimeWindows(StartDate!.Value, EndDate!.Value, totalCount);
                Logger?.LogInfo($"Created {windows.Count} time windows for processing");

                // Process windows in parallel
                await ProcessWindowsAsync(windows, recordType);
            }
        }

        private async Task<int> GetRecordCountAsync(string recordType)
        {
            try
            {
                var searchParams = BuildSearchParameters(recordType, StartDate!.Value, EndDate!.Value);
                searchParams["ResultSize"] = "1";

                var result = await _exchangeClient!.SearchUnifiedAuditLogAsync(
                    StartDate!.Value,
                    EndDate!.Value,
                    resultSize: 1,
                    recordTypes: recordType == "*" ? null : new[] { recordType },
                    userIds: UserIds?.FirstOrDefault() == "*" ? null : UserIds,
                    operations: Operations,
                    cancellationToken: CancellationToken);

                return result?.ResultCount ?? 0;
            }
            catch (Exception ex)
            {
                Logger?.WriteWarningWithTimestamp($"Failed to get record count: {ex.Message}");
                // Return a positive number to force processing
                return 1;
            }
        }

        private List<TimeWindow> CreateTimeWindows(DateTime start, DateTime end, int estimatedRecords)
        {
            var windows = new List<TimeWindow>();
            var intervalHours = IntervalHours;

            // Adjust interval based on estimated record density
            var totalHours = (end - start).TotalHours;
            var recordsPerHour = estimatedRecords / Math.Max(1, totalHours);

            if (recordsPerHour > 10000)
            {
                // High density - use smaller windows
                intervalHours = Math.Max(MinIntervalMinutes / 60.0, 1);
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
                if (_checkpointManager?.IsWindowCompleted(window.Id) == true)
                {
                    window.Status = WindowStatus.Completed;
                    _stats.WindowsCompleted++;
                }

                windows.Add(window);
                current = windowEnd;
                windowId++;
            }

            return windows;
        }

        private async Task ProcessWindowsAsync(List<TimeWindow> windows, string recordType)
        {
            var actionBlock = new ActionBlock<TimeWindow>(
                async window => await ProcessWindowAsync(window, recordType),
                new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = MaxParallelWindows,
                    CancellationToken = CancellationToken,
                    BoundedCapacity = MaxParallelWindows * 2
                });

            // Post windows to process
            foreach (var window in windows.Where(w => w.Status != WindowStatus.Completed))
            {
                await actionBlock.SendAsync(window, CancellationToken);
            }

            actionBlock.Complete();
            await actionBlock.Completion;
        }

        private async Task ProcessWindowAsync(TimeWindow window, string recordType)
        {
            var retryCount = 0;
            var success = false;

            while (!success && retryCount < MaxRetries)
            {
                try
                {
                    window.Status = WindowStatus.Processing;
                    _windowStates[window.Id] = new WindowState { Window = window };

                    WriteVerboseWithTimestamp($"Processing window {window.Id}: {window.Start:HH:mm} - {window.End:HH:mm}");

                    var windowRecords = 0;
                    var hasMoreData = true;
                    string? sessionId = null;

                    while (hasMoreData && !CancellationToken.IsCancellationRequested)
                    {
                        var result = await _exchangeClient!.SearchUnifiedAuditLogAsync(
                            window.Start,
                            window.End,
                            sessionId: sessionId,
                            operations: Operations,
                            recordTypes: recordType == "*" ? null : new[] { recordType },
                            userIds: UserIds?.FirstOrDefault() == "*" ? null : UserIds,
                            resultSize: BatchSize,
                            cancellationToken: CancellationToken);

                        if (result == null || result.Value == null || result.Value.Length == 0)
                        {
                            hasMoreData = false;
                            continue;
                        }

                        // Process records
                        var processedInBatch = await ProcessBatchAsync(result.Value, window);
                        windowRecords += processedInBatch;

                        // Update progress
                        UpdateProgress(window, windowRecords);

                        // Setup for next iteration
                        sessionId = result.SessionId;
                        hasMoreData = result.HasMoreData;

                        // Adaptive delay to avoid throttling
                        if (hasMoreData)
                        {
                            await Task.Delay(100, CancellationToken);
                        }
                    }

                    window.Status = WindowStatus.Completed;
                    window.RecordsProcessed = windowRecords;
                    _stats.WindowsCompleted++;

                    // Save checkpoint
                    _checkpointManager?.MarkWindowCompleted(window.Id);

                    WriteVerboseWithTimestamp($"Completed window {window.Id}: {windowRecords} records");
                    success = true;
                }
                catch (Exception ex)
                {
                    retryCount++;
                    window.RetryCount = retryCount;

                    if (retryCount >= MaxRetries)
                    {
                        window.Status = WindowStatus.Failed;
                        window.Error = ex.Message;
                        _stats.WindowsFailed++;

                        Logger?.WriteErrorWithTimestamp($"Window {window.Id} failed after {MaxRetries} retries: {ex.Message}", ex);
                        WriteWarning($"Failed to process window {window.Id}: {ex.Message}");
                    }
                    else
                    {
                        var delay = Math.Pow(2, retryCount) * 1000;
                        Logger?.WriteWarningWithTimestamp($"Window {window.Id} failed (attempt {retryCount}), retrying in {delay}ms: {ex.Message}");
                        await Task.Delay((int)delay, CancellationToken);

                        // Reduce window size on retry
                        if (window.End - window.Start > TimeSpan.FromMinutes(MinIntervalMinutes * 2))
                        {
                            var midpoint = window.Start.AddTicks((window.End - window.Start).Ticks / 2);
                            window.End = midpoint;
                            Logger?.LogDebug($"Reduced window {window.Id} size to {(window.End - window.Start).TotalMinutes} minutes");
                        }
                    }
                }
            }
        }

        private async Task<int> ProcessBatchAsync(UnifiedAuditLogRecord[] records, TimeWindow window)
        {
            var processedCount = 0;
            var outputFile = GetOutputFileName(window);

            using var stream = new FileStream(outputFile, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, true);
            using var writer = new StreamWriter(stream, Encoding.UTF8, 65536, false);

            foreach (var record in records)
            {
                // Deduplication
                if (Deduplicate && !string.IsNullOrEmpty(record.Id))
                {
                    if (!_processedRecordIds.TryAdd(record.Id, true))
                    {
                        _stats.DuplicatesSkipped++;
                        continue;
                    }
                }

                // Write record based on format
                await WriteRecordAsync(record, writer);
                processedCount++;
                _stats.TotalRecords++;
            }

            await writer.FlushAsync();
            return processedCount;
        }

        private async Task WriteRecordAsync(UnifiedAuditLogRecord record, StreamWriter writer)
        {
            switch (OutputFormat.ToUpper())
            {
                case "CSV":
                    await WriteCsvRecordAsync(record, writer);
                    break;

                case "JSON":
                    var json = JsonSerializer.Serialize(record, new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });
                    await writer.WriteLineAsync(json);
                    if (_stats.TotalRecords > 1) await writer.WriteLineAsync(",");
                    break;

                case "JSONL":
                    var jsonl = JsonSerializer.Serialize(record, new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    });
                    await writer.WriteLineAsync(jsonl);
                    break;
            }
        }

        private async Task WriteCsvRecordAsync(UnifiedAuditLogRecord record, StreamWriter writer)
        {
            // Write CSV header if needed
            lock (_fileLock)
            {
                if (!_csvHeaderWritten)
                {
                    writer.WriteLine("Id,RecordType,CreationTime,Operation,UserType,UserKey,Workload,ResultStatus,ObjectId,UserId,ClientIP,AuditData");
                    _csvHeaderWritten = true;
                }
            }

            var csvLine = $"\"{Escape(record.Id)}\",{record.RecordType},\"{record.CreationTime:yyyy-MM-dd HH:mm:ss}\"," +
                         $"\"{Escape(record.Operation)}\",{record.UserType},\"{Escape(record.UserKey)}\"," +
                         $"\"{Escape(record.Workload)}\",\"{Escape(record.ResultStatus)}\",\"{Escape(record.ObjectId)}\"," +
                         $"\"{Escape(record.UserId)}\",\"{Escape(record.ClientIP)}\",\"{Escape(record.AuditData)}\"";

            await writer.WriteLineAsync(csvLine);
        }

        private void UpdateProgress(TimeWindow window, int recordsProcessed)
        {
            var totalWindows = _windowStates.Count;
            var completedWindows = _windowStates.Values.Count(w => w.Window.Status == WindowStatus.Completed);
            var percentComplete = totalWindows > 0 ? (completedWindows * 100) / totalWindows : 0;

            WriteProgressSafe(
                $"Processing UAL - {_stats.CurrentRecordType}",
                $"Window {window.Id}: {recordsProcessed} records | Total: {_stats.TotalRecords:N0}",
                percentComplete);
        }

        private void SetupOutputDirectory()
        {
            if (string.IsNullOrEmpty(OutputDir))
            {
                var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
                _outputDirectory = Path.Combine("Output", "UnifiedAuditLog", timestamp);
            }
            else
            {
                _outputDirectory = OutputDir;
            }

            if (!Directory.Exists(_outputDirectory))
            {
                Directory.CreateDirectory(_outputDirectory);
            }
        }

        private string GetOutputFileName(TimeWindow window)
        {
            var extension = OutputFormat.ToLower() switch
            {
                "csv" => "csv",
                "jsonl" => "jsonl",
                _ => "json"
            };

            var fileName = $"UAL_{_sessionId}_{window.Id}_{window.Start:yyyyMMdd_HHmmss}.{extension}";
            return Path.Combine(_outputDirectory, fileName);
        }

        private async Task MergeOutputFiles()
        {
            try
            {
                WriteHost("\nMerging output files...\n", ConsoleColor.Cyan);

                var pattern = $"UAL_{_sessionId}_*.{OutputFormat.ToLower()}*";
                var files = Directory.GetFiles(_outputDirectory, pattern).OrderBy(f => f).ToArray();

                if (files.Length == 0)
                {
                    WriteWarning("No files to merge");
                    return;
                }

                var mergedFile = Path.Combine(_outputDirectory, $"UAL_Merged_{_sessionId}.{OutputFormat.ToLower()}");

                using var output = new FileStream(mergedFile, FileMode.Create, FileAccess.Write);
                using var writer = new StreamWriter(output, Encoding.UTF8);

                var firstFile = true;
                foreach (var file in files)
                {
                    using var input = new FileStream(file, FileMode.Open, FileAccess.Read);
                    using var reader = new StreamReader(input);

                    if (OutputFormat.ToUpper() == "CSV" && !firstFile)
                    {
                        // Skip header line for CSV
                        await reader.ReadLineAsync();
                    }

                    string? line;
                    while ((line = await reader.ReadLineAsync()) != null)
                    {
                        await writer.WriteLineAsync(line);
                    }

                    firstFile = false;
                }

                WriteHost($"Merged {files.Length} files into: {mergedFile}\n", ConsoleColor.Green);

                // Optionally delete individual files
                foreach (var file in files)
                {
                    File.Delete(file);
                }
            }
            catch (Exception ex)
            {
                WriteWarning($"Failed to merge files: {ex.Message}");
            }
        }

        private List<string> BuildRecordTypeFilter()
        {
            var recordTypes = new List<string>();

            if (!string.IsNullOrEmpty(Group) && GroupRecordTypes.ContainsKey(Group))
            {
                recordTypes.AddRange(GroupRecordTypes[Group]);
            }

            if (RecordTypes != null && RecordTypes.Any())
            {
                recordTypes.AddRange(RecordTypes);
            }

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

            if (Operations != null && Operations.Any())
                parameters["Operations"] = Operations;

            if (UserIds != null && UserIds.Any() && UserIds[0] != "*")
                parameters["UserIds"] = UserIds;

            if (ObjectIds != null && ObjectIds.Any())
                parameters["ObjectIds"] = ObjectIds;

            if (!string.IsNullOrEmpty(IPAddress))
                parameters["IPAddress"] = IPAddress;

            return parameters;
        }

        private void DisplayStatistics(TimeSpan duration)
        {
            WriteHost("\n=== Unified Audit Log Collection Summary ===\n", ConsoleColor.Cyan);
            WriteHost($"Duration: {duration:hh\\:mm\\:ss}\n");
            WriteHost($"Total Records Processed: {_stats.TotalRecords:N0}\n");
            WriteHost($"Windows Completed: {_stats.WindowsCompleted}\n");

            if (_stats.WindowsFailed > 0)
            {
                WriteHost($"Windows Failed: {_stats.WindowsFailed}\n", ConsoleColor.Red);
            }

            if (_stats.DuplicatesSkipped > 0)
            {
                WriteHost($"Duplicates Skipped: {_stats.DuplicatesSkipped:N0}\n", ConsoleColor.Yellow);
            }

            var recordsPerSecond = duration.TotalSeconds > 0 ? _stats.TotalRecords / duration.TotalSeconds : 0;
            WriteHost($"Processing Rate: {recordsPerSecond:N0} records/second\n");

            WriteHost($"\nOutput Directory: {_outputDirectory}\n", ConsoleColor.Green);
        }

        private static string Escape(string? value)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;

            return value.Replace("\"", "\"\"");
        }

        private void WriteHost(string message, ConsoleColor? color = null)
        {
            if (color.HasValue)
            {
                Host.UI.Write(color.Value, Host.UI.RawUI.BackgroundColor, message);
            }
            else
            {
                Host.UI.Write(message);
            }
        }

        protected override void EndProcessing()
        {
            _mergedWriter?.Dispose();
            _exchangeClient?.Dispose();
            _checkpointManager?.Save();
            base.EndProcessing();
        }

        #region Helper Classes

        private class TimeWindow
        {
            public string Id { get; set; } = string.Empty;
            public DateTime Start { get; set; }
            public DateTime End { get; set; }
            public WindowStatus Status { get; set; }
            public int EstimatedRecords { get; set; }
            public int RecordsProcessed { get; set; }
            public int RetryCount { get; set; }
            public string? Error { get; set; }
        }

        private enum WindowStatus
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
            public int TotalRecords { get; set; }
            public int WindowsCompleted { get; set; }
            public int WindowsFailed { get; set; }
            public int DuplicatesSkipped { get; set; }
            public string CurrentRecordType { get; set; } = string.Empty;
        }

        private class CheckpointManager
        {
            private readonly string _checkpointFile;
            private readonly HashSet<string> _completedWindows = new();

            public CheckpointManager(string checkpointFile)
            {
                _checkpointFile = checkpointFile;
            }

            public void Load()
            {
                if (File.Exists(_checkpointFile))
                {
                    var lines = File.ReadAllLines(_checkpointFile);
                    foreach (var line in lines)
                    {
                        _completedWindows.Add(line.Trim());
                    }
                }
            }

            public void Save()
            {
                File.WriteAllLines(_checkpointFile, _completedWindows);
            }

            public bool IsWindowCompleted(string windowId)
            {
                return _completedWindows.Contains(windowId);
            }

            public void MarkWindowCompleted(string windowId)
            {
                _completedWindows.Add(windowId);
            }
        }

        #endregion
    }
}
