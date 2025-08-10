using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core.AsyncOperations;
using Microsoft.ExtractorSuite.Core.Authentication;
using Microsoft.ExtractorSuite.Core.Logging;

namespace Microsoft.ExtractorSuite.Core
{
    /// <summary>
    /// Enhanced base cmdlet with proper async support for long-running operations
    /// Prevents blocking and provides non-blocking async execution patterns
    /// </summary>
    public abstract class AsyncBaseCmdlet : PSCmdlet, IDisposable
    {
        private CancellationTokenSource? _cancellationTokenSource;
        private AsyncTaskManager? _taskManager;
        private bool _disposed;

        protected ILogger? Logger { get; private set; }

        [Parameter]
        public LogLevel LogLevel { get; set; } = LogLevel.Standard;

        [Parameter]
        public string? OutputDirectory { get; set; }

        [Parameter]
        public SwitchParameter NoProgress { get; set; }

        [Parameter]
        public SwitchParameter Async { get; set; }

        protected AuthenticationManager AuthManager => AuthenticationManager.Instance;
        protected CancellationToken CancellationToken => _cancellationTokenSource?.Token ?? CancellationToken.None;
        protected AsyncTaskManager TaskManager => _taskManager ??= new AsyncTaskManager();

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            _cancellationTokenSource = new CancellationTokenSource();

            // Initialize logger
            Logger = new FileLogger(LogLevel, OutputDirectory ?? Environment.CurrentDirectory);
            Logger.LogInfo($"Starting cmdlet: {this.MyInvocation.MyCommand.Name}");
        }

        protected override void StopProcessing()
        {
            base.StopProcessing();
            _cancellationTokenSource?.Cancel();
            _taskManager?.CancelAllTasks();
            Logger?.LogInfo($"Stopping cmdlet: {this.MyInvocation.MyCommand.Name}");
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();

            try
            {
                var task = ProcessRecordAsync();
                task.GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Logger?.WriteErrorWithTimestamp($"Error in ProcessRecord: {ex.Message}", ex);
                WriteError(new ErrorRecord(ex, "ProcessRecordError", ErrorCategory.InvalidOperation, null));
            }
        }

        /// <summary>
        /// Override this method in derived classes to implement async processing logic
        /// </summary>
        protected virtual Task ProcessRecordAsync()
        {
            return Task.CompletedTask;
        }

        protected override void EndProcessing()
        {
            base.EndProcessing();
            Logger?.LogInfo($"Completed cmdlet: {this.MyInvocation.MyCommand.Name}");
            Dispose();
        }

        /// <summary>
        /// Runs an async operation with proper PowerShell integration
        /// Returns immediately if -Async is specified, otherwise waits for completion
        /// </summary>
        protected T RunAsyncOperation<T>(
            Func<IProgress<TaskProgress>, CancellationToken, Task<T>> operation,
            string operationName)
        {
            if (Async.IsPresent)
            {
                // Start async and return task ID for later retrieval
                var taskId = TaskManager.StartLongRunningTask(operation, this, operationName);

                var asyncResult = new PSObject();
                asyncResult.Properties.Add(new PSNoteProperty("TaskId", taskId));
                asyncResult.Properties.Add(new PSNoteProperty("OperationName", operationName));
                asyncResult.Properties.Add(new PSNoteProperty("Status", "Running"));
                asyncResult.Properties.Add(new PSNoteProperty("StartTime", DateTime.UtcNow));

                WriteObject(asyncResult);

                // Return default value since we're running async
                return default(T)!;
            }
            else
            {
                // Run synchronously with progress updates
                return RunAsyncWithProgress(operation, operationName);
            }
        }

        /// <summary>
        /// Runs async operation synchronously with progress reporting
        /// Uses proper async patterns without blocking the thread pool
        /// </summary>
        private T RunAsyncWithProgress<T>(
            Func<IProgress<TaskProgress>, CancellationToken, Task<T>> operation,
            string operationName)
        {
            // Create a dedicated thread for the async operation to avoid deadlocks
            T result = default(T)!;
            Exception? exception = null;

            var thread = new System.Threading.Thread(() =>
            {
                try
                {
                    // Create a new SynchronizationContext for this thread
                    SynchronizationContext.SetSynchronizationContext(new SynchronizationContext());

                    var progress = new Progress<TaskProgress>(p =>
                    {
                        if (!NoProgress.IsPresent)
                        {
                            WriteProgressSafe(operationName, p.CurrentOperation ?? "Processing...", p.PercentComplete);
                        }
                    });

                    var task = operation(progress, CancellationToken);
                    result = task.GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    exception = ex;
                }
            })
            {
                IsBackground = false,
                Name = $"AsyncOperation_{operationName}"
            };

            thread.Start();
            thread.Join();

            if (exception != null)
            {
                throw exception;
            }

            return result;
        }

        /// <summary>
        /// Executes multiple async operations in parallel with controlled concurrency
        /// </summary>
        protected async Task<IEnumerable<T>> RunParallelOperationsAsync<T>(
            IEnumerable<Func<CancellationToken, Task<T>>> operations,
            int maxConcurrency = 10,
            string operationName = "Parallel Operation")
        {
            return await TaskManager.ExecuteParallelAsync(operations, this, maxConcurrency, operationName);
        }

        /// <summary>
        /// Streams results from an async enumerable directly to the PowerShell pipeline
        /// </summary>
        protected async Task StreamResultsAsync<T>(
            IAsyncEnumerable<T> source,
            string operationName,
            Action<T>? processItem = null)
        {
            var count = 0;
            var lastProgressUpdate = DateTime.UtcNow;

            await foreach (var item in source.WithCancellation(CancellationToken))
            {
                // Process item if handler provided
                processItem?.Invoke(item);

                // Write to pipeline
                WriteObject(item);

                count++;

                // Update progress periodically (every 100ms)
                if ((DateTime.UtcNow - lastProgressUpdate).TotalMilliseconds > 100)
                {
                    if (!NoProgress.IsPresent)
                    {
                        WriteVerboseWithTimestamp($"{operationName}: Processed {count} items");
                    }
                    lastProgressUpdate = DateTime.UtcNow;
                }
            }

            WriteVerboseWithTimestamp($"{operationName}: Completed. Total items: {count}");
        }

        /// <summary>
        /// Safe progress writing that handles hosts that don't support progress
        /// </summary>
        protected void WriteProgressSafe(string activity, string statusDescription, int percentComplete)
        {
            if (NoProgress.IsPresent) return;

            try
            {
                var progressRecord = new ProgressRecord(0, activity, statusDescription)
                {
                    PercentComplete = percentComplete
                };
                WriteProgress(progressRecord);
            }
            catch
            {
                // Some hosts don't support progress - ignore
            }
        }

        protected void WriteVerboseWithTimestamp(string message)
        {
            WriteVerbose($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] {message}");
            Logger?.LogDebug(message);
        }

        protected void WriteWarningWithTimestamp(string message)
        {
            WriteWarning($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] {message}");
            Logger?.WriteWarningWithTimestamp(message);
        }

        protected void WriteErrorWithTimestamp(string message, Exception? exception = null)
        {
            var errorRecord = new ErrorRecord(
                exception ?? new InvalidOperationException(message),
                "ExtractorSuiteError",
                ErrorCategory.InvalidOperation,
                null);

            WriteError(errorRecord);
            Logger?.WriteErrorWithTimestamp(message, exception);
        }

        protected bool RequireGraphConnection()
        {
            if (!AuthManager.IsGraphConnected)
            {
                WriteErrorWithTimestamp("Not connected to Microsoft Graph. Please run Connect-M365 first.");
                return false;
            }
            return true;
        }

        protected bool RequireAzureConnection()
        {
            if (!AuthManager.IsAzureConnected)
            {
                WriteErrorWithTimestamp("Not connected to Azure. Please run Connect-AzureAZ first.");
                return false;
            }
            return true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _cancellationTokenSource?.Dispose();
                    _taskManager?.Dispose();
                    Logger?.Dispose();
                }
                _disposed = true;
            }
        }
    }
}
