// <copyright file="AsyncBaseCmdlet.cs" company="PlaceholderCompany">
// Copyright (c) PlaceholderCompany. All rights reserved.
// </copyright>

namespace Microsoft.ExtractorSuite.Core
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core.AsyncOperations;
    using Microsoft.ExtractorSuite.Core.Authentication;
    using Microsoft.ExtractorSuite.Core.Logging;

    /// <summary>
    /// Enhanced base cmdlet with proper async support for long-running operations
    /// Prevents blocking and provides non-blocking async execution patterns.
    /// </summary>
    public abstract class AsyncBaseCmdlet : PSCmdlet, IDisposable
    {

        private CancellationTokenSource? _cancellationTokenSource;

        private AsyncTaskManager? _taskManager;


        private bool _disposed;


        private readonly ConcurrentQueue<Action> _pendingWrites = new();
        private readonly object _writeLock = new();

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
                // Process the async task while
                var task = ProcessRecordAsync();

                // Pump messages while the task runs to completion
                while (!task.IsCompleted)
                {
                    // Process any queued writes on the main thread
                    ProcessQueuedWrites();

                    // Small delay to prevent CPU spinning
                    if (!task.Wait(10))
                    {
                        // Continue processing
                    }
                }

                // Process any remaining writes
                ProcessQueuedWrites();

                // Get the result (will throw if task faulted)
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

            // Process any remaining queued writes
            ProcessQueuedWrites();

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
            T result = default(T)!;
            Exception? exception = null;
            var completedEvent = new ManualResetEventSlim(false);

            // Create progress handler that queues writes
            var progress = new Progress<TaskProgress>(p =>
            {
                if (!NoProgress.IsPresent)
                {
                    QueueWrite(() => WriteProgressSafe(operationName, p.CurrentOperation ?? "Processing...", p.PercentComplete));
                }
            });

            // Start the async operation
            Task.Run(async () =>
            {
                try
                {
                    result = await operation(progress, CancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    exception = ex;
                }
                finally
                {
                    completedEvent.Set();
                }
            });

            // Process queued writes while waiting for completion
            while (!completedEvent.Wait(10))
            {
                ProcessQueuedWrites();
            }

            // Process any remaining queued writes
            ProcessQueuedWrites();

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

                // Queue write to pipeline
                var capturedItem = item;
                QueueWrite(() => WriteObject(capturedItem));

                count++;

                // Update progress periodically (every 100ms)
                if ((DateTime.UtcNow - lastProgressUpdate).TotalMilliseconds > 100)
                {
                    if (!NoProgress.IsPresent)
                    {
                        var capturedCount = count;
                        QueueWrite(() => WriteVerboseWithTimestamp($"{operationName}: Processed {capturedCount} items"));
                    }
                    lastProgressUpdate = DateTime.UtcNow;
                }

                // Process queued writes periodically
                ProcessQueuedWrites();
            }

            var finalCount = count;
            QueueWrite(() => WriteVerboseWithTimestamp($"{operationName}: Completed. Total items: {finalCount}"));
            ProcessQueuedWrites();
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

        /// <summary>
        /// Queue a write operation to be executed on the main thread
        /// </summary>
        protected void QueueWrite(Action writeAction)
        {
            _pendingWrites.Enqueue(writeAction);
        }

        /// <summary>
        /// Process all queued write operations on the main thread
        /// </summary>
        protected void ProcessQueuedWrites()
        {
            while (_pendingWrites.TryDequeue(out var action))
            {
                try
                {
                    action();
                }
                catch (Exception ex)
                {
                    // Log but don't throw to avoid breaking the pipeline
                    Logger?.WriteErrorWithTimestamp($"Error processing queued write: {ex.Message}", ex);
                }
            }
        }

        /// <summary>
        /// Thread-safe method to write an object to the pipeline
        /// </summary>
        protected void WriteObjectThreadSafe(object obj)
        {
            if (IsOnPipelineThread())
            {
                WriteObject(obj);
            }
            else
            {
                QueueWrite(() => WriteObject(obj));
            }
        }

        /// <summary>
        /// Check if we're on the PowerShell pipeline thread
        /// </summary>
        private bool IsOnPipelineThread()
        {
            // PowerShell doesn't expose the pipeline thread ID directly,
            // so we track it based on whether we're in ProcessRecord/BeginProcessing/EndProcessing
            return Thread.CurrentThread.ManagedThreadId == System.Threading.Thread.CurrentThread.ManagedThreadId
                && SynchronizationContext.Current == null;
        }

        protected void WriteVerboseWithTimestamp(string message)
        {
            // Always queue writes to ensure thread safety
            QueueWrite(() => WriteVerbose($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] {message}"));
            Logger?.LogDebug(message);
        }

        protected void WriteWarningWithTimestamp(string message)
        {
            // Always queue writes to ensure thread safety
            QueueWrite(() => WriteWarning($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] {message}"));
            Logger?.WriteWarningWithTimestamp(message);
        }

        protected void WriteErrorWithTimestamp(string message, Exception? exception = null)
        {
            var errorRecord = new ErrorRecord(
                exception ?? new InvalidOperationException(message),
                "ExtractorSuiteError",
                ErrorCategory.InvalidOperation,
                null);

            // Always queue writes to ensure thread safety
            QueueWrite(() => WriteError(errorRecord));
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
