namespace Microsoft.ExtractorSuite.Core.AsyncOperations
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Manages long-running async operations for PowerShell cmdlets
    /// Provides proper async/await handling without blocking the PowerShell pipeline
    /// </summary>
    public class AsyncTaskManager : IDisposable
    {

        private readonly ConcurrentDictionary<Guid, TrackedTask> _activeTasks;


        private readonly CancellationTokenSource _globalCancellation;



        private readonly Timer _cleanupTimer;


        private readonly object _lock = new();


        public AsyncTaskManager()
        {

            _activeTasks = new ConcurrentDictionary<Guid, TrackedTask>();


            _globalCancellation = new CancellationTokenSource();


            // Cleanup completed tasks every 30 seconds

            _cleanupTimer = new Timer(
                CleanupCompletedTasks,
                null,
                TimeSpan.FromSeconds(30),
                TimeSpan.FromSeconds(30));

        }

        /// <summary>
        /// Executes a long-running task with progress reporting
        /// </summary>
        public Guid StartLongRunningTask<T>(
            Func<IProgress<TaskProgress>, CancellationToken, Task<T>> taskFactory,
            PSCmdlet cmdlet,
            string taskName)
        {
            var taskId = Guid.NewGuid();

            var cts = CancellationTokenSource.CreateLinkedTokenSource(_globalCancellation.Token);


            var progress = new Progress<TaskProgress>(p => ReportProgress(cmdlet, p));


            var task = Task.Run(async () =>
            {
                try
                {
                    return await taskFactory(progress, cts.Token);
                }
                catch (OperationCanceledException)
                {
                    throw new PipelineStoppedException($"Task '{taskName}' was cancelled");
                }
            }, cts.Token);

            var trackedTask = new TrackedTask
            {
                Id = taskId,
                Name = taskName,
                Task = task,
                CancellationSource = cts,
                StartTime = DateTime.UtcNow,
                Status = TaskStatus.Running
            };


            _activeTasks.TryAdd(taskId, trackedTask);


            // Set up continuation to update status
            task.ContinueWith(t =>
            {

                if (_activeTasks.TryGetValue(taskId, out var tracked))
                {
                    tracked.EndTime = DateTime.UtcNow;
                    tracked.Status = t.Status;

                    if (t.IsFaulted)
                    {
                        tracked.Error = t.Exception?.GetBaseException();
                    }
                }

            }, TaskScheduler.Default);

            return taskId;
        }

        /// <summary>
        /// Waits for a task with periodic progress updates to PowerShell
        /// </summary>
        public async Task<T> WaitForTaskAsync<T>(
            Guid taskId,
            PSCmdlet cmdlet,
            int progressUpdateIntervalMs = 500)
        {

            if (!_activeTasks.TryGetValue(taskId, out var trackedTask))
            {
                throw new InvalidOperationException($"Task {taskId} not found");
            }


            var progressTimer = new Timer(_ =>
            {
                if (trackedTask.LastProgress != null)
                {

                    ReportProgress(cmdlet, trackedTask.LastProgress);

                }
            }, null, progressUpdateIntervalMs, progressUpdateIntervalMs);

            try
            {
                // Use Task.Run to avoid blocking the calling thread
                return await Task.Run(async () =>
                {
                    var result = await (Task<T>)trackedTask.Task;
                    return result;
                });
            }
            finally
            {
                progressTimer?.Dispose();
            }
        }

        /// <summary>
        /// Non-blocking check for task completion
        /// </summary>
        public bool IsTaskComplete(Guid taskId)
        {

            if (_activeTasks.TryGetValue(taskId, out var trackedTask))
            {
                return trackedTask.Task.IsCompleted;
            }

            return true;
        }

        /// <summary>
        /// Gets task result without blocking (throws if not complete)
        /// </summary>
        public T GetTaskResult<T>(Guid taskId)
        {

            if (!_activeTasks.TryGetValue(taskId, out var trackedTask))
            {
                throw new InvalidOperationException($"Task {taskId} not found");
            }


            if (!trackedTask.Task.IsCompleted)
            {
                throw new InvalidOperationException($"Task {taskId} is still running");
            }

            if (trackedTask.Task.IsFaulted)
            {
                throw trackedTask.Task.Exception?.GetBaseException()
                    ?? new InvalidOperationException("Task failed");
            }

            if (trackedTask.Task.IsCanceled)
            {
                throw new OperationCanceledException($"Task {taskId} was cancelled");
            }

            return ((Task<T>)trackedTask.Task).Result;
        }

        /// <summary>
        /// Cancels a specific task
        /// </summary>
        public void CancelTask(Guid taskId)
        {

            if (_activeTasks.TryGetValue(taskId, out var trackedTask))
            {
                trackedTask.CancellationSource.Cancel();
            }

        }

        /// <summary>
        /// Cancels all active tasks
        /// </summary>
        public void CancelAllTasks()
        {

            _globalCancellation.Cancel();

        }

        /// <summary>
        /// Gets status of all active tasks
        /// </summary>
        public IEnumerable<TaskStatusInfo> GetActiveTasksStatus()
        {

            return _activeTasks.Values.Select(t => new TaskStatusInfo
            {
                Id = t.Id,
                Name = t.Name,
                Status = t.Status,
                StartTime = t.StartTime,
                EndTime = t.EndTime,
                Duration = (t.EndTime ?? DateTime.UtcNow) - t.StartTime,
                Progress = t.LastProgress?.PercentComplete ?? 0,
                CurrentOperation = t.LastProgress?.CurrentOperation
            });

        }

        /// <summary>
        /// Executes multiple tasks in parallel with controlled concurrency
        /// </summary>
        public async Task<IEnumerable<T>> ExecuteParallelAsync<T>(
            IEnumerable<Func<CancellationToken, Task<T>>> taskFactories,
            PSCmdlet cmdlet,
            int maxConcurrency = 10,
            string operationName = "Parallel Operation")
        {
            var semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);
            var tasks = new List<Task<T>>();
            var totalTasks = taskFactories.Count();
            var completedTasks = 0;

            foreach (var factory in taskFactories)
            {
                var task = Task.Run(async () =>
                {

                    await semaphore.WaitAsync(_globalCancellation.Token);

                    try
                    {

                        var result = await factory(_globalCancellation.Token);


                        Interlocked.Increment(ref completedTasks);

                        var progress = new TaskProgress
                        {
                            PercentComplete = (completedTasks * 100) / totalTasks,
                            CurrentOperation = $"{operationName}: {completedTasks}/{totalTasks}",
                            ItemsProcessed = completedTasks,
                            TotalItems = totalTasks
                        };


                        ReportProgress(cmdlet, progress);


                        return result;
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                });

                tasks.Add(task);
            }

            return await Task.WhenAll(tasks);
        }

        private void ReportProgress(PSCmdlet cmdlet, TaskProgress progress)
        {
            try
            {
                var progressRecord = new ProgressRecord(
                    progress.ActivityId,
                    progress.Activity ?? "Processing",
                    progress.CurrentOperation ?? "Working...")
                {
                    PercentComplete = progress.PercentComplete,
                    SecondsRemaining = progress.EstimatedSecondsRemaining ?? -1
                };

                if (progress.ItemsProcessed.HasValue && progress.TotalItems.HasValue)
                {
                    progressRecord.StatusDescription =
                        $"{progress.CurrentOperation} ({progress.ItemsProcessed}/{progress.TotalItems})";
                }

                cmdlet.WriteProgress(progressRecord);
            }
            catch
            {
                // Ignore progress reporting errors
            }
        }

        private void CleanupCompletedTasks(object? state)
        {
            var cutoffTime = DateTime.UtcNow.AddMinutes(-5);

            var toRemove = _activeTasks
                .Where(kvp => kvp.Value.Task.IsCompleted &&
                             kvp.Value.EndTime.HasValue &&
                             kvp.Value.EndTime.Value < cutoffTime)
                .Select(kvp => kvp.Key)
                .ToList();


            foreach (var id in toRemove)

            {


                if (_activeTasks.TryRemove(id, out var task))
                {
                    task.CancellationSource?.Dispose();
                }

            }
        }

        public void Dispose()
        {

            _cleanupTimer?.Dispose();


            _globalCancellation?.Cancel();


            _globalCancellation?.Dispose();



            foreach (var task in _activeTasks.Values)
            {
                task.CancellationSource?.Dispose();
            }



            _activeTasks.Clear();

        }

        private class TrackedTask
        {
            public Guid Id { get; set; }public string Name { get; set; } = string.Empty;
            public Task Task { get; set; } = null!;
            public CancellationTokenSource CancellationSource { get; set; } = null!;


            public DateTime S

            public DateTime? EndTime { get; set; }



        public TaskStatus Status { get; set; }
            public Exception? Error { get; set; }


            public TaskProgress? LastProgress { get; set; }


        }


    }





    public class TaskProgress

    {


        public int ActivityId { get; set; }
        public string? Activity

        public string? CurrentOperation { get; set; }

        public int PercentComplete {

set; }

        public int? EstimatedSecondsRemaining { get; set; }


        public int? ItemsProcessed { get; set;}


        public int? TotalItems { get; set; }


    }





    public class TaskStatusInfo


    {

        public Guid Id { get; set; }public string Name { get; set; } = string.Empty;
        public TaskStatus Status { get; set; }public DateTime StartTime { get; set; }public DateTime? EndTime { get; set; }
        public TimeSpan Duration { get; set; }public int Progress { get; set; }public string? CurrentOperation { get; set; }
    }
}
