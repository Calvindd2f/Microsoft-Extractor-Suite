using System;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core.Authentication;
using Microsoft.ExtractorSuite.Core.Logging;

namespace Microsoft.ExtractorSuite.Core
{
    public abstract class BaseCmdlet : PSCmdlet
    {
        private CancellationTokenSource? _cancellationTokenSource;
        protected ILogger? Logger { get; private set; }
        
        [Parameter]
        public LogLevel LogLevel { get; set; } = LogLevel.Standard;
        
        [Parameter]
        public string? OutputDirectory { get; set; }
        
        protected AuthenticationManager AuthManager => AuthenticationManager.Instance;
        
        protected CancellationToken CancellationToken => _cancellationTokenSource?.Token ?? CancellationToken.None;
        
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            _cancellationTokenSource = new CancellationTokenSource();
            
            // Initialize logger
            Logger = new FileLogger(LogLevel, OutputDirectory ?? Environment.CurrentDirectory);
            
            // Log cmdlet start
            Logger.LogInfo($"Starting cmdlet: {this.MyInvocation.MyCommand.Name}");
        }
        
        protected override void StopProcessing()
        {
            base.StopProcessing();
            _cancellationTokenSource?.Cancel();
            Logger?.LogInfo($"Stopping cmdlet: {this.MyInvocation.MyCommand.Name}");
        }
        
        protected override void EndProcessing()
        {
            base.EndProcessing();
            _cancellationTokenSource?.Dispose();
            Logger?.LogInfo($"Completed cmdlet: {this.MyInvocation.MyCommand.Name}");
            Logger?.Dispose();
        }
        
        protected T RunAsync<T>(Task<T> task)
        {
            try
            {
                return task.GetAwaiter().GetResult();
            }
            catch (AggregateException ex)
            {
                throw ex.InnerException ?? ex;
            }
        }
        
        protected void RunAsync(Task task)
        {
            try
            {
                task.GetAwaiter().GetResult();
            }
            catch (AggregateException ex)
            {
                throw ex.InnerException ?? ex;
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
            Logger?.LogWarning(message);
        }
        
        protected void WriteErrorWithTimestamp(string message, Exception? exception = null)
        {
            var errorRecord = new ErrorRecord(
                exception ?? new InvalidOperationException(message),
                "ExtractorSuiteError",
                ErrorCategory.InvalidOperation,
                null);
            
            WriteError(errorRecord);
            Logger?.LogError(message, exception);
        }
        
        protected void WriteProgressSafe(string activity, string statusDescription, int percentComplete)
        {
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
                // Ignore progress errors (some hosts don't support progress)
            }
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
    }
}