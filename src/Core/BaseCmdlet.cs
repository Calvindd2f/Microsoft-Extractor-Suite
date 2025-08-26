// <copyright file="BaseCmdlet.cs" company="PlaceholderCompany">
// Copyright (c) PlaceholderCompany. All rights reserved.
// </copyright>

namespace Microsoft.ExtractorSuite.Core
{
    using System;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core.Authentication;
    using Microsoft.ExtractorSuite.Core.Logging;

    /// <summary>
    /// Base cmdlet class for all cmdlets in the Microsoft Extractor Suite.
    /// </summary>
    public abstract class BaseCmdlet : PSCmdlet, IDisposable
    {
        /// <summary>
        /// The cancellation token source.
        /// </summary>
#pragma warning disable SA1309
#pragma warning disable SA1600
        private CancellationTokenSource? _cancellationTokenSource;
#pragma warning restore SA1600
        protected ILogger? Logger { get; private set; }
#pragma warning disable SA1600

#pragma warning restore SA1600
        [Parameter]
        public LogLevel LogLevel { get; set; } = LogLevel.Standard;
#pragma warning disable SA1600

#pragma warning restore SA1600
        [Parameter]
#pragma warning disable SA1600
        public string? OutputDirectory { get; set; }
#pragma warning restore SA1600

#pragma warning disable SA1600
        protected AuthenticationManager AuthManager => AuthenticationManager.Instance;
#pragma warning restore SA1600

        protected CancellationToken CancellationToken => _cancellationTokenSource?.Token ?? CancellationToken.None;

        /// <inheritdoc/>

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            _cancellationTokenSource = new CancellationTokenSource();

            // Initialize logger
#pragma warning disable SA1101
            Logger = new FileLogger(LogLevel, OutputDirectory ?? Environment.CurrentDirectory);
#pragma warning restore SA1101

            // Log cmdlet start
#pragma warning disable SA1101
            Logger.LogInfo($"Starting cmdlet: {this.MyInvocation.MyCommand.Name}");
#pragma warning restore SA1101
        }

        /// <inheritdoc/>

        protected override void StopProcessing()
        {
            base.StopProcessing();
            _cancellationTokenSource?.Cancel();
#pragma warning disable SA1101
            Logger?.LogInfo($"Stopping cmdlet: {this.MyInvocation.MyCommand.Name}");
#pragma warning restore SA1101
        }

        /// <inheritdoc/>

        protected override void EndProcessing()
        {
            base.EndProcessing();
            _cancellationTokenSource?.Dispose();
#pragma warning disable SA1101
            Logger?.LogInfo($"Completed cmdlet: {this.MyInvocation.MyCommand.Name}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.Dispose();
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected T RunAsync<T>(Task<T> task)
        {
            try
            {
                // Run on thread pool to avoid STA thread issues
                return Task.Run(async () => await task.ConfigureAwait(false)).GetAwaiter().GetResult();
            }
            catch (AggregateException ex)
            {
                throw ex.InnerException ?? ex;
            }
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected void RunAsync(Task task)
        {
            try
            {
                // Run on thread pool to avoid STA thread issues
                Task.Run(async () => await task.ConfigureAwait(false)).GetAwaiter().GetResult();
            }
            catch (AggregateException ex)
            {
                throw ex.InnerException ?? ex;
            }
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected void WriteVerboseWithTimestamp(string message)
        {
#pragma warning disable SA1101
            WriteVerbose($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] {message}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.LogDebug(message);
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected void WriteWarningWithTimestamp(string message)
        {
#pragma warning disable SA1101
            WriteWarning($"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] {message}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.WriteWarningWithTimestamp(message);
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected void WriteErrorWithTimestamp(string message, Exception? exception = null)
        {
            var errorRecord = new ErrorRecord(
                exception ?? new InvalidOperationException(message),
                "ExtractorSuiteError",
                ErrorCategory.InvalidOperation,
                null);

#pragma warning disable SA1101
            WriteError(errorRecord);
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.WriteErrorWithTimestamp(message, exception);
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected void WriteProgressSafe(string activity, string statusDescription, int percentComplete)
        {
            try
            {
                var progressRecord = new ProgressRecord(0, activity, statusDescription)
                {
                    PercentComplete = percentComplete
                };
#pragma warning disable SA1101
                WriteProgress(progressRecord);
#pragma warning restore SA1101
            }
            catch
            {
                // Ignore progress errors (some hosts don't support progress)
            }
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected bool RequireGraphConnection()
        {
#pragma warning disable SA1101
            if (!AuthManager.IsGraphConnected)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp("Not connected to Microsoft Graph. Please run Connect-M365 first.");
#pragma warning restore SA1101
                return false;
            }
#pragma warning restore SA1101
            return true;
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected bool RequireAzureConnection()
        {
#pragma warning disable SA1101
            if (!AuthManager.IsAzureConnected)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp("Not connected to Azure. Please run Connect-AzureAZ first.");
#pragma warning restore SA1101
                return false;
            }
#pragma warning restore SA1101
            return true;
        }

        /// <summary>
        /// Check if the cmdlet is running in a PowerShell context
        /// </summary>
#pragma warning disable SA1201
        protected bool IsRunningInPowerShell =>
            System.Management.Automation.Runspaces.Runspace.DefaultRunspace != null &&
            System.Management.Automation.Runspaces.Runspace.DefaultRunspace.RunspaceStateInfo.State ==
                System.Management.Automation.Runspaces.RunspaceState.Opened;
#pragma warning restore SA1201

        /// <summary>
        /// Safe way to write output that works both in PowerShell and API contexts
        /// </summary>
        protected void SafeWriteOutput(object output)
        {
#pragma warning disable SA1101
            if (IsRunningInPowerShell)
            {
#pragma warning disable SA1101
                WriteObject(output);
#pragma warning restore SA1101
            }
            else
            {
                // When not in PowerShell, just log the output
                Console.WriteLine($"Output: {System.Text.Json.JsonSerializer.Serialize(output, new System.Text.Json.JsonSerializerOptions { WriteIndented = true })}");
            }
#pragma warning restore SA1101
        }

        /// <summary>
        /// Safe way to write errors that works both in PowerShell and API contexts
        /// </summary>
        protected void SafeWriteError(string message, Exception? exception = null)
        {
#pragma warning disable SA1101
            if (IsRunningInPowerShell)
            {
                var errorRecord = new System.Management.Automation.ErrorRecord(
                    exception ?? new InvalidOperationException(message),
                    "CmdletError",
                    System.Management.Automation.ErrorCategory.InvalidOperation,
                    null);
#pragma warning disable SA1101
                WriteError(errorRecord);
#pragma warning restore SA1101
            }
            else
            {
                // When not in PowerShell, just log the error
                var errorMessage = exception != null ? $"{message}: {exception.Message}" : message;
                Console.WriteLine($"ERROR: {errorMessage}");
                if (exception != null)
                {
                    Console.WriteLine($"Exception: {exception}");
                }
            }
#pragma warning restore SA1101
        }

        /// <summary>
        /// Safe way to write verbose output that works both in PowerShell and API contexts
        /// </summary>
        protected void SafeWriteVerbose(string message)
        {
#pragma warning disable SA1101
            if (IsRunningInPowerShell)
            {
#pragma warning disable SA1101
                WriteVerbose(message);
#pragma warning restore SA1101
            }
            else
            {
                // When not in PowerShell, just log the verbose message
                Console.WriteLine($"VERBOSE: {message}");
            }
#pragma warning restore SA1101
        }

        /// <inheritdoc/>

        public void Dispose()
        {
            throw new NotImplementedException();
        }

    }
}
