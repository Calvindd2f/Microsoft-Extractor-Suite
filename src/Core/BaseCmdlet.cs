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


        private CancellationTokenSource? _cancellationTokenSource;

        protected ILogger? Logger { get; private set; }



        [Parameter]
        public LogLevel LogLevel { get; set; } = LogLevel.Standard;



        [Parameter]

        public string? OutputDirectory { get; set; }



        protected AuthenticationManager AuthManager => AuthenticationManager.Instance;


        protected CancellationToken CancellationToken => _cancellationTokenSource?.Token ?? CancellationToken.None;

        /// <inheritdoc/>

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            _cancellationTokenSource = new CancellationTokenSource();

            // Initialize logger

            Logger = new FileLogger(LogLevel, OutputDirectory ?? Environment.CurrentDirectory);


            // Log cmdlet start

            Logger.LogInfo($"Starting cmdlet: {this.MyInvocation.MyCommand.Name}");

        }

        /// <inheritdoc/>

        protected override void StopProcessing()
        {
            base.StopProcessing();
            _cancellationTokenSource?.Cancel();

            Logger?.LogInfo($"Stopping cmdlet: {this.MyInvocation.MyCommand.Name}");

        }

        /// <inheritdoc/>

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
                // Run on thread pool to avoid STA thread issues
                return Task.Run(async () => await task.ConfigureAwait(false)).GetAwaiter().GetResult();
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
                // Run on thread pool to avoid STA thread issues
                Task.Run(async () => await task.ConfigureAwait(false)).GetAwaiter().GetResult();
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

        /// <summary>
        /// Check if the cmdlet is running in a PowerShell context
        /// </summary>

        protected bool IsRunningInPowerShell =>
            System.Management.Automation.Runspaces.Runspace.DefaultRunspace != null &&
            System.Management.Automation.Runspaces.Runspace.DefaultRunspace.RunspaceStateInfo.State ==
                System.Management.Automation.Runspaces.RunspaceState.Opened;


        /// <summary>
        /// Safe way to write output that works both in PowerShell and API contexts
        /// </summary>
        protected void SafeWriteOutput(object output)
        {

            if (IsRunningInPowerShell)
            {

                WriteObject(output);

            }
            else
            {
                // When not in PowerShell, just log the output
                Console.WriteLine($"Output: {System.Text.Json.JsonSerializer.Serialize(output, new System.Text.Json.JsonSerializerOptions { WriteIndented = true })}");
            }

        }

        /// <summary>
        /// Safe way to write errors that works both in PowerShell and API contexts
        /// </summary>
        protected void SafeWriteError(string message, Exception? exception = null)
        {

            if (IsRunningInPowerShell)
            {
                var errorRecord = new System.Management.Automation.ErrorRecord(
                    exception ?? new InvalidOperationException(message),
                    "CmdletError",
                    System.Management.Automation.ErrorCategory.InvalidOperation,
                    null);

                WriteError(errorRecord);

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

        }

        /// <summary>
        /// Safe way to write verbose output that works both in PowerShell and API contexts
        /// </summary>
        protected void SafeWriteVerbose(string message)
        {

            if (IsRunningInPowerShell)
            {

                WriteVerbose(message);

            }
            else
            {
                // When not in PowerShell, just log the verbose message
                Console.WriteLine($"VERBOSE: {message}");
            }

        }

        /// <inheritdoc/>

        public void Dispose()
        {
            throw new NotImplementedException();
        }

    }
}
