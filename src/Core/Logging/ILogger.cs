namespace Microsoft.ExtractorSuite.Core.Logging
{
    using System;

#pragma warning disable SA1600
    public enum LogLevel
#pragma warning restore SA1600
    {
        None = 0,
        Minimal = 1,
        Standard = 2,
        Debug = 3
    }

#pragma warning disable SA1600
    public interface ILogger : IDisposable
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        LogLevel CurrentLevel { get; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        void LogDebug(string message);
#pragma warning restore SA1600
#pragma warning disable SA1600
        void LogInfo(string message);
#pragma warning restore SA1600
#pragma warning disable SA1600
        void WriteWarningWithTimestamp(string message);
#pragma warning restore SA1600
#pragma warning disable SA1600
        void WriteErrorWithTimestamp(string message, Exception? exception = null);
#pragma warning restore SA1600
#pragma warning disable SA1600
        void LogProgress(string operation, int current, int total);
#pragma warning restore SA1600
    }
}
