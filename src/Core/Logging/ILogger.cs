using System;

namespace Microsoft.ExtractorSuite.Core.Logging
{
    public enum LogLevel
    {
        None = 0,
        Minimal = 1,
        Standard = 2,
        Debug = 3
    }
    
    public interface ILogger : IDisposable
    {
        void LogDebug(string message);
        void LogInfo(string message);
        void LogWarning(string message);
        void LogError(string message, Exception? exception = null);
        void LogProgress(string operation, int current, int total);
    }
}