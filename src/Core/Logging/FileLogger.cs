using System;
using System.IO;
using Serilog;
using Serilog.Core;

namespace Microsoft.ExtractorSuite.Core.Logging
{
    public class FileLogger : ILogger
    {
        private readonly LogLevel _logLevel;
        private readonly Logger _serilogLogger;
        
        public FileLogger(LogLevel logLevel, string outputDirectory)
        {
            _logLevel = logLevel;
            
            var logPath = Path.Combine(outputDirectory, "Logs", $"MES_{DateTime.Now:yyyyMMdd_HHmmss}.log");
            Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
            
            var loggerConfig = new LoggerConfiguration()
                .WriteTo.File(
                    logPath,
                    outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] [{Level:u3}] {Message:lj}{NewLine}{Exception}",
                    fileSizeLimitBytes: 100 * 1024 * 1024, // 100MB
                    rollOnFileSizeLimit: true,
                    retainedFileCountLimit: 10);
            
            switch (_logLevel)
            {
                case LogLevel.None:
                    loggerConfig.MinimumLevel.Fatal();
                    break;
                case LogLevel.Minimal:
                    loggerConfig.MinimumLevel.Warning();
                    break;
                case LogLevel.Standard:
                    loggerConfig.MinimumLevel.Information();
                    break;
                case LogLevel.Debug:
                    loggerConfig.MinimumLevel.Debug();
                    break;
            }
            
            _serilogLogger = loggerConfig.CreateLogger();
        }
        
        public void LogDebug(string message)
        {
            if (_logLevel >= LogLevel.Debug)
                _serilogLogger.Debug(message);
        }
        
        public void LogInfo(string message)
        {
            if (_logLevel >= LogLevel.Standard)
                _serilogLogger.Information(message);
        }
        
        public void LogWarning(string message)
        {
            if (_logLevel >= LogLevel.Minimal)
                _serilogLogger.Warning(message);
        }
        
        public void LogError(string message, Exception? exception = null)
        {
            if (_logLevel >= LogLevel.Minimal)
            {
                if (exception != null)
                    _serilogLogger.Error(exception, message);
                else
                    _serilogLogger.Error(message);
            }
        }
        
        public void LogProgress(string operation, int current, int total)
        {
            if (_logLevel >= LogLevel.Standard)
            {
                var percentage = total > 0 ? (current * 100.0 / total) : 0;
                _serilogLogger.Information($"{operation}: {current}/{total} ({percentage:F1}%)");
            }
        }
        
        public void Dispose()
        {
            _serilogLogger?.Dispose();
        }
    }
}