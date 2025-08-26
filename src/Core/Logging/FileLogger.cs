namespace Microsoft.ExtractorSuite.Core.Logging
{
    using System;
    using System.IO;
    using Serilog;
    using Serilog.Core;

#pragma warning disable SA1600
    public class FileLogger : ILogger
#pragma warning restore SA1600
    {
#pragma warning disable SA1309
        private readonly LogLevel _logLevel;
#pragma warning restore SA1309
#pragma warning disable SA1600
#pragma warning disable SA1309
#pragma warning restore SA1600
        private readonly Logger _serilogLogger;
#pragma warning disable SA1600
#pragma warning restore SA1309

#pragma warning disable SA1101
        public LogLevel CurrentLevel => _logLevel;
#pragma warning restore SA1101

#pragma warning disable SA1201
        public FileLogger(LogLevel logLevel, string outputDirectory)
#pragma warning restore SA1201
        {
#pragma warning disable SA1101
            _logLevel = logLevel;
#pragma warning restore SA1101

            var logPath = Path.Combine(outputDirectory, "Logs", $"MES_{DateTime.Now:yyyyMMdd_HHmmss}.log");
            Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);

            var loggerConfig = new LoggerConfiguration()
                .WriteTo.File(
                    logPath,
                    outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] [{Level:u3}] {Message:lj}{NewLine}{Exception}",
                    fileSizeLimitBytes: 100 * 1024 * 1024, // 100MB
                    rollOnFileSizeLimit: true,
                    retainedFileCountLimit: 10);

#pragma warning disable SA1101
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
#pragma warning restore SA1101
#pragma warning disable SA1600

#pragma warning restore SA1600
#pragma warning disable SA1101
            _serilogLogger = loggerConfig.CreateLogger();
#pragma warning restore SA1101
        }

        public void LogDebug(string message)
        {
#pragma warning disable SA1600
#pragma warning disable SA1101
            if (_logLevel >= LogLevel.Debug
#pragma warning restore SA1600
documented)
#pragma warning disable SA1101
                _serilogLogger.Debug(message);
#pragma warning restore SA1101
        }

        public void LogInfo(string message)
        {
#pragma warning disable SA1600
#pragma warning disable SA1101
            if (_logLevel >= LogLevel.Standard)
#pragma warning restore SA1600
#pragma warning disable SA1101
                _serilogLogger.Information(message);
#pragma warning restore SA1101
        }

        public void WriteWarningWithTimestamp(string message)
        {
#pragma warning disable SA1600
#pragma warning disable SA1101
            if (_logLevel >= LogLevel.Minimal)
#pragma warning restore SA1600
#pragma warning disable SA1101
                _serilogLogger.Warning(message);
#pragma warning restore SA1101
        }

        public void WriteErrorWithTimestamp(string message, Exception? exception = null)
        {
#pragma warning disable SA1101
            if (_logLevel >= LogLevel.Minimal)
            {
                if (exception != null)
#pragma warning disable SA1101
                    _serilogLogger.Error(exception, message);
#pragma warning restore SA1101
                else
#pragma warning disable SA1600
#pragma warning disable SA1101
                    _serilogLogger.Error(message);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        public void LogProgress(string operation, int current, int total)
        {
#pragma warning disable SA1101
            if (_logLevel >= LogLevel.Standard)
            {
                var percentage = total > 0 ? (current * 100.0 / total) : 0;
#pragma warning disable SA1600
                _serilogLogge
#pragma warning restore SA1600
documentedr.Information($"{operation}: {current}/{total} ({percentage:F1}%)");
            }
#pragma warning restore SA1101
        }

        public void Dispose()
        {
#pragma warning disable SA1101
            _serilogLogger?.Dispose();
#pragma warning restore SA1101
        }
    }
}
