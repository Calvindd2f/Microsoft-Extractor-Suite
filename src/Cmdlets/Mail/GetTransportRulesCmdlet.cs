namespace Microsoft.ExtractorSuite.Cmdlets.Mail
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Exchange;
    using Microsoft.ExtractorSuite.Core.Logging;
    using Microsoft.ExtractorSuite.Models.Exchange;


    /// <summary>
    /// Retrieves transport rules from Exchange Online.
    /// High-performance implementation using direct REST API calls.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "TransportRules")]
    [OutputType(typeof(TransportRule))]
    public class GetTransportRulesCmdlet : BaseCmdlet
    {
        [Parameter(
            HelpMessage = "Output directory for the CSV file. Default: Output\\Rules")]
        [ValidateNotNullOrEmpty]
#pragma warning disable SA1600
        public string OutputDir { get; set; } = Path.Combine("Output", "Rules");
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Encoding for the CSV file. Default: UTF8")]
        [ValidateSet("UTF8", "UTF7", "ASCII", "Unicode", "UTF32")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output format for the results")]
        [ValidateSet("CSV", "JSON", "Object")]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "CSV";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Show only rules in the specified state")]
        [ValidateSet("Enabled", "Disabled", "All")]
#pragma warning disable SA1600
        public string StateFilter { get; set; } = "All";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Show transport rules in console output")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1309
        public SwitchParameter ShowRules { get; set; }
#pragma warning disable SA1201
        private ExchangeRestClient? _exchangeClient;
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning disable SA1309
sho
#pragma warning restore SA1600
        private readonly Statistics _stats = new();
#pragma warning restore SA1309

        protected override void BeginProcessing()
        {
            base.BeginProcessing();

#pragma warning disable SA1101
            if (!AuthManager.IsExchangeConnected)
            {
                throw new PSInvalidOperationException(
                    "Not connected to Exchange Online. Please run Connect-M365 -Service ExchangeOnline first.");
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            _exchangeClient = new ExchangeRestClient(AuthManager);
#pragma warning restore SA1101

            // Create output directory if it doesn't exist
#pragma warning disable SA1101
            if (!Directory.Exists(OutputDir))
            {
#pragma warning disable SA1101
                Directory.CreateDirectory(OutputDir);
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger?.LogDebug($"Created output directory: {OutputDir}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            Logger?.LogInfo("=== Starting Transport Rules Collection ===");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
#pragma warning disable SA1101
                Logger.LogDebug($"PowerShell Version: {this.Host?.Version ?? new Version("7.0")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug("Input parameters:");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  OutputDir: '{OutputDir}'");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  Encoding: '{Encoding}'");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  OutputFormat: '{OutputFormat}'");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  StateFilter: '{StateFilter}'");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  ShowRules: {ShowRules}");
#pragma warning restore SA1101
#pragma warning disable SA1600
#pragma warning disable SA1101
                Logger.LogDebug($"  LogLevel: '
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        protected override void ProcessRecord()
        {
            try
            {
#pragma warning disable SA1101
                WriteVerboseWithTimestamp("Retrieving transport rules from Exchange Online...");
#pragma warning restore SA1101
                var startTime = DateTime.UtcNow;

#pragma warning disable SA1101
                var rules = RunAsync(GetTransportRulesAsync());
#pragma warning restore SA1101

                var processingTime = DateTime.UtcNow - startTime;
#pragma warning disable SA1101
                if (Logger?.CurrentLevel == LogLevel.Debug)
                {
#pragma warning disable SA1101
                    Logger.LogDebug($"Transport rule retrieval took {processingTime.TotalSeconds:F2} seconds");
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                if (rules == null || rules.Length == 0)
                {
#pragma warning disable SA1101
                    Logger?.WriteWarningWithTimestamp("No transport rules found");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    WriteWarning("No transport rules found in the organization");
#pragma warning restore SA1101
                    return;
                }

                // Apply state filter
#pragma warning disable SA1101
                if (StateFilter != "All")
                {
#pragma warning disable SA1101
                    rules = rules.Where(r =>
                        string.Equals(r.State, StateFilter, StringComparison.OrdinalIgnoreCase))
                        .ToArray();
#pragma warning restore SA1101

                    if (rules.Length == 0)
                    {
#pragma warning disable SA1101
                        Logger?.LogInfo($"No rules found with state: {StateFilter}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                        WriteWarning($"No transport rules found with state: {StateFilter}");
#pragma warning restore SA1101
                        return;
                    }
                }
#pragma warning restore SA1101

                // Process statistics
#pragma warning disable SA1101
                ProcessStatistics(rules);
#pragma warning restore SA1101

                // Show rules in console if requested
#pragma warning disable SA1101
                if (ShowRules)
                {
#pragma warning disable SA1101
                    DisplayRules(rules);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                // Output based on format
#pragma warning disable SA1101
                switch (OutputFormat.ToUpper())
                {
                    case "CSV":
#pragma warning disable SA1101
                        ExportToCsv(rules);
#pragma warning restore SA1101
                        break;
                    case "JSON":
#pragma warning disable SA1101
                        ExportToJson(rules);
#pragma warning restore SA1101
                        break;
                    case "OBJECT":
                        foreach (var rule in rules)
                        {
#pragma warning disable SA1101
                            WriteObject(rule);
#pragma warning restore SA1101
                        }
                        break;
                }
#pragma warning restore SA1101

                // Display summary
#pragma warning disable SA1101
                DisplaySummary();
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                Logger?.WriteErrorWithTimestamp($"Error retrieving transport rules: {ex.Message}", ex);
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to retrieve transport rules: {ex.Message}", ex);
#pragma warning restore SA1101
            }
        }

        private async Task<TransportRule[]> GetTransportRulesAsync()
        {
#pragma warning disable SA1101
            if (_exchangeClient == null)
            {
                throw new InvalidOperationException("Exchange client not initialized");
            }
#pragma warning restore SA1101

            try
            {
#pragma warning disable SA1101
                WriteProgressSafe("Retrieving Transport Rules", "Connecting to Exchange Online...", 0);
#pragma warning restore SA1101

#pragma warning disable SA1101
                var rules = await _exchangeClient.GetTransportRulesTypedAsync(CancellationToken);
#pragma warning restore SA1101

#pragma warning disable SA1101
                WriteProgressSafe("Retrieving Transport Rules", "Processing rules...", 50);
#pragma warning restore SA1101

                // Convert WhenChanged to UTC if needed
                foreach (var rule in rules)
                {
                    if (rule.WhenChanged.HasValue && rule.WhenChanged.Value.Kind != DateTimeKind.Utc)
                    {
                        rule.WhenChanged = rule.WhenChanged.Value.ToUniversalTime();
                    }
                }

#pragma warning disable SA1101
                WriteProgressSafe("Retrieving Transport Rules", "Complete", 100);
#pragma warning restore SA1101

                return rules;
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                Logger?.WriteErrorWithTimestamp($"Failed to retrieve transport rules: {ex.Message}", ex);
#pragma warning restore SA1101
                throw new PSInvalidOperationException($"Failed to retrieve transport rules: {ex.Message}", ex);
            }
        }

        private void ProcessStatistics(TransportRule[] rules)
        {
#pragma warning disable SA1101
            _stats.TotalRules = rules.Length;
#pragma warning restore SA1101
#pragma warning disable SA1101
            _stats.EnabledRules = rules.Count(r =>
                string.Equals(r.State, "Enabled", StringComparison.OrdinalIgnoreCase));
#pragma warning restore SA1101
#pragma warning disable SA1101
            _stats.DisabledRules = rules.Count(r =>
                string.Equals(r.State, "Disabled", StringComparison.OrdinalIgnoreCase));
#pragma warning restore SA1101

            // Mode statistics
#pragma warning disable SA1101
            _stats.EnforceMode = rules.Count(r =>
                string.Equals(r.Mode, "Enforce", StringComparison.OrdinalIgnoreCase));
#pragma warning restore SA1101
#pragma warning disable SA1101
            _stats.AuditMode = rules.Count(r =>
                string.Equals(r.Mode, "Audit", StringComparison.OrdinalIgnoreCase));
#pragma warning restore SA1101

            // Priority analysis
            if (rules.Any())
            {
#pragma warning disable SA1101
                _stats.HighestPriority = rules.Min(r => r.Priority);
#pragma warning restore SA1101
#pragma warning disable SA1101
                _stats.LowestPriority = rules.Max(r => r.Priority);
#pragma warning restore SA1101
            }

            // Recent changes (last 30 days)
            var thirtyDaysAgo = DateTime.UtcNow.AddDays(-30);
#pragma warning disable SA1101
            _stats.RecentlyModified = rules.Count(r =>
                r.WhenChanged.HasValue && r.WhenChanged.Value > thirtyDaysAgo);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
                foreach (var rule in rules)
                {
#pragma warning disable SA1101
                    Logger.LogDebug($"Processing rule: {rule.Name}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    Logger.LogDebug($"  State: {rule.State}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    Logger.LogDebug($"  Priority: {rule.Priority}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    Logger.LogDebug($"  Mode: {rule.Mode}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    Logger.LogDebug($"  When Changed: {rule.WhenChanged}");
#pragma warning restore SA1101
                }
            }
#pragma warning restore SA1101
        }

        private void DisplayRules(TransportRule[] rules)
        {
#pragma warning disable SA1101
            WriteHost("\n=== Transport Rules ===\n", ConsoleColor.Cyan);
#pragma warning restore SA1101

            foreach (var rule in rules.OrderBy(r => r.Priority))
            {
#pragma warning disable SA1101
                WriteHost($"[{rule.State?.ToUpper()}] ",
                    rule.State?.Equals("Enabled", StringComparison.OrdinalIgnoreCase) == true
                        ? ConsoleColor.Green : ConsoleColor.Yellow);
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteHost($"{rule.Name}\n");
#pragma warning restore SA1101

#pragma warning disable SA1101
                WriteHost($"  Priority: {rule.Priority}\n", ConsoleColor.Gray);
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteHost($"  Mode: {rule.Mode}\n", ConsoleColor.Gray);
#pragma warning restore SA1101

                if (!string.IsNullOrWhiteSpace(rule.Description))
                {
#pragma warning disable SA1101
                    WriteHost($"  Description: {rule.Description}\n", ConsoleColor.Gray);
#pragma warning restore SA1101
                }

                if (rule.WhenChanged.HasValue)
                {
#pragma warning disable SA1101
                    WriteHost($"  Last Modified: {rule.WhenChanged.Value:yyyy-MM-dd HH:mm:ss} UTC\n",
                        ConsoleColor.Gray);
#pragma warning restore SA1101
                }

#pragma warning disable SA1101
                WriteHost("\n");
#pragma warning restore SA1101
            }
        }

        private void ExportToCsv(TransportRule[] rules)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
#pragma warning disable SA1101
            var filename = Path.Combine(OutputDir, $"{timestamp}-TransportRules.csv");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var encoding = GetEncoding();
#pragma warning restore SA1101

            using var writer = new StreamWriter(filename, false, encoding);

            // Write CSV header
            writer.WriteLine("Name,State,Priority,Mode,Description,WhenChanged,Identity");

            // Write data
            foreach (var rule in rules.OrderBy(r => r.Priority))
            {
                writer.WriteLine($"\"{EscapeCsvField(rule.Name)}\"," +
                               $"\"{rule.State}\"," +
                               $"{rule.Priority}," +
                               $"\"{rule.Mode}\"," +
                               $"\"{EscapeCsvField(rule.Description)}\"," +
                               $"\"{rule.WhenChanged?.ToString("yyyy-MM-dd HH:mm:ss")}\"," +
                               $"\"{EscapeCsvField(rule.Identity)}\"");
            }

#pragma warning disable SA1101
            Logger?.LogInfo($"Exported {rules.Length} transport rules to: {filename}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"\nExported to: {filename}\n", ConsoleColor.Green);
#pragma warning restore SA1101
        }

        private void ExportToJson(TransportRule[] rules)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
#pragma warning disable SA1101
            var filename = Path.Combine(OutputDir, $"{timestamp}-TransportRules.json");
#pragma warning restore SA1101

            var json = System.Text.Json.JsonSerializer.Serialize(rules, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
            });

#pragma warning disable SA1101
            File.WriteAllText(filename, json, GetEncoding());
#pragma warning restore SA1101

#pragma warning disable SA1101
            Logger?.LogInfo($"Exported {rules.Length} transport rules to: {filename}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"\nExported to: {filename}\n", ConsoleColor.Green);
#pragma warning restore SA1101
        }

        private void DisplaySummary()
        {
#pragma warning disable SA1101
            WriteHost("\n=== Transport Rules Summary ===\n", ConsoleColor.Cyan);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Total Rules: {_stats.TotalRules}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"  - Enabled: {_stats.EnabledRules}\n", ConsoleColor.Green);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"  - Disabled: {_stats.DisabledRules}\n", ConsoleColor.Yellow);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.TotalRules > 0)
            {
#pragma warning disable SA1101
                WriteHost($"\nMode Distribution:\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteHost($"  - Enforce: {_stats.EnforceMode}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteHost($"  - Audit: {_stats.AuditMode}\n");
#pragma warning restore SA1101

#pragma warning disable SA1101
                WriteHost($"\nPriority Range: {_stats.HighestPriority} - {_stats.LowestPriority}\n");
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (_stats.RecentlyModified > 0)
                {
#pragma warning disable SA1101
                    WriteHost($"Recently Modified (30 days): {_stats.RecentlyModified}\n",
                        ConsoleColor.Cyan);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            Logger?.LogInfo("Transport Rules Summary:");
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.LogInfo($"Total Rules: {_stats.TotalRules}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.LogInfo($"  - Enabled: {_stats.EnabledRules}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.LogInfo($"  - Disabled: {_stats.DisabledRules}");
#pragma warning restore SA1101
        }

        private System.Text.Encoding GetEncoding()
        {
#pragma warning disable SA1101
            return Encoding.ToUpper() switch
            {
                "UTF7" => System.Text.Encoding.UTF7,
                "ASCII" => System.Text.Encoding.ASCII,
                "UNICODE" => System.Text.Encoding.Unicode,
                "UTF32" => System.Text.Encoding.UTF32,
                _ => System.Text.Encoding.UTF8
            };
#pragma warning restore SA1101
        }

        private static string EscapeCsvField(string? field)
        {
            if (string.IsNullOrEmpty(field))
                return string.Empty;

            // Escape quotes by doubling them
            return field.Replace("\"", "\"\"");
        }

        private void WriteHost(string message, ConsoleColor? color = null)
        {
            if (color.HasValue)
            {
#pragma warning disable SA1101
                Host.UI.Write(color.Value, Host.UI.RawUI.BackgroundColor, message);
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1600
#pragma warning disable SA1101
                Host.UI.Write(message);
#pragma warning restore SA1101
            }
        }

        protected override void EndProcessing()
        {
#pragma warning disable SA1101
            _exchangeClient?.Dispose();
#pragma warning restore SA1101
            base.EndProcessing();
        }

        private class Statistics
        {
            public int TotalRules { get; set; }public int EnabledRules { get; set; }public int DisabledRules { get; set; }public int EnforceMode { get; set; }public int AuditMode { get; set; }public int HighestPriority { get; set; }public int LowestPriority { get; set; }public int RecentlyModified { get; set; }}
    }
}
