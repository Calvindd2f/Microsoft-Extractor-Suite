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

namespace Microsoft.ExtractorSuite.Cmdlets.Mail
{
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
        public string OutputDir { get; set; } = Path.Combine("Output", "Rules");

        [Parameter(
            HelpMessage = "Encoding for the CSV file. Default: UTF8")]
        [ValidateSet("UTF8", "UTF7", "ASCII", "Unicode", "UTF32")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(
            HelpMessage = "Output format for the results")]
        [ValidateSet("CSV", "JSON", "Object")]
        public string OutputFormat { get; set; } = "CSV";

        [Parameter(
            HelpMessage = "Show only rules in the specified state")]
        [ValidateSet("Enabled", "Disabled", "All")]
        public string StateFilter { get; set; } = "All";

        [Parameter(
            HelpMessage = "Show transport rules in console output")]
        public SwitchParameter ShowRules { get; set; }

        private ExchangeRestClient? _exchangeClient;
        private readonly Statistics _stats = new();

        protected override void BeginProcessing()
        {
            base.BeginProcessing();

            if (!AuthManager.IsExchangeConnected)
            {
                throw new PSInvalidOperationException(
                    "Not connected to Exchange Online. Please run Connect-M365 -Service ExchangeOnline first.");
            }

            _exchangeClient = new ExchangeRestClient(AuthManager);

            // Create output directory if it doesn't exist
            if (!Directory.Exists(OutputDir))
            {
                Directory.CreateDirectory(OutputDir);
                Logger?.LogDebug($"Created output directory: {OutputDir}");
            }

            Logger?.LogInfo("=== Starting Transport Rules Collection ===");

            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
                Logger.LogDebug($"PowerShell Version: {PSVersionTable.PSVersion}");
                Logger.LogDebug("Input parameters:");
                Logger.LogDebug($"  OutputDir: '{OutputDir}'");
                Logger.LogDebug($"  Encoding: '{Encoding}'");
                Logger.LogDebug($"  OutputFormat: '{OutputFormat}'");
                Logger.LogDebug($"  StateFilter: '{StateFilter}'");
                Logger.LogDebug($"  ShowRules: {ShowRules}");
                Logger.LogDebug($"  LogLevel: '{LogLevel}'");
            }
        }

        protected override void ProcessRecord()
        {
            try
            {
                WriteVerboseWithTimestamp("Retrieving transport rules from Exchange Online...");
                var startTime = DateTime.UtcNow;

                var rules = RunAsync(GetTransportRulesAsync());

                var processingTime = DateTime.UtcNow - startTime;
                if (Logger?.CurrentLevel == LogLevel.Debug)
                {
                    Logger.LogDebug($"Transport rule retrieval took {processingTime.TotalSeconds:F2} seconds");
                }

                if (rules == null || rules.Length == 0)
                {
                    Logger?.WriteWarningWithTimestamp("No transport rules found");
                    WriteWarning("No transport rules found in the organization");
                    return;
                }

                // Apply state filter
                if (StateFilter != "All")
                {
                    rules = rules.Where(r =>
                        string.Equals(r.State, StateFilter, StringComparison.OrdinalIgnoreCase))
                        .ToArray();

                    if (rules.Length == 0)
                    {
                        Logger?.LogInfo($"No rules found with state: {StateFilter}");
                        WriteWarning($"No transport rules found with state: {StateFilter}");
                        return;
                    }
                }

                // Process statistics
                ProcessStatistics(rules);

                // Show rules in console if requested
                if (ShowRules)
                {
                    DisplayRules(rules);
                }

                // Output based on format
                switch (OutputFormat.ToUpper())
                {
                    case "CSV":
                        ExportToCsv(rules);
                        break;
                    case "JSON":
                        ExportToJson(rules);
                        break;
                    case "OBJECT":
                        foreach (var rule in rules)
                        {
                            WriteObject(rule);
                        }
                        break;
                }

                // Display summary
                DisplaySummary();
            }
            catch (Exception ex)
            {
                Logger?.WriteErrorWithTimestamp($"Error retrieving transport rules: {ex.Message}", ex);
                WriteErrorWithTimestamp($"Failed to retrieve transport rules: {ex.Message}", ex);
            }
        }

        private async Task<TransportRule[]> GetTransportRulesAsync()
        {
            if (_exchangeClient == null)
            {
                throw new InvalidOperationException("Exchange client not initialized");
            }

            try
            {
                WriteProgressSafe("Retrieving Transport Rules", "Connecting to Exchange Online...", 0);

                var rules = await _exchangeClient.GetTransportRulesTypedAsync(CancellationToken);

                WriteProgressSafe("Retrieving Transport Rules", "Processing rules...", 50);

                // Convert WhenChanged to UTC if needed
                foreach (var rule in rules)
                {
                    if (rule.WhenChanged.HasValue && rule.WhenChanged.Value.Kind != DateTimeKind.Utc)
                    {
                        rule.WhenChanged = rule.WhenChanged.Value.ToUniversalTime();
                    }
                }

                WriteProgressSafe("Retrieving Transport Rules", "Complete", 100);

                return rules;
            }
            catch (Exception ex)
            {
                Logger?.WriteErrorWithTimestamp($"Failed to retrieve transport rules: {ex.Message}", ex);
                throw new PSInvalidOperationException($"Failed to retrieve transport rules: {ex.Message}", ex);
            }
        }

        private void ProcessStatistics(TransportRule[] rules)
        {
            _stats.TotalRules = rules.Length;
            _stats.EnabledRules = rules.Count(r =>
                string.Equals(r.State, "Enabled", StringComparison.OrdinalIgnoreCase));
            _stats.DisabledRules = rules.Count(r =>
                string.Equals(r.State, "Disabled", StringComparison.OrdinalIgnoreCase));

            // Mode statistics
            _stats.EnforceMode = rules.Count(r =>
                string.Equals(r.Mode, "Enforce", StringComparison.OrdinalIgnoreCase));
            _stats.AuditMode = rules.Count(r =>
                string.Equals(r.Mode, "Audit", StringComparison.OrdinalIgnoreCase));

            // Priority analysis
            if (rules.Any())
            {
                _stats.HighestPriority = rules.Min(r => r.Priority);
                _stats.LowestPriority = rules.Max(r => r.Priority);
            }

            // Recent changes (last 30 days)
            var thirtyDaysAgo = DateTime.UtcNow.AddDays(-30);
            _stats.RecentlyModified = rules.Count(r =>
                r.WhenChanged.HasValue && r.WhenChanged.Value > thirtyDaysAgo);

            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
                foreach (var rule in rules)
                {
                    Logger.LogDebug($"Processing rule: {rule.Name}");
                    Logger.LogDebug($"  State: {rule.State}");
                    Logger.LogDebug($"  Priority: {rule.Priority}");
                    Logger.LogDebug($"  Mode: {rule.Mode}");
                    Logger.LogDebug($"  When Changed: {rule.WhenChanged}");
                }
            }
        }

        private void DisplayRules(TransportRule[] rules)
        {
            WriteHost("\n=== Transport Rules ===\n", ConsoleColor.Cyan);

            foreach (var rule in rules.OrderBy(r => r.Priority))
            {
                WriteHost($"[{rule.State?.ToUpper()}] ",
                    rule.State?.Equals("Enabled", StringComparison.OrdinalIgnoreCase) == true
                        ? ConsoleColor.Green : ConsoleColor.Yellow);
                WriteHost($"{rule.Name}\n");

                WriteHost($"  Priority: {rule.Priority}\n", ConsoleColor.Gray);
                WriteHost($"  Mode: {rule.Mode}\n", ConsoleColor.Gray);

                if (!string.IsNullOrWhiteSpace(rule.Description))
                {
                    WriteHost($"  Description: {rule.Description}\n", ConsoleColor.Gray);
                }

                if (rule.WhenChanged.HasValue)
                {
                    WriteHost($"  Last Modified: {rule.WhenChanged.Value:yyyy-MM-dd HH:mm:ss} UTC\n",
                        ConsoleColor.Gray);
                }

                WriteHost("\n");
            }
        }

        private void ExportToCsv(TransportRule[] rules)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            var filename = Path.Combine(OutputDir, $"{timestamp}-TransportRules.csv");

            var encoding = GetEncoding();

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

            Logger?.LogInfo($"Exported {rules.Length} transport rules to: {filename}");
            WriteHost($"\nExported to: {filename}\n", ConsoleColor.Green);
        }

        private void ExportToJson(TransportRule[] rules)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            var filename = Path.Combine(OutputDir, $"{timestamp}-TransportRules.json");

            var json = System.Text.Json.JsonSerializer.Serialize(rules, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
            });

            File.WriteAllText(filename, json, GetEncoding());

            Logger?.LogInfo($"Exported {rules.Length} transport rules to: {filename}");
            WriteHost($"\nExported to: {filename}\n", ConsoleColor.Green);
        }

        private void DisplaySummary()
        {
            WriteHost("\n=== Transport Rules Summary ===\n", ConsoleColor.Cyan);
            WriteHost($"Total Rules: {_stats.TotalRules}\n");
            WriteHost($"  - Enabled: {_stats.EnabledRules}\n", ConsoleColor.Green);
            WriteHost($"  - Disabled: {_stats.DisabledRules}\n", ConsoleColor.Yellow);

            if (_stats.TotalRules > 0)
            {
                WriteHost($"\nMode Distribution:\n");
                WriteHost($"  - Enforce: {_stats.EnforceMode}\n");
                WriteHost($"  - Audit: {_stats.AuditMode}\n");

                WriteHost($"\nPriority Range: {_stats.HighestPriority} - {_stats.LowestPriority}\n");

                if (_stats.RecentlyModified > 0)
                {
                    WriteHost($"Recently Modified (30 days): {_stats.RecentlyModified}\n",
                        ConsoleColor.Cyan);
                }
            }

            Logger?.LogInfo("Transport Rules Summary:");
            Logger?.LogInfo($"Total Rules: {_stats.TotalRules}");
            Logger?.LogInfo($"  - Enabled: {_stats.EnabledRules}");
            Logger?.LogInfo($"  - Disabled: {_stats.DisabledRules}");
        }

        private System.Text.Encoding GetEncoding()
        {
            return Encoding.ToUpper() switch
            {
                "UTF7" => System.Text.Encoding.UTF7,
                "ASCII" => System.Text.Encoding.ASCII,
                "UNICODE" => System.Text.Encoding.Unicode,
                "UTF32" => System.Text.Encoding.UTF32,
                _ => System.Text.Encoding.UTF8
            };
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
                Host.UI.Write(color.Value, Host.UI.RawUI.BackgroundColor, message);
            }
            else
            {
                Host.UI.Write(message);
            }
        }

        protected override void EndProcessing()
        {
            _exchangeClient?.Dispose();
            base.EndProcessing();
        }

        private class Statistics
        {
            public int TotalRules { get; set; }
            public int EnabledRules { get; set; }
            public int DisabledRules { get; set; }
            public int EnforceMode { get; set; }
            public int AuditMode { get; set; }
            public int HighestPriority { get; set; }
            public int LowestPriority { get; set; }
            public int RecentlyModified { get; set; }
        }
    }
}
