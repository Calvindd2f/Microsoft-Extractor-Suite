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
    /// Retrieves inbox rules from Exchange Online mailboxes.
    /// High-performance parallel processing with progress tracking.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "MailboxRules")]
    [OutputType(typeof(InboxRule))]
    [Alias("Get-InboxRules")]
    public class GetMailboxRulesCmdlet : BaseCmdlet
    {
        [Parameter(
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            HelpMessage = "Specific user(s) to check. Supports comma-separated values or array.")]
        [Alias("UserIds", "Users", "Mailbox")]
        public string[]? UserPrincipalNames { get; set; }

        [Parameter(
            HelpMessage = "Output directory for the CSV/JSON file. Default: Output\\Rules")]
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
            HelpMessage = "Show only enabled rules")]
        public SwitchParameter EnabledOnly { get; set; }

        [Parameter(
            HelpMessage = "Show rules with forwarding/redirect actions")]
        public SwitchParameter ForwardingOnly { get; set; }

        [Parameter(
            HelpMessage = "Show rules in console output")]
        public SwitchParameter ShowRules { get; set; }

        [Parameter(
            HelpMessage = "Maximum number of mailboxes to process in parallel")]
        [ValidateRange(1, 50)]
        public int MaxConcurrency { get; set; } = 10;

        [Parameter(
            HelpMessage = "Include detailed rule analysis in output")]
        public SwitchParameter DetailedAnalysis { get; set; }

        private ExchangeRestClient? _exchangeClient;
        private readonly Statistics _stats = new();
        private readonly List<InboxRule> _allRules = new();
        private readonly Dictionary<string, List<SecurityConcern>> _securityConcerns = new();

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

            Logger?.LogInfo("=== Starting Mailbox Rules Collection ===");
            
            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
                Logger.LogDebug($"PowerShell Version: {PSVersionTable.PSVersion}");
                Logger.LogDebug("Input parameters:");
                Logger.LogDebug($"  UserPrincipalNames: {(UserPrincipalNames != null ? string.Join(", ", UserPrincipalNames) : "All users")}");
                Logger.LogDebug($"  OutputDir: '{OutputDir}'");
                Logger.LogDebug($"  Encoding: '{Encoding}'");
                Logger.LogDebug($"  OutputFormat: '{OutputFormat}'");
                Logger.LogDebug($"  EnabledOnly: {EnabledOnly}");
                Logger.LogDebug($"  ForwardingOnly: {ForwardingOnly}");
                Logger.LogDebug($"  MaxConcurrency: {MaxConcurrency}");
                Logger.LogDebug($"  LogLevel: '{LogLevel}'");
            }
        }

        protected override void ProcessRecord()
        {
            try
            {
                var startTime = DateTime.UtcNow;
                WriteVerboseWithTimestamp("Starting mailbox rules collection...");

                // Process rules
                RunAsync(ProcessMailboxRulesAsync());

                var processingTime = DateTime.UtcNow - startTime;
                Logger?.LogInfo($"Processing completed in {processingTime.TotalSeconds:F2} seconds");

                if (_allRules.Count == 0)
                {
                    Logger?.LogWarning("No inbox rules found");
                    WriteWarning("No inbox rules found matching the criteria");
                    return;
                }

                // Apply filters
                var filteredRules = ApplyFilters(_allRules);

                if (filteredRules.Count == 0)
                {
                    Logger?.LogWarning("No rules remaining after applying filters");
                    WriteWarning("No rules found matching the specified filters");
                    return;
                }

                // Show rules in console if requested
                if (ShowRules)
                {
                    DisplayRules(filteredRules);
                }

                // Perform security analysis if requested
                if (DetailedAnalysis)
                {
                    PerformSecurityAnalysis(filteredRules);
                }

                // Output based on format
                switch (OutputFormat.ToUpper())
                {
                    case "CSV":
                        ExportToCsv(filteredRules);
                        break;
                    case "JSON":
                        ExportToJson(filteredRules);
                        break;
                    case "OBJECT":
                        foreach (var rule in filteredRules)
                        {
                            WriteObject(rule);
                        }
                        break;
                }

                // Display summary
                DisplaySummary();

                // Display security concerns if any
                if (_securityConcerns.Any())
                {
                    DisplaySecurityConcerns();
                }
            }
            catch (Exception ex)
            {
                Logger?.LogError($"Error retrieving mailbox rules: {ex.Message}", ex);
                WriteErrorWithTimestamp($"Failed to retrieve mailbox rules: {ex.Message}", ex);
            }
        }

        private async Task ProcessMailboxRulesAsync()
        {
            if (_exchangeClient == null)
            {
                throw new InvalidOperationException("Exchange client not initialized");
            }

            var progress = new Progress<(int processed, int total, string currentUser)>(report =>
            {
                var percentComplete = (int)((report.processed * 100.0) / report.total);
                WriteProgressSafe(
                    "Retrieving Mailbox Rules",
                    $"Processing {report.currentUser} ({report.processed}/{report.total})",
                    percentComplete);
                
                WriteVerboseWithTimestamp($"Processing mailbox {report.processed}/{report.total}: {report.currentUser}");
            });

            try
            {
                if (UserPrincipalNames != null && UserPrincipalNames.Any())
                {
                    // Process specific users
                    var users = UserPrincipalNames
                        .SelectMany(u => u.Split(',', StringSplitOptions.RemoveEmptyEntries))
                        .Select(u => u.Trim())
                        .Where(u => !string.IsNullOrWhiteSpace(u))
                        .Distinct()
                        .ToArray();

                    _stats.TotalUsers = users.Length;
                    Logger?.LogInfo($"Processing {users.Length} specific user(s)");

                    await foreach (var rule in _exchangeClient.GetAllMailboxInboxRulesAsync(
                        users, MaxConcurrency, progress, CancellationToken))
                    {
                        ProcessRule(rule);
                        _allRules.Add(rule);
                    }
                }
                else
                {
                    // Process all mailboxes
                    Logger?.LogInfo("Processing all mailboxes in the organization");
                    
                    await foreach (var rule in _exchangeClient.GetAllMailboxInboxRulesAsync(
                        null, MaxConcurrency, progress, CancellationToken))
                    {
                        ProcessRule(rule);
                        _allRules.Add(rule);
                    }
                }

                // Update user statistics
                _stats.UsersWithRules = _allRules
                    .Select(r => r.MailboxOwnerId)
                    .Distinct()
                    .Count();

                WriteProgressSafe("Retrieving Mailbox Rules", "Complete", 100);
            }
            catch (Exception ex)
            {
                Logger?.LogError($"Failed to retrieve mailbox rules: {ex.Message}", ex);
                throw new PSInvalidOperationException($"Failed to retrieve mailbox rules: {ex.Message}", ex);
            }
        }

        private void ProcessRule(InboxRule rule)
        {
            _stats.TotalRules++;

            if (rule.Enabled)
                _stats.EnabledRules++;

            if (rule.ForwardTo?.Any() == true)
                _stats.ForwardingRules++;

            if (rule.ForwardAsAttachmentTo?.Any() == true)
                _stats.ForwardAsAttachmentRules++;

            if (rule.RedirectTo?.Any() == true)
                _stats.RedirectRules++;

            if (rule.DeleteMessage)
                _stats.DeleteRules++;

            if (rule.SoftDeleteMessage)
                _stats.SoftDeleteRules++;

            if (rule.HasAttachment)
                _stats.HasAttachmentRules++;

            if (rule.StopProcessingRules)
                _stats.StopProcessingRules++;

            if (string.Equals(rule.MarkImportance, "High", StringComparison.OrdinalIgnoreCase))
                _stats.HighImportanceRules++;

            if (rule.InError)
                _stats.RulesInError++;

            // Check for security concerns
            CheckSecurityConcerns(rule);

            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
                Logger.LogDebug($"Processing rule: {rule.Name} for user: {rule.MailboxOwnerId}");
                Logger.LogDebug($"  Enabled: {rule.Enabled}");
                Logger.LogDebug($"  Priority: {rule.Priority}");
                if (rule.ForwardTo?.Any() == true)
                    Logger.LogDebug($"  Forward To: {string.Join(", ", rule.ForwardTo)}");
                if (rule.RedirectTo?.Any() == true)
                    Logger.LogDebug($"  Redirect To: {string.Join(", ", rule.RedirectTo)}");
            }
        }

        private void CheckSecurityConcerns(InboxRule rule)
        {
            var concerns = new List<SecurityConcern>();

            // Check for external forwarding
            if (rule.ForwardTo?.Any(IsExternalAddress) == true)
            {
                concerns.Add(new SecurityConcern
                {
                    Type = "External Forwarding",
                    Severity = "High",
                    Description = $"Rule forwards to external addresses: {string.Join(", ", rule.ForwardTo.Where(IsExternalAddress))}"
                });
            }

            if (rule.RedirectTo?.Any(IsExternalAddress) == true)
            {
                concerns.Add(new SecurityConcern
                {
                    Type = "External Redirect",
                    Severity = "High",
                    Description = $"Rule redirects to external addresses: {string.Join(", ", rule.RedirectTo.Where(IsExternalAddress))}"
                });
            }

            // Check for deletion rules
            if (rule.DeleteMessage && rule.Enabled)
            {
                concerns.Add(new SecurityConcern
                {
                    Type = "Message Deletion",
                    Severity = "Medium",
                    Description = "Rule permanently deletes messages"
                });
            }

            // Check for rules that stop processing
            if (rule.StopProcessingRules && rule.Priority < 10)
            {
                concerns.Add(new SecurityConcern
                {
                    Type = "Processing Blocker",
                    Severity = "Medium",
                    Description = $"High-priority rule (Priority: {rule.Priority}) stops further rule processing"
                });
            }

            // Check for suspicious patterns
            if (HasSuspiciousPatterns(rule))
            {
                concerns.Add(new SecurityConcern
                {
                    Type = "Suspicious Pattern",
                    Severity = "Low",
                    Description = "Rule contains patterns commonly used in attacks"
                });
            }

            if (concerns.Any())
            {
                var key = $"{rule.MailboxOwnerId}:{rule.Name}";
                _securityConcerns[key] = concerns;
            }
        }

        private bool IsExternalAddress(string address)
        {
            if (string.IsNullOrWhiteSpace(address))
                return false;

            // Simple check - in production, compare against organization's domains
            return !address.Contains("@" + AuthManager.CurrentTenantDomain);
        }

        private bool HasSuspiciousPatterns(InboxRule rule)
        {
            var suspiciousKeywords = new[] { "invoice", "payment", "urgent", "verify", "suspended", "security" };
            
            if (rule.SubjectContainsWords?.Any(w => 
                suspiciousKeywords.Any(s => w.Contains(s, StringComparison.OrdinalIgnoreCase))) == true)
                return true;

            if (rule.BodyContainsWords?.Any(w => 
                suspiciousKeywords.Any(s => w.Contains(s, StringComparison.OrdinalIgnoreCase))) == true)
                return true;

            return false;
        }

        private List<InboxRule> ApplyFilters(List<InboxRule> rules)
        {
            var filtered = rules.AsEnumerable();

            if (EnabledOnly)
            {
                filtered = filtered.Where(r => r.Enabled);
            }

            if (ForwardingOnly)
            {
                filtered = filtered.Where(r => 
                    r.ForwardTo?.Any() == true || 
                    r.RedirectTo?.Any() == true || 
                    r.ForwardAsAttachmentTo?.Any() == true);
            }

            return filtered.ToList();
        }

        private void DisplayRules(List<InboxRule> rules)
        {
            WriteHost("\n=== Mailbox Rules ===\n", ConsoleColor.Cyan);

            var groupedRules = rules.GroupBy(r => r.MailboxOwnerId).OrderBy(g => g.Key);

            foreach (var userGroup in groupedRules)
            {
                WriteHost($"\n{userGroup.Key}:\n", ConsoleColor.Yellow);

                foreach (var rule in userGroup.OrderBy(r => r.Priority))
                {
                    WriteHost($"  [{(rule.Enabled ? "ENABLED" : "DISABLED")}] ", 
                        rule.Enabled ? ConsoleColor.Green : ConsoleColor.Gray);
                    WriteHost($"{rule.Name}\n");

                    if (!string.IsNullOrWhiteSpace(rule.Description))
                    {
                        WriteHost($"    Description: {rule.Description}\n", ConsoleColor.Gray);
                    }

                    WriteHost($"    Priority: {rule.Priority}\n", ConsoleColor.Gray);

                    // Show actions
                    if (rule.ForwardTo?.Any() == true)
                    {
                        WriteHost($"    Forward To: {string.Join(", ", rule.ForwardTo)}\n", ConsoleColor.Red);
                    }
                    if (rule.RedirectTo?.Any() == true)
                    {
                        WriteHost($"    Redirect To: {string.Join(", ", rule.RedirectTo)}\n", ConsoleColor.Red);
                    }
                    if (rule.MoveToFolder != null)
                    {
                        WriteHost($"    Move To: {rule.MoveToFolder}\n", ConsoleColor.Gray);
                    }
                    if (rule.DeleteMessage)
                    {
                        WriteHost($"    Action: DELETE MESSAGE\n", ConsoleColor.Red);
                    }
                    if (rule.InError)
                    {
                        WriteHost($"    ERROR: {rule.ErrorType}\n", ConsoleColor.Red);
                    }
                }
            }
        }

        private void PerformSecurityAnalysis(List<InboxRule> rules)
        {
            Logger?.LogInfo("Performing security analysis on rules...");

            // Additional analysis logic
            var externalForwardingUsers = rules
                .Where(r => r.Enabled && 
                    (r.ForwardTo?.Any(IsExternalAddress) == true || 
                     r.RedirectTo?.Any(IsExternalAddress) == true))
                .Select(r => r.MailboxOwnerId)
                .Distinct()
                .Count();

            if (externalForwardingUsers > 0)
            {
                _stats.UsersWithExternalForwarding = externalForwardingUsers;
            }

            // Check for potential data exfiltration patterns
            var suspiciousRules = rules.Where(r => 
                r.Enabled && 
                (r.DeleteMessage || r.SoftDeleteMessage) &&
                (r.ForwardTo?.Any() == true || r.ForwardAsAttachmentTo?.Any() == true))
                .ToList();

            if (suspiciousRules.Any())
            {
                _stats.SuspiciousRules = suspiciousRules.Count;
            }
        }

        private void ExportToCsv(List<InboxRule> rules)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            var filename = Path.Combine(OutputDir, $"{timestamp}-MailboxRules.csv");

            var encoding = GetEncoding();

            using var writer = new StreamWriter(filename, false, encoding);

            // Write CSV header
            writer.WriteLine("UserName,RuleName,Enabled,Priority,RuleIdentity,StopProcessingRules," +
                           "CopyToFolder,MoveToFolder,RedirectTo,ForwardTo,ForwardAsAttachmentTo," +
                           "ApplyCategory,MarkImportance,MarkAsRead,DeleteMessage,SoftDeleteMessage," +
                           "From,SubjectContainsWords,SubjectOrBodyContainsWords,BodyContainsWords," +
                           "HasAttachment,Description,InError,ErrorType");

            // Write data
            foreach (var rule in rules.OrderBy(r => r.MailboxOwnerId).ThenBy(r => r.Priority))
            {
                writer.WriteLine(
                    $"\"{EscapeCsvField(rule.MailboxOwnerId)}\"," +
                    $"\"{EscapeCsvField(rule.Name)}\"," +
                    $"{rule.Enabled}," +
                    $"{rule.Priority}," +
                    $"\"{EscapeCsvField(rule.RuleIdentity)}\"," +
                    $"{rule.StopProcessingRules}," +
                    $"\"{EscapeCsvField(rule.CopyToFolder)}\"," +
                    $"\"{EscapeCsvField(rule.MoveToFolder)}\"," +
                    $"\"{JoinArray(rule.RedirectTo)}\"," +
                    $"\"{JoinArray(rule.ForwardTo)}\"," +
                    $"\"{JoinArray(rule.ForwardAsAttachmentTo)}\"," +
                    $"\"{JoinArray(rule.ApplyCategory)}\"," +
                    $"\"{rule.MarkImportance}\"," +
                    $"{rule.MarkAsRead}," +
                    $"{rule.DeleteMessage}," +
                    $"{rule.SoftDeleteMessage}," +
                    $"\"{JoinArray(rule.From)}\"," +
                    $"\"{JoinArray(rule.SubjectContainsWords)}\"," +
                    $"\"{JoinArray(rule.SubjectOrBodyContainsWords)}\"," +
                    $"\"{JoinArray(rule.BodyContainsWords)}\"," +
                    $"{rule.HasAttachment}," +
                    $"\"{EscapeCsvField(rule.Description)}\"," +
                    $"{rule.InError}," +
                    $"\"{EscapeCsvField(rule.ErrorType)}\"");
            }

            Logger?.LogInfo($"Exported {rules.Count} mailbox rules to: {filename}");
            WriteHost($"\nExported to: {filename}\n", ConsoleColor.Green);
        }

        private void ExportToJson(List<InboxRule> rules)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            var filename = Path.Combine(OutputDir, $"{timestamp}-MailboxRules.json");

            var output = new
            {
                ExportDate = DateTime.UtcNow,
                TotalRules = rules.Count,
                Statistics = _stats,
                SecurityConcerns = _securityConcerns,
                Rules = rules
            };

            var json = System.Text.Json.JsonSerializer.Serialize(output, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
            });

            File.WriteAllText(filename, json, GetEncoding());

            Logger?.LogInfo($"Exported {rules.Count} mailbox rules to: {filename}");
            WriteHost($"\nExported to: {filename}\n", ConsoleColor.Green);
        }

        private void DisplaySummary()
        {
            WriteHost("\n=== Mailbox Rules Summary ===\n", ConsoleColor.Cyan);
            WriteHost($"Users Processed: {_stats.TotalUsers}\n");
            WriteHost($"Users with Rules: {_stats.UsersWithRules}\n");
            WriteHost($"Total Rules Found: {_stats.TotalRules}\n");
            
            if (_stats.EnabledRules > 0)
                WriteHost($"  - Enabled Rules: {_stats.EnabledRules}\n", ConsoleColor.Green);
            
            if (_stats.ForwardingRules > 0)
                WriteHost($"  - Forwarding Rules: {_stats.ForwardingRules}\n", ConsoleColor.Yellow);
            
            if (_stats.ForwardAsAttachmentRules > 0)
                WriteHost($"  - Forward As Attachment: {_stats.ForwardAsAttachmentRules}\n", ConsoleColor.Yellow);
            
            if (_stats.RedirectRules > 0)
                WriteHost($"  - Redirect Rules: {_stats.RedirectRules}\n", ConsoleColor.Yellow);
            
            if (_stats.DeleteRules > 0)
                WriteHost($"  - Delete Rules: {_stats.DeleteRules}\n", ConsoleColor.Red);
            
            if (_stats.SoftDeleteRules > 0)
                WriteHost($"  - Soft Delete Rules: {_stats.SoftDeleteRules}\n", ConsoleColor.Yellow);
            
            if (_stats.RulesInError > 0)
                WriteHost($"  - Rules in Error: {_stats.RulesInError}\n", ConsoleColor.Red);
            
            if (_stats.UsersWithExternalForwarding > 0)
                WriteHost($"\nUsers with External Forwarding: {_stats.UsersWithExternalForwarding}\n", ConsoleColor.Red);
            
            if (_stats.SuspiciousRules > 0)
                WriteHost($"Suspicious Rules Detected: {_stats.SuspiciousRules}\n", ConsoleColor.Red);
        }

        private void DisplaySecurityConcerns()
        {
            WriteHost("\n=== Security Concerns ===\n", ConsoleColor.Red);

            var highSeverity = _securityConcerns
                .SelectMany(kvp => kvp.Value.Where(c => c.Severity == "High")
                    .Select(c => new { User = kvp.Key.Split(':')[0], Rule = kvp.Key.Split(':')[1], Concern = c }))
                .ToList();

            if (highSeverity.Any())
            {
                WriteHost("\nHIGH SEVERITY:\n", ConsoleColor.Red);
                foreach (var item in highSeverity)
                {
                    WriteHost($"  User: {item.User}\n");
                    WriteHost($"  Rule: {item.Rule}\n");
                    WriteHost($"  Issue: {item.Concern.Type} - {item.Concern.Description}\n\n");
                }
            }

            var mediumSeverity = _securityConcerns
                .SelectMany(kvp => kvp.Value.Where(c => c.Severity == "Medium")
                    .Select(c => new { User = kvp.Key.Split(':')[0], Rule = kvp.Key.Split(':')[1], Concern = c }))
                .ToList();

            if (mediumSeverity.Any())
            {
                WriteHost("\nMEDIUM SEVERITY:\n", ConsoleColor.Yellow);
                foreach (var item in mediumSeverity.Take(5)) // Show first 5
                {
                    WriteHost($"  User: {item.User}, Rule: {item.Rule}\n");
                    WriteHost($"  Issue: {item.Concern.Type}\n");
                }
                if (mediumSeverity.Count > 5)
                {
                    WriteHost($"  ... and {mediumSeverity.Count - 5} more\n");
                }
            }
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

            return field.Replace("\"", "\"\"");
        }

        private static string JoinArray(string[]? array)
        {
            if (array == null || array.Length == 0)
                return string.Empty;

            return string.Join("; ", array);
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
            public int TotalUsers { get; set; }
            public int UsersWithRules { get; set; }
            public int TotalRules { get; set; }
            public int EnabledRules { get; set; }
            public int ForwardingRules { get; set; }
            public int ForwardAsAttachmentRules { get; set; }
            public int RedirectRules { get; set; }
            public int DeleteRules { get; set; }
            public int SoftDeleteRules { get; set; }
            public int HasAttachmentRules { get; set; }
            public int StopProcessingRules { get; set; }
            public int HighImportanceRules { get; set; }
            public int RulesInError { get; set; }
            public int UsersWithExternalForwarding { get; set; }
            public int SuspiciousRules { get; set; }
        }

        private class SecurityConcern
        {
            public string Type { get; set; } = string.Empty;
            public string Severity { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
        }
    }
}