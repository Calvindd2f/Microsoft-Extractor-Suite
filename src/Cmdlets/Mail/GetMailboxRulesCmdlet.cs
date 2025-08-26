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
#pragma warning disable SA1600
        public string[]? UserPrincipalNames { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output directory for the CSV/JSON file. Default: Output\\Rules")]
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
            HelpMessage = "Show only enabled rules")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter EnabledOnly { get; set; }

        [Parameter(
            HelpMessage = "Show rules with forwarding/redirect actions")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter ForwardingOnly { get; set; }

        [Parameter(
            HelpMessage = "Show rules in console output")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter ShowRules { get; set; }

        [Parameter(
            HelpMessage = "Maximum number of mailboxes to process in parallel")]
        [ValidateRange(1, 50)]
#pragma warning disable SA1600
        public int MaxConcurrency { get; set; } = 10;
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Include detailed rule analysis in output")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1309
        public SwitchParameter DetailedAnalysis { get; set; }
#pragma warning disable SA1201
        private ExchangeRestClient? _exchangeClient;
#pragma warning restore SA1201
#pragma warning disable SA1309
        private readonly Statistics _stats = new();
#pragma warning disable SA1600
#pragma warning restore SA1309
sho
#pragma warning disable SA1309
        private readonly List<InboxRule> _allRules = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly Dictionary<string, List<SecurityConcern>> _securityConcerns = new();
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
            Logger?.LogInfo("=== Starting Mailbox Rules Collection ===");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
#pragma warning disable SA1101
                Logger.LogDebug($"PowerShell Version: {Host.Version}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug("Input parameters:");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  UserPrincipalNames: {(UserPrincipalNames != null ? string.Join(", ", UserPrincipalNames) : "All users")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  OutputDir: '{OutputDir}'");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  Encoding: '{Encoding}'");
#pragma warning restore SA1101
#pragma warning disable SA1600
#pragma warning disable SA1101
                Logger.LogDebug($"  OutputForma
#pragma warning restore SA1600
documentedt: '{OutputFormat}'");
                Logger.LogDebug($"  EnabledOnly: {EnabledOnly}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  ForwardingOnly: {ForwardingOnly}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  MaxConcurrency: {MaxConcurrency}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  LogLevel: '{LogLevel}'");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        protected override void ProcessRecord()
        {
            try
            {
                var startTime = DateTime.UtcNow;
#pragma warning disable SA1101
                WriteVerboseWithTimestamp("Starting mailbox rules collection...");
#pragma warning restore SA1101

                // Process rules
#pragma warning disable SA1101
                RunAsync(ProcessMailboxRulesAsync());
#pragma warning restore SA1101

                var processingTime = DateTime.UtcNow - startTime;
#pragma warning disable SA1101
                Logger?.LogInfo($"Processing completed in {processingTime.TotalSeconds:F2} seconds");
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (_allRules.Count == 0)
                {
#pragma warning disable SA1101
                    Logger?.WriteWarningWithTimestamp("No inbox rules found");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    WriteWarning("No inbox rules found matching the criteria");
#pragma warning restore SA1101
                    return;
                }
#pragma warning restore SA1101

                // Apply filters
#pragma warning disable SA1101
                var filteredRules = ApplyFilters(_allRules);
#pragma warning restore SA1101

                if (filteredRules.Count == 0)
                {
#pragma warning disable SA1101
                    Logger?.WriteWarningWithTimestamp("No rules remaining after applying filters");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    WriteWarning("No rules found matching the specified filters");
#pragma warning restore SA1101
                    return;
                }

                // Show rules in console if requested
#pragma warning disable SA1101
                if (ShowRules)
                {
#pragma warning disable SA1101
                    DisplayRules(filteredRules);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                // Perform security analysis if requested
#pragma warning disable SA1101
                if (DetailedAnalysis)
                {
#pragma warning disable SA1101
                    PerformSecurityAnalysis(filteredRules);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                // Output based on format
#pragma warning disable SA1101
                switch (OutputFormat.ToUpper())
                {
                    case "CSV":
#pragma warning disable SA1101
                        ExportToCsv(filteredRules);
#pragma warning restore SA1101
                        break;
                    case "JSON":
#pragma warning disable SA1101
                        ExportToJson(filteredRules);
#pragma warning restore SA1101
                        break;
                    case "OBJECT":
                        foreach (var rule in filteredRules)
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

                // Display security concerns if any
#pragma warning disable SA1101
                if (_securityConcerns.Any())
                {
#pragma warning disable SA1101
                    DisplaySecurityConcerns();
#pragma warning restore SA1101
                }
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                Logger?.WriteErrorWithTimestamp($"Error retrieving mailbox rules: {ex.Message}", ex);
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to retrieve mailbox rules: {ex.Message}", ex);
#pragma warning restore SA1101
            }
        }

        private async Task ProcessMailboxRulesAsync()
        {
#pragma warning disable SA1101
            if (_exchangeClient == null)
            {
                throw new InvalidOperationException("Exchange client not initialized");
            }
#pragma warning restore SA1101

            var progress = new Progress<(int processed, int total, string currentUser)>(report =>
            {
                var percentComplete = (int)((report.processed * 100.0) / report.total);
#pragma warning disable SA1101
                WriteProgressSafe(
                    "Retrieving Mailbox Rules",
                    $"Processing {report.currentUser} ({report.processed}/{report.total})",
                    percentComplete);
#pragma warning restore SA1101

#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"Processing mailbox {report.processed}/{report.total}: {report.currentUser}");
#pragma warning restore SA1101
            });

            try
            {
#pragma warning disable SA1101
                if (UserPrincipalNames != null && UserPrincipalNames.Any())
                {
                    // Process specific users
#pragma warning disable SA1101
                    var users = UserPrincipalNames
                        .SelectMany(u => u.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                        .Select(u => u.Trim())
                        .Where(u => !string.IsNullOrWhiteSpace(u))
                        .Distinct()
                        .ToArray();
#pragma warning restore SA1101

#pragma warning disable SA1101
                    _stats.TotalUsers = users.Length;
#pragma warning restore SA1101
#pragma warning disable SA1101
                    Logger?.LogInfo($"Processing {users.Length} specific user(s)");
#pragma warning restore SA1101

#pragma warning disable SA1101
                    await foreach (var rule in _exchangeClient.GetAllMailboxInboxRulesAsync(
                        users, MaxConcurrency, progress, CancellationToken))
                    {
#pragma warning disable SA1101
                        ProcessRule(rule);
#pragma warning restore SA1101
#pragma warning disable SA1101
                        _allRules.Add(rule);
#pragma warning restore SA1101
                    }
#pragma warning restore SA1101
                }
                else
                {
                    // Process all mailboxes
#pragma warning disable SA1101
                    Logger?.LogInfo("Processing all mailboxes in the organization");
#pragma warning restore SA1101

#pragma warning disable SA1101
                    await foreach (var rule in _exchangeClient.GetAllMailboxInboxRulesAsync(
                        null, MaxConcurrency, progress, CancellationToken))
                    {
#pragma warning disable SA1101
                        ProcessRule(rule);
#pragma warning restore SA1101
#pragma warning disable SA1101
                        _allRules.Add(rule);
#pragma warning restore SA1101
                    }
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                // Update user statistics
#pragma warning disable SA1101
                _stats.UsersWithRules = _allRules
                    .Select(r => r.MailboxOwnerId)
                    .Distinct()
                    .Count();
#pragma warning restore SA1101

#pragma warning disable SA1101
                WriteProgressSafe("Retrieving Mailbox Rules", "Complete", 100);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                Logger?.WriteErrorWithTimestamp($"Failed to retrieve mailbox rules: {ex.Message}", ex);
#pragma warning restore SA1101
                throw new PSInvalidOperationException($"Failed to retrieve mailbox rules: {ex.Message}", ex);
            }
        }

        private void ProcessRule(InboxRule rule)
        {
#pragma warning disable SA1101
            _stats.TotalRules++;
#pragma warning restore SA1101

            if (rule.Enabled)
#pragma warning disable SA1101
                _stats.EnabledRules++;
#pragma warning restore SA1101

            if (rule.ForwardTo?.Any() == true)
#pragma warning disable SA1101
                _stats.ForwardingRules++;
#pragma warning restore SA1101

            if (rule.ForwardAsAttachmentTo?.Any() == true)
#pragma warning disable SA1101
                _stats.ForwardAsAttachmentRules++;
#pragma warning restore SA1101

            if (rule.RedirectTo?.Any() == true)
#pragma warning disable SA1101
                _stats.RedirectRules++;
#pragma warning restore SA1101

            if (rule.DeleteMessage)
#pragma warning disable SA1101
                _stats.DeleteRules++;
#pragma warning restore SA1101

            if (rule.SoftDeleteMessage)
#pragma warning disable SA1101
                _stats.SoftDeleteRules++;
#pragma warning restore SA1101

            if (rule.HasAttachment)
#pragma warning disable SA1101
                _stats.HasAttachmentRules++;
#pragma warning restore SA1101

            if (rule.StopProcessingRules)
#pragma warning disable SA1101
                _stats.StopProcessingRules++;
#pragma warning restore SA1101

            if (string.Equals(rule.MarkImportance, "High", StringComparison.OrdinalIgnoreCase))
#pragma warning disable SA1101
                _stats.HighImportanceRules++;
#pragma warning restore SA1101

            if (rule.InError)
#pragma warning disable SA1101
                _stats.RulesInError++;
#pragma warning restore SA1101

            // Check for security concerns
#pragma warning disable SA1101
            CheckSecurityConcerns(rule);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
#pragma warning disable SA1101
                Logger.LogDebug($"Processing rule: {rule.Name} for user: {rule.MailboxOwnerId}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  Enabled: {rule.Enabled}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"  Priority: {rule.Priority}");
#pragma warning restore SA1101
                if (rule.ForwardTo?.Any() == true)
#pragma warning disable SA1101
                    Logger.LogDebug($"  Forward To: {string.Join(", ", rule.ForwardTo)}");
#pragma warning restore SA1101
                if (rule.RedirectTo?.Any() == true)
#pragma warning disable SA1101
                    Logger.LogDebug($"  Redirect To: {string.Join(", ", rule.RedirectTo)}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        private void CheckSecurityConcerns(InboxRule rule)
        {
            var concerns = new List<SecurityConcern>();

            // Check for external forwarding
#pragma warning disable SA1101
            if (rule.ForwardTo?.Any(IsExternalAddress) == true)
            {
#pragma warning disable SA1101
                concerns.Add(new SecurityConcern
                {
                    Type = "External Forwarding",
                    Severity = "High",
                    Description = $"Rule forwards to external addresses: {string.Join(", ", rule.ForwardTo.Where(IsExternalAddress))}"
                });
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (rule.RedirectTo?.Any(IsExternalAddress) == true)
            {
#pragma warning disable SA1101
                concerns.Add(new SecurityConcern
                {
                    Type = "External Redirect",
                    Severity = "High",
                    Description = $"Rule redirects to external addresses: {string.Join(", ", rule.RedirectTo.Where(IsExternalAddress))}"
                });
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

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
#pragma warning disable SA1101
            if (HasSuspiciousPatterns(rule))
            {
                concerns.Add(new SecurityConcern
                {
                    Type = "Suspicious Pattern",
                    Severity = "Low",
                    Description = "Rule contains patterns commonly used in attacks"
                });
            }
#pragma warning restore SA1101

            if (concerns.Any())
            {
                var key = $"{rule.MailboxOwnerId}:{rule.Name}";
#pragma warning disable SA1101
                _securityConcerns[key] = concerns;
#pragma warning restore SA1101
            }
        }

        private bool IsExternalAddress(string address)
        {
            if (string.IsNullOrWhiteSpace(address))
                return false;

            // Simple check - in production, compare against organization's domains
#pragma warning disable SA1101
            return !address.Contains("@" + AuthManager.CurrentTenantDomain);
#pragma warning restore SA1101
        }

        private bool HasSuspiciousPatterns(InboxRule rule)
        {
            var suspiciousKeywords = new[] { "invoice", "payment", "urgent", "verify", "suspended", "security" };

            if (rule.SubjectContainsWords?.Any(w =>
                suspiciousKeywords.Any(s => w.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0)) == true)
                return true;

            if (rule.BodyContainsWords?.Any(w =>
                suspiciousKeywords.Any(s => w.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0)) == true)
                return true;

            return false;
        }

        private List<InboxRule> ApplyFilters(List<InboxRule> rules)
        {
            var filtered = rules.AsEnumerable();

#pragma warning disable SA1101
            if (EnabledOnly)
            {
                filtered = filtered.Where(r => r.Enabled);
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (ForwardingOnly)
            {
                filtered = filtered.Where(r =>
                    r.ForwardTo?.Any() == true ||
                    r.RedirectTo?.Any() == true ||
                    r.ForwardAsAttachmentTo?.Any() == true);
            }
#pragma warning restore SA1101

            return filtered.ToList();
        }

        private void DisplayRules(List<InboxRule> rules)
        {
#pragma warning disable SA1101
            WriteHost("\n=== Mailbox Rules ===\n", ConsoleColor.Cyan);
#pragma warning restore SA1101

            var groupedRules = rules.GroupBy(r => r.MailboxOwnerId).OrderBy(g => g.Key);

            foreach (var userGroup in groupedRules)
            {
#pragma warning disable SA1101
                WriteHost($"\n{userGroup.Key}:\n", ConsoleColor.Yellow);
#pragma warning restore SA1101

                foreach (var rule in userGroup.OrderBy(r => r.Priority))
                {
#pragma warning disable SA1101
                    WriteHost($"  [{(rule.Enabled ? "ENABLED" : "DISABLED")}] ",
                        rule.Enabled ? ConsoleColor.Green : ConsoleColor.Gray);
#pragma warning restore SA1101
#pragma warning disable SA1101
                    WriteHost($"{rule.Name}\n");
#pragma warning restore SA1101

                    if (!string.IsNullOrWhiteSpace(rule.Description))
                    {
#pragma warning disable SA1101
                        WriteHost($"    Description: {rule.Description}\n", ConsoleColor.Gray);
#pragma warning restore SA1101
                    }

#pragma warning disable SA1101
                    WriteHost($"    Priority: {rule.Priority}\n", ConsoleColor.Gray);
#pragma warning restore SA1101

                    // Show actions
                    if (rule.ForwardTo?.Any() == true)
                    {
#pragma warning disable SA1101
                        WriteHost($"    Forward To: {string.Join(", ", rule.ForwardTo)}\n", ConsoleColor.Red);
#pragma warning restore SA1101
                    }
                    if (rule.RedirectTo?.Any() == true)
                    {
#pragma warning disable SA1101
                        WriteHost($"    Redirect To: {string.Join(", ", rule.RedirectTo)}\n", ConsoleColor.Red);
#pragma warning restore SA1101
                    }
                    if (rule.MoveToFolder != null)
                    {
#pragma warning disable SA1101
                        WriteHost($"    Move To: {rule.MoveToFolder}\n", ConsoleColor.Gray);
#pragma warning restore SA1101
                    }
                    if (rule.DeleteMessage)
                    {
#pragma warning disable SA1101
                        WriteHost($"    Action: DELETE MESSAGE\n", ConsoleColor.Red);
#pragma warning restore SA1101
                    }
                    if (rule.InError)
                    {
#pragma warning disable SA1101
                        WriteHost($"    ERROR: {rule.ErrorType}\n", ConsoleColor.Red);
#pragma warning restore SA1101
                    }
                }
            }
        }

        private void PerformSecurityAnalysis(List<InboxRule> rules)
        {
#pragma warning disable SA1101
            Logger?.LogInfo("Performing security analysis on rules...");
#pragma warning restore SA1101

            // Additional analysis logic
#pragma warning disable SA1101
            var externalForwardingUsers = rules
                .Where(r => r.Enabled &&
                    (r.ForwardTo?.Any(IsExternalAddress) == true ||
                     r.RedirectTo?.Any(IsExternalAddress) == true))
                .Select(r => r.MailboxOwnerId)
                .Distinct()
                .Count();
#pragma warning restore SA1101

            if (externalForwardingUsers > 0)
            {
#pragma warning disable SA1101
                _stats.UsersWithExternalForwarding = externalForwardingUsers;
#pragma warning restore SA1101
            }

            // Check for potential data exfiltration patterns
            var suspiciousRules = rules.Where(r =>
                r.Enabled &&
                (r.DeleteMessage || r.SoftDeleteMessage) &&
                (r.ForwardTo?.Any() == true || r.ForwardAsAttachmentTo?.Any() == true))
                .ToList();

            if (suspiciousRules.Any())
            {
#pragma warning disable SA1101
                _stats.SuspiciousRules = suspiciousRules.Count;
#pragma warning restore SA1101
            }
        }

        private void ExportToCsv(List<InboxRule> rules)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
#pragma warning disable SA1101
            var filename = Path.Combine(OutputDir, $"{timestamp}-MailboxRules.csv");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var encoding = GetEncoding();
#pragma warning restore SA1101

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

#pragma warning disable SA1101
            Logger?.LogInfo($"Exported {rules.Count} mailbox rules to: {filename}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"\nExported to: {filename}\n", ConsoleColor.Green);
#pragma warning restore SA1101
        }

        private void ExportToJson(List<InboxRule> rules)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
#pragma warning disable SA1101
            var filename = Path.Combine(OutputDir, $"{timestamp}-MailboxRules.json");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var output = new
            {
                ExportDate = DateTime.UtcNow,
                TotalRules = rules.Count,
                Statistics = _stats,
                SecurityConcerns = _securityConcerns,
                Rules = rules
            };
#pragma warning restore SA1101

            var json = System.Text.Json.JsonSerializer.Serialize(output, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
            });

#pragma warning disable SA1101
            File.WriteAllText(filename, json, GetEncoding());
#pragma warning restore SA1101

#pragma warning disable SA1101
            Logger?.LogInfo($"Exported {rules.Count} mailbox rules to: {filename}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"\nExported to: {filename}\n", ConsoleColor.Green);
#pragma warning restore SA1101
        }

        private void DisplaySummary()
        {
#pragma warning disable SA1101
            WriteHost("\n=== Mailbox Rules Summary ===\n", ConsoleColor.Cyan);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Users Processed: {_stats.TotalUsers}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Users with Rules: {_stats.UsersWithRules}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Total Rules Found: {_stats.TotalRules}\n");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.EnabledRules > 0)
#pragma warning disable SA1101
                WriteHost($"  - Enabled Rules: {_stats.EnabledRules}\n", ConsoleColor.Green);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.ForwardingRules > 0)
#pragma warning disable SA1101
                WriteHost($"  - Forwarding Rules: {_stats.ForwardingRules}\n", ConsoleColor.Yellow);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.ForwardAsAttachmentRules > 0)
#pragma warning disable SA1101
                WriteHost($"  - Forward As Attachment: {_stats.ForwardAsAttachmentRules}\n", ConsoleColor.Yellow);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.RedirectRules > 0)
#pragma warning disable SA1101
                WriteHost($"  - Redirect Rules: {_stats.RedirectRules}\n", ConsoleColor.Yellow);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.DeleteRules > 0)
#pragma warning disable SA1101
                WriteHost($"  - Delete Rules: {_stats.DeleteRules}\n", ConsoleColor.Red);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.SoftDeleteRules > 0)
#pragma warning disable SA1101
                WriteHost($"  - Soft Delete Rules: {_stats.SoftDeleteRules}\n", ConsoleColor.Yellow);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.RulesInError > 0)
#pragma warning disable SA1101
                WriteHost($"  - Rules in Error: {_stats.RulesInError}\n", ConsoleColor.Red);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.UsersWithExternalForwarding > 0)
#pragma warning disable SA1101
                WriteHost($"\nUsers with External Forwarding: {_stats.UsersWithExternalForwarding}\n", ConsoleColor.Red);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.SuspiciousRules > 0)
#pragma warning disable SA1101
                WriteHost($"Suspicious Rules Detected: {_stats.SuspiciousRules}\n", ConsoleColor.Red);
#pragma warning restore SA1101
        }

        private void DisplaySecurityConcerns()
        {
#pragma warning disable SA1101
            WriteHost("\n=== Security Concerns ===\n", ConsoleColor.Red);
#pragma warning restore SA1101

#pragma warning disable SA1101
            var highSeverity = _securityConcerns
                .SelectMany(kvp => kvp.Value.Where(c => c.Severity == "High")
                    .Select(c => new { User = kvp.Key.Split(':')[0], Rule = kvp.Key.Split(':')[1], Concern = c }))
                .ToList();
#pragma warning restore SA1101

            if (highSeverity.Any())
            {
#pragma warning disable SA1101
                WriteHost("\nHIGH SEVERITY:\n", ConsoleColor.Red);
#pragma warning restore SA1101
                foreach (var item in highSeverity)
                {
#pragma warning disable SA1101
                    WriteHost($"  User: {item.User}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    WriteHost($"  Rule: {item.Rule}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    WriteHost($"  Issue: {item.Concern.Type} - {item.Concern.Description}\n\n");
#pragma warning restore SA1101
                }
            }

#pragma warning disable SA1101
            var mediumSeverity = _securityConcerns
                .SelectMany(kvp => kvp.Value.Where(c => c.Severity == "Medium")
                    .Select(c => new { User = kvp.Key.Split(':')[0], Rule = kvp.Key.Split(':')[1], Concern = c }))
                .ToList();
#pragma warning restore SA1101

            if (mediumSeverity.Any())
            {
#pragma warning disable SA1101
                WriteHost("\nMEDIUM SEVERITY:\n", ConsoleColor.Yellow);
#pragma warning restore SA1101
                foreach (var item in mediumSeverity.Take(5)) // Show first 5
                {
#pragma warning disable SA1101
                    WriteHost($"  User: {item.User}, Rule: {item.Rule}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    WriteHost($"  Issue: {item.Concern.Type}\n");
#pragma warning restore SA1101
                }
                if (mediumSeverity.Count > 5)
                {
#pragma warning disable SA1101
                    WriteHost($"  ... and {mediumSeverity.Count - 5} more\n");
#pragma warning restore SA1101
                }
            }
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
#pragma warning disable SA1600
#pragma warning disable SA1101
                Host.UI.Write(color.Value, Host
#pragma warning restore SA1101
#pragma warning restore SA1600
message);
            }
            else
            {
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
            public int TotalUsers { get; set; }public int UsersWithRules { get; set; }public int TotalRules { get; set; }public int EnabledRules { get; set; }public int ForwardingRules { get; set; }public int ForwardAsAttachmentRules { get; set; }public int RedirectRules { get; set; }public int DeleteRules { get; set; }public int SoftDeleteRules { get; set; }public int HasAttachmentRules { get; set; }public int StopProcessingRules { get; set; }public int HighImportanceRules { get; set; }public int RulesInError { get; set; }public int UsersWithExternalForwarding { get; set; }public int SuspiciousRules { get; set; }}

        private class SecurityConcern
        {
            public string Type { get; set; } = string.Empty;
            public string Severity { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
        }
    }
}
