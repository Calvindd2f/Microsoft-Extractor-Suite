using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Exchange;

namespace Microsoft.ExtractorSuite.Cmdlets.Mail
{
    /// <summary>
    /// Cmdlet to collect transport rules and mailbox rules for security analysis
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "Rules")]
    [OutputType(typeof(RulesResult))]
    public class GetRulesCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve mailbox rules for. If not specified, retrieves for all users")]
        public string[] UserIds { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
        public string OutputDir { get; set; } = "Output\\Rules";

        [Parameter(
            HelpMessage = "File encoding for output files")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(
            HelpMessage = "Rule type to collect: TransportRules, MailboxRules, or Both")]
        [ValidateSet("TransportRules", "MailboxRules", "Both")]
        public string RuleType { get; set; } = "Both";

        [Parameter(
            HelpMessage = "Show rules in the console output")]
        public SwitchParameter ShowRules { get; set; }

        private readonly ExchangeRestClient _exchangeClient;

        public GetRulesCmdlet()
        {
            _exchangeClient = new ExchangeRestClient();
        }

        protected override async Task ProcessRecordAsync()
        {
            WriteVerbose("=== Starting Rules Collection ===");

            // Check for authentication
            if (!await _exchangeClient.IsConnectedAsync())
            {
                WriteErrorWithTimestamp("Not connected to Exchange Online. Please run Connect-M365 first.");
                return;
            }

            var outputDirectory = GetOutputDirectory();
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmm");

            var summary = new RulesSummary
            {
                StartTime = DateTime.Now,
                TotalTransportRules = 0,
                EnabledTransportRules = 0,
                DisabledTransportRules = 0,
                TotalMailboxRules = 0,
                EnabledMailboxRules = 0,
                UsersWithRules = 0,
                ForwardingRules = 0,
                RedirectRules = 0,
                SoftDeleteRules = 0,
                OutputFiles = new List<string>()
            };

            try
            {
                switch (RuleType.ToUpperInvariant())
                {
                    case "TRANSPORTRULES":
                        await ProcessTransportRulesAsync(outputDirectory, timestamp, summary);
                        break;
                    case "MAILBOXRULES":
                        await ProcessMailboxRulesAsync(outputDirectory, timestamp, summary);
                        break;
                    case "BOTH":
                        await ProcessTransportRulesAsync(outputDirectory, timestamp, summary);
                        await ProcessMailboxRulesAsync(outputDirectory, timestamp, summary);
                        break;
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
                LogSummary(summary);

                var result = new RulesResult
                {
                    TransportRules = new List<TransportRule>(),
                    MailboxRules = new List<MailboxRule>(),
                    Summary = summary
                };

                WriteObject(result);
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during rules collection: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessTransportRulesAsync(string outputDirectory, string timestamp, RulesSummary summary)
        {
            WriteVerbose("=== Starting Transport Rules Collection ===");

            var transportRules = new List<TransportRule>();

            try
            {
                var rules = await _exchangeClient.GetTransportRulesAsync();

                if (rules == null || rules.Count == 0)
                {
                    WriteVerbose("No transport rules found");
                    return;
                }

                foreach (var rule in rules)
                {
                    var transportRule = new TransportRule
                    {
                        Name = rule.Name,
                        Description = rule.Description,
                        CreatedBy = rule.CreatedBy,
                        WhenChanged = rule.WhenChanged,
                        State = rule.State,
                        Priority = rule.Priority,
                        Mode = rule.Mode
                    };

                    transportRules.Add(transportRule);
                    summary.TotalTransportRules++;

                    if (rule.State?.ToLowerInvariant() == "enabled")
                        summary.EnabledTransportRules++;
                    else if (rule.State?.ToLowerInvariant() == "disabled")
                        summary.DisabledTransportRules++;

                    if (ShowRules)
                    {
                        WriteVerbose($"Found a TransportRule:");
                        WriteVerbose($"  Rule Name: {rule.Name}");
                        WriteVerbose($"  Rule CreatedBy: {rule.CreatedBy}");
                        WriteVerbose($"  When Changed: {rule.WhenChanged}");
                        WriteVerbose($"  Rule State: {rule.State}");
                        WriteVerbose($"  Description: {rule.Description}");
                    }
                }

                if (transportRules.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-TransportRules.csv");
                    await WriteTransportRulesAsync(transportRules, fileName);
                    summary.OutputFiles.Add(fileName);

                    WriteVerbose($"Transport rules written to: {fileName}");
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during transport rules collection: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessMailboxRulesAsync(string outputDirectory, string timestamp, RulesSummary summary)
        {
            WriteVerbose("=== Starting Mailbox Rules Collection ===");

            var mailboxRules = new List<MailboxRule>();
            var processedUsers = new HashSet<string>();

            try
            {
                var usersToProcess = await GetUsersToProcessAsync();

                foreach (var user in usersToProcess)
                {
                    try
                    {
                        WriteVerbose($"Checking rules for: {user}");

                        var rules = await _exchangeClient.GetInboxRulesAsync(user);

                        if (rules != null && rules.Count > 0)
                        {
                            if (!processedUsers.Contains(user))
                            {
                                summary.UsersWithRules++;
                                processedUsers.Add(user);
                            }

                            foreach (var rule in rules)
                            {
                                var mailboxRule = new MailboxRule
                                {
                                    UserName = user,
                                    RuleName = rule.Name,
                                    Enabled = rule.Enabled,
                                    Priority = rule.Priority,
                                    RuleIdentity = rule.RuleIdentity,
                                    StopProcessingRules = rule.StopProcessingRules,
                                    CopyToFolder = rule.CopyToFolder,
                                    MoveToFolder = rule.MoveToFolder,
                                    RedirectTo = rule.RedirectTo,
                                    ForwardTo = rule.ForwardTo,
                                    ForwardAsAttachmentTo = rule.ForwardAsAttachmentTo,
                                    ApplyCategory = string.Join(", ", rule.ApplyCategory ?? new string[0]),
                                    MarkImportance = rule.MarkImportance,
                                    MarkAsRead = rule.MarkAsRead,
                                    DeleteMessage = rule.DeleteMessage,
                                    SoftDeleteMessage = rule.SoftDeleteMessage,
                                    From = rule.From,
                                    SubjectContainsWords = string.Join(", ", rule.SubjectContainsWords ?? new string[0]),
                                    SubjectOrBodyContainsWords = string.Join(", ", rule.SubjectOrBodyContainsWords ?? new string[0]),
                                    BodyContainsWords = string.Join(", ", rule.BodyContainsWords ?? new string[0]),
                                    HasAttachment = rule.HasAttachment,
                                    Description = rule.Description,
                                    InError = rule.InError,
                                    ErrorType = rule.ErrorType
                                };

                                mailboxRules.Add(mailboxRule);
                                summary.TotalMailboxRules++;

                                if (rule.Enabled)
                                    summary.EnabledMailboxRules++;

                                if (!string.IsNullOrEmpty(rule.ForwardTo))
                                    summary.ForwardingRules++;

                                if (!string.IsNullOrEmpty(rule.RedirectTo))
                                    summary.RedirectRules++;

                                if (rule.SoftDeleteMessage)
                                    summary.SoftDeleteRules++;

                                if (ShowRules)
                                {
                                    WriteVerbose($"Found InboxRule for: {user}");
                                    WriteVerbose($"  Username: {user}");
                                    WriteVerbose($"  RuleName: {rule.Name}");
                                    WriteVerbose($"  RuleEnabled: {rule.Enabled}");
                                    WriteVerbose($"  CopytoFolder: {rule.CopyToFolder}");
                                    WriteVerbose($"  MovetoFolder: {rule.MoveToFolder}");
                                    WriteVerbose($"  RedirectTo: {rule.RedirectTo}");
                                    WriteVerbose($"  ForwardTo: {rule.ForwardTo}");
                                    WriteVerbose($"  ForwardAsAttachmentTo: {rule.ForwardAsAttachmentTo}");
                                    WriteVerbose($"  SoftDeleteMessage: {rule.SoftDeleteMessage}");
                                    WriteVerbose($"  TextDescription: {rule.Description}");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteWarningWithTimestamp($"Failed to process rules for user {user}: {ex.Message}");
                    }
                }

                if (mailboxRules.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-MailboxRules.csv");
                    await WriteMailboxRulesAsync(mailboxRules, fileName);
                    summary.OutputFiles.Add(fileName);

                    WriteVerbose($"Mailbox rules written to: {fileName}");
                }

                if (summary.TotalMailboxRules > 0)
                {
                    WriteVerbose($"A total of {summary.TotalMailboxRules} Inbox Rules found");
                }
                else
                {
                    WriteVerbose("No Inbox Rules found!");
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during mailbox rules collection: {ex.Message}");
                throw;
            }
        }

        private async Task<List<string>> GetUsersToProcessAsync()
        {
            var users = new List<string>();

            if (UserIds != null && UserIds.Length > 0)
            {
                // Use specified users
                users.AddRange(UserIds);
            }
            else
            {
                // Get all mailboxes
                var mailboxes = await _exchangeClient.GetMailboxesAsync(unlimited: true);
                users.AddRange(mailboxes.Select(m => m.UserPrincipalName));
            }

            return users;
        }

        private string GetOutputDirectory()
        {
            var directory = OutputDir;

            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
                WriteVerbose($"Created output directory: {directory}");
            }

            return directory;
        }

        private void LogSummary(RulesSummary summary)
        {
            WriteVerbose("");
            WriteVerbose("=== Rules Collection Summary ===");
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");

            if (RuleType == "TransportRules" || RuleType == "Both")
            {
                WriteVerbose("");
                WriteVerbose("Transport Rules:");
                WriteVerbose($"  Total Rules: {summary.TotalTransportRules}");
                WriteVerbose($"  - Enabled: {summary.EnabledTransportRules}");
                WriteVerbose($"  - Disabled: {summary.DisabledTransportRules}");
            }

            if (RuleType == "MailboxRules" || RuleType == "Both")
            {
                WriteVerbose("");
                WriteVerbose("Mailbox Rules:");
                WriteVerbose($"  Users Processed: {summary.UsersWithRules}");
                WriteVerbose($"  Total Rules Found: {summary.TotalMailboxRules}");
                WriteVerbose($"  - Enabled Rules: {summary.EnabledMailboxRules}");

                if (summary.ForwardingRules > 0)
                    WriteVerbose($"  - Forwarding Rules: {summary.ForwardingRules}");

                if (summary.RedirectRules > 0)
                    WriteVerbose($"  - Redirect Rules: {summary.RedirectRules}");

                if (summary.SoftDeleteRules > 0)
                    WriteVerbose($"  - Soft Delete Rules: {summary.SoftDeleteRules}");
            }

            WriteVerbose("");
            WriteVerbose("Output Files:");
            foreach (var file in summary.OutputFiles)
            {
                WriteVerbose($"  - {file}");
            }
            WriteVerbose("================================");
        }

        private async Task WriteTransportRulesAsync(IEnumerable<TransportRule> rules, string filePath)
        {
            var csv = "Name,Description,CreatedBy,WhenChanged,State,Priority,Mode" + Environment.NewLine;

            foreach (var rule in rules)
            {
                var values = new[]
                {
                    EscapeCsvValue(rule.Name),
                    EscapeCsvValue(rule.Description),
                    EscapeCsvValue(rule.CreatedBy),
                    rule.WhenChanged?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(rule.State),
                    rule.Priority?.ToString() ?? "",
                    EscapeCsvValue(rule.Mode)
                };

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteMailboxRulesAsync(IEnumerable<MailboxRule> rules, string filePath)
        {
            var csv = "UserName,RuleName,Enabled,Priority,RuleIdentity,StopProcessingRules,CopyToFolder,MoveToFolder,RedirectTo,ForwardTo,ForwardAsAttachmentTo,ApplyCategory,MarkImportance,MarkAsRead,DeleteMessage,SoftDeleteMessage,From,SubjectContainsWords,SubjectOrBodyContainsWords,BodyContainsWords,HasAttachment,Description,InError,ErrorType" + Environment.NewLine;

            foreach (var rule in rules)
            {
                var values = new[]
                {
                    EscapeCsvValue(rule.UserName),
                    EscapeCsvValue(rule.RuleName),
                    rule.Enabled.ToString(),
                    rule.Priority?.ToString() ?? "",
                    EscapeCsvValue(rule.RuleIdentity),
                    rule.StopProcessingRules.ToString(),
                    EscapeCsvValue(rule.CopyToFolder),
                    EscapeCsvValue(rule.MoveToFolder),
                    EscapeCsvValue(rule.RedirectTo),
                    EscapeCsvValue(rule.ForwardTo),
                    EscapeCsvValue(rule.ForwardAsAttachmentTo),
                    EscapeCsvValue(rule.ApplyCategory),
                    EscapeCsvValue(rule.MarkImportance),
                    rule.MarkAsRead.ToString(),
                    rule.DeleteMessage.ToString(),
                    rule.SoftDeleteMessage.ToString(),
                    EscapeCsvValue(rule.From),
                    EscapeCsvValue(rule.SubjectContainsWords),
                    EscapeCsvValue(rule.SubjectOrBodyContainsWords),
                    EscapeCsvValue(rule.BodyContainsWords),
                    rule.HasAttachment.ToString(),
                    EscapeCsvValue(rule.Description),
                    rule.InError.ToString(),
                    EscapeCsvValue(rule.ErrorType)
                };

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private string EscapeCsvValue(string value)
        {
            if (string.IsNullOrEmpty(value))
                return "";

            if (value.Contains(",") || value.Contains("\"") || value.Contains("\n"))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }

            return value;
        }
    }

    // Supporting classes
    public class RulesResult
    {
        public List<TransportRule> TransportRules { get; set; } = new List<TransportRule>();
        public List<MailboxRule> MailboxRules { get; set; } = new List<MailboxRule>();
        public RulesSummary Summary { get; set; }
    }

    public class TransportRule
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string CreatedBy { get; set; }
        public DateTime? WhenChanged { get; set; }
        public string State { get; set; }
        public int? Priority { get; set; }
        public string Mode { get; set; }
    }

    public class MailboxRule
    {
        public string UserName { get; set; }
        public string RuleName { get; set; }
        public bool Enabled { get; set; }
        public int? Priority { get; set; }
        public string RuleIdentity { get; set; }
        public bool StopProcessingRules { get; set; }
        public string CopyToFolder { get; set; }
        public string MoveToFolder { get; set; }
        public string RedirectTo { get; set; }
        public string ForwardTo { get; set; }
        public string ForwardAsAttachmentTo { get; set; }
        public string ApplyCategory { get; set; }
        public string MarkImportance { get; set; }
        public bool MarkAsRead { get; set; }
        public bool DeleteMessage { get; set; }
        public bool SoftDeleteMessage { get; set; }
        public string From { get; set; }
        public string SubjectContainsWords { get; set; }
        public string SubjectOrBodyContainsWords { get; set; }
        public string BodyContainsWords { get; set; }
        public bool HasAttachment { get; set; }
        public string Description { get; set; }
        public bool InError { get; set; }
        public string ErrorType { get; set; }
    }

    public class RulesSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public int TotalTransportRules { get; set; }
        public int EnabledTransportRules { get; set; }
        public int DisabledTransportRules { get; set; }
        public int TotalMailboxRules { get; set; }
        public int EnabledMailboxRules { get; set; }
        public int UsersWithRules { get; set; }
        public int ForwardingRules { get; set; }
        public int RedirectRules { get; set; }
        public int SoftDeleteRules { get; set; }
        public List<string> OutputFiles { get; set; } = new List<string>();
    }
}
