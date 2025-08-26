namespace Microsoft.ExtractorSuite.Cmdlets.Mail
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Exchange;
    using Microsoft.ExtractorSuite.Models.Exchange;


    /// <summary>
    /// Cmdlet to collect transport rules and mailbox rules for security analysis
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "Rules")]
    [OutputType(typeof(RulesResult))]
    public class GetRulesCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve mailbox rules for. If not specified, retrieves for all users")]
#pragma warning disable SA1600
        public string[] UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
#pragma warning disable SA1600
        public string OutputDir { get; set; } = "Output\\Rules";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "File encoding for output files")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Rule type to collect: TransportRules, MailboxRules, or Both")]
        [ValidateSet("TransportRules", "MailboxRules", "Both")]
#pragma warning disable SA1600
        public string RuleType { get; set; } = "Both";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Show rules in the console output")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1309
        public SwitchParameter ShowRules { get; set; }
#pragma warning disable SA1201
        private readonly ExchangeRestClient _exchangeClient;
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning restore SA1309

        public GetRulesCmdlet()
        {
#pragma warning disable SA1101
            _exchangeClient = new ExchangeRestClient(AuthManager);
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected override async Task ProcessRecordAsync()
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting Rules Collection ===");
#pragma warning restore SA1101

            // Check for authentication
#pragma warning disable SA1101
            if (!await _exchangeClient.IsConnectedAsync())
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp("Not connected to Exchange Online. Please run Connect-M365 first.");
#pragma warning restore SA1101
                return;
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            var outputDirectory = GetOutputDirectory();
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                switch (RuleType.ToUpperInvariant())
                {
                    case "TRANSPORTRULES":
#pragma warning disable SA1101
                        await ProcessTransportRulesAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                    case "MAILBOXRULES":
#pragma warning disable SA1101
                        await ProcessMailboxRulesAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                    case "BOTH":
#pragma warning disable SA1101
                        await ProcessTransportRulesAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
#pragma warning disable SA1101
                        await ProcessMailboxRulesAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                }
#pragma warning restore SA1101

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
#pragma warning disable SA1101
                LogSummary(summary);
#pragma warning restore SA1101

                var result = new RulesResult
                {
                    TransportRules = new List<TransportRuleInfo>(),
                    MailboxRules = new List<MailboxRuleInfo>(),
                    Summary = summary
                };

#pragma warning disable SA1101
                WriteObject(result);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during rules collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task ProcessTransportRulesAsync(string outputDirectory, string timestamp, RulesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting Transport Rules Collection ===");
#pragma warning restore SA1101

            var transportRules = new List<TransportRuleInfo>();

            try
            {
#pragma warning disable SA1101
                var rules = await _exchangeClient.GetTransportRulesTypedAsync();
#pragma warning restore SA1101

                if (rules == null || rules.Length == 0)
                {
#pragma warning disable SA1101
                    WriteVerbose("No transport rules found");
#pragma warning restore SA1101
                    return;
                }

                foreach (var rule in rules)
                {
                    var transportRule = new TransportRuleInfo
                    {
                        Name = rule.Name,
                        Description = rule.Description,
                        CreatedBy = rule.Identity, // Use Identity instead of CreatedBy
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

#pragma warning disable SA1101
                    if (ShowRules)
                    {
#pragma warning disable SA1101
                        WriteVerbose($"Found a TransportRule:");
#pragma warning restore SA1101
#pragma warning disable SA1101
                        WriteVerbose($"  Rule Name: {rule.Name}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                        WriteVerbose($"  Rule Identity: {rule.Identity}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                        WriteVerbose($"  When Changed: {rule.WhenChanged}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                        WriteVerbose($"  Rule State: {rule.State}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                        WriteVerbose($"  Description: {rule.Description}");
#pragma warning restore SA1101
                    }
#pragma warning restore SA1101
                }

                if (transportRules.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-TransportRules.csv");
#pragma warning disable SA1101
                    await WriteTransportRulesAsync(transportRules, fileName);
#pragma warning restore SA1101
                    summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                    WriteVerbose($"Transport rules written to: {fileName}");
#pragma warning restore SA1101
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during transport rules collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task ProcessMailboxRulesAsync(string outputDirectory, string timestamp, RulesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting Mailbox Rules Collection ===");
#pragma warning restore SA1101

            var mailboxRules = new List<MailboxRuleInfo>();
            var processedUsers = new HashSet<string>();

            try
            {
#pragma warning disable SA1101
                var usersToProcess = await GetUsersToProcessAsync();
#pragma warning restore SA1101

                foreach (var user in usersToProcess)
                {
                    try
                    {
#pragma warning disable SA1101
                        WriteVerbose($"Checking rules for: {user}");
#pragma warning restore SA1101

#pragma warning disable SA1101
                        var rules = await _exchangeClient.GetInboxRulesAsync(user);
#pragma warning restore SA1101

                        if (rules != null && rules.Length > 0)
                        {
                            if (!processedUsers.Contains(user))
                            {
                                summary.UsersWithRules++;
                                processedUsers.Add(user);
                            }

                            foreach (var rule in rules)
                            {
                                var mailboxRule = new MailboxRuleInfo
                                {
                                    UserName = user,
                                    RuleName = rule.Name,
                                    Enabled = rule.Enabled,
                                    Priority = rule.Priority,
                                    RuleIdentity = rule.RuleIdentity,
                                    StopProcessingRules = rule.StopProcessingRules,
                                    CopyToFolder = rule.CopyToFolder,
                                    MoveToFolder = rule.MoveToFolder,
                                    RedirectTo = rule.RedirectTo != null ? string.Join(", ", rule.RedirectTo) : null,
                                    ForwardTo = rule.ForwardTo != null ? string.Join(", ", rule.ForwardTo) : null,
                                    ForwardAsAttachmentTo = rule.ForwardAsAttachmentTo != null ? string.Join(", ", rule.ForwardAsAttachmentTo) : null,
                                    ApplyCategory = rule.ApplyCategory != null ? string.Join(", ", rule.ApplyCategory) : null,
                                    MarkImportance = rule.MarkImportance,
                                    MarkAsRead = rule.MarkAsRead,
                                    DeleteMessage = rule.DeleteMessage,
                                    SoftDeleteMessage = rule.SoftDeleteMessage,
                                    From = rule.From != null ? string.Join(", ", rule.From) : null,
                                    SubjectContainsWords = rule.SubjectContainsWords != null ? string.Join(", ", rule.SubjectContainsWords) : null,
                                    SubjectOrBodyContainsWords = rule.SubjectOrBodyContainsWords != null ? string.Join(", ", rule.SubjectOrBodyContainsWords) : null,
                                    BodyContainsWords = rule.BodyContainsWords != null ? string.Join(", ", rule.BodyContainsWords) : null,
                                    HasAttachment = rule.HasAttachment,
                                    Description = rule.Description,
                                    InError = rule.InError,
                                    ErrorType = rule.ErrorType
                                };

                                mailboxRules.Add(mailboxRule);
                                summary.TotalMailboxRules++;

                                if (rule.Enabled)
                                    summary.EnabledMailboxRules++;

                                if (rule.ForwardTo != null && rule.ForwardTo.Length > 0)
                                    summary.ForwardingRules++;

                                if (rule.RedirectTo != null && rule.RedirectTo.Length > 0)
                                    summary.RedirectRules++;

                                if (rule.SoftDeleteMessage)
                                    summary.SoftDeleteRules++;

#pragma warning disable SA1101
                                if (ShowRules)
                                {
#pragma warning disable SA1101
                                    WriteVerbose($"Found InboxRule for: {user}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    WriteVerbose($"  Username: {user}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    WriteVerbose($"  RuleName: {rule.Name}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    WriteVerbose($"  RuleEnabled: {rule.Enabled}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    WriteVerbose($"  CopytoFolder: {rule.CopyToFolder}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    WriteVerbose($"  MovetoFolder: {rule.MoveToFolder}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    WriteVerbose($"  RedirectTo: {(rule.RedirectTo != null ? string.Join(", ", rule.RedirectTo) : "None")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    WriteVerbose($"  ForwardTo: {(rule.ForwardTo != null ? string.Join(", ", rule.ForwardTo) : "None")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    WriteVerbose($"  ForwardAsAttachmentTo: {(rule.ForwardAsAttachmentTo != null ? string.Join(", ", rule.ForwardAsAttachmentTo) : "None")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    WriteVerbose($"  SoftDeleteMessage: {rule.SoftDeleteMessage}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                                    WriteVerbose($"  TextDescription: {rule.Description}");
#pragma warning restore SA1101
                                }
#pragma warning restore SA1101
                            }
                        }
                    }
                    catch (Exception ex)
                    {
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"Failed to process rules for user {user}: {ex.Message}");
#pragma warning restore SA1101
                    }
                }

                if (mailboxRules.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-MailboxRules.csv");
#pragma warning disable SA1101
                    await WriteMailboxRulesAsync(mailboxRules, fileName);
#pragma warning restore SA1101
                    summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                    WriteVerbose($"Mailbox rules written to: {fileName}");
#pragma warning restore SA1101
                }

                if (summary.TotalMailboxRules > 0)
                {
#pragma warning disable SA1101
                    WriteVerbose($"A total of {summary.TotalMailboxRules} Inbox Rules found");
#pragma warning restore SA1101
                }
                else
                {
#pragma warning disable SA1101
                    WriteVerbose("No Inbox Rules found!");
#pragma warning restore SA1101
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during mailbox rules collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task<List<string>> GetUsersToProcessAsync()
        {
            var users = new List<string>();

#pragma warning disable SA1101
            if (UserIds != null && UserIds.Length > 0)
            {
                // Use specified users
#pragma warning disable SA1101
                users.AddRange(UserIds);
#pragma warning restore SA1101
            }
            else
            {
                // Get all mailboxes
#pragma warning disable SA1101
                var mailboxes = await _exchangeClient.GetMailboxesAsync();
#pragma warning restore SA1101
                users.AddRange(mailboxes);
            }
#pragma warning restore SA1101

            return users;
        }

        private string GetOutputDirectory()
        {
#pragma warning disable SA1101
            var directory = OutputDir;
#pragma warning restore SA1101

            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
#pragma warning disable SA1101
                WriteVerbose($"Created output directory: {directory}");
#pragma warning restore SA1101
            }

            return directory;
        }

        private void LogSummary(RulesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("=== Rules Collection Summary ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (RuleType == "TransportRules" || RuleType == "Both")
            {
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose("Transport Rules:");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"  Total Rules: {summary.TotalTransportRules}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"  - Enabled: {summary.EnabledTransportRules}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"  - Disabled: {summary.DisabledTransportRules}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (RuleType == "MailboxRules" || RuleType == "Both")
            {
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose("Mailbox Rules:");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"  Users Processed: {summary.UsersWithRules}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"  Total Rules Found: {summary.TotalMailboxRules}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"  - Enabled Rules: {summary.EnabledMailboxRules}");
#pragma warning restore SA1101

                if (summary.ForwardingRules > 0)
#pragma warning disable SA1101
                    WriteVerbose($"  - Forwarding Rules: {summary.ForwardingRules}");
#pragma warning restore SA1101

                if (summary.RedirectRules > 0)
#pragma warning disable SA1101
                    WriteVerbose($"  - Redirect Rules: {summary.RedirectRules}");
#pragma warning restore SA1101

                if (summary.SoftDeleteRules > 0)
#pragma warning disable SA1101
                    WriteVerbose($"  - Soft Delete Rules: {summary.SoftDeleteRules}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("Output Files:");
#pragma warning restore SA1101
            foreach (var file in summary.OutputFiles)
            {
#pragma warning disable SA1101
                WriteVerbose($"  - {file}");
#pragma warning restore SA1101
            }
#pragma warning disable SA1101
            WriteVerbose("================================");
#pragma warning restore SA1101
        }

        private async Task WriteTransportRulesAsync(IEnumerable<TransportRuleInfo> rules, string filePath)
        {
            var csv = "Name,Description,CreatedBy,WhenChanged,State,Priority,Mode" + Environment.NewLine;

            foreach (var rule in rules)
            {
#pragma warning disable SA1101
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
#pragma warning restore SA1101

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteMailboxRulesAsync(IEnumerable<MailboxRuleInfo> rules, string filePath)
        {
            var csv = "UserName,RuleName,Enabled,Priority,RuleIdentity,StopProcessingRules,CopyToFolder,MoveToFolder,RedirectTo,ForwardTo,ForwardAsAttachmentTo,ApplyCategory,MarkImportance,MarkAsRead,DeleteMessage,SoftDeleteMessage,From,SubjectContainsWords,SubjectOrBodyContainsWords,BodyContainsWords,HasAttachment,Description,InError,ErrorType" + Environment.NewLine;

            foreach (var rule in rules)
            {
#pragma warning disable SA1101
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
#pragma warning restore SA1101

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
#pragma warning disable SA1600

#pragma warning restore SA1600
    // Supporting classes
#pragma warning disable SA1600
    public class RulesResult
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
        public List<TransportRuleInfo> TransportR
#pragma warning restore SA1600
List<TransportRuleInfo>();
        public List<MailboxRuleInfo> MailboxRules { get; set; } = new List<MailboxRuleInfo>();
#pragma warning disable SA1600
        public RulesSummary Summary { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class TransportRuleInfo
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Name { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Description { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string CreatedBy { get; set; }
        public DateTime? WhenChanged { get
#pragma warning restore SA1600
set; }
#pragma warning disable SA1600
#pragma warning restore SA1600
        public string State { get; set; }
        public int? Priority { get; set; }
#pragma warning disable SA1600
        public string Mode { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class MailboxRuleInfo
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RuleName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool Enabled { get; set; }
        public int? Priority { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RuleIdentity { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool StopProcessingRules { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string CopyToFolder { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string MoveToFolder { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RedirectTo { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ForwardTo { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ForwardAsAttachmentTo { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ApplyCategory { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string MarkImportance { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool MarkAsRead { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool DeleteMessage { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool SoftDeleteMessage { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string From { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string SubjectContainsWords { get; set; }
#pragma warning disable SA1201
        public string SubjectOrBodyContainsWord
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string BodyContainsWords { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool HasAttachment { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Description { get; set; }
        public bool InError { get; set; }public string ErrorType { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class RulesSummary
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalTransportRules { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int EnabledTransportRules { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int DisabledTransportRules { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalMailboxRules { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int EnabledMailboxRules { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int UsersWithRules { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int ForwardingRules { get; set; }
#pragma warning restore SA1600
        public int RedirectRules { get; set; }
        public int SoftDeleteRules { get; set; }public List<string> OutputFiles { get; set; } = new List<string>();
    }
}
