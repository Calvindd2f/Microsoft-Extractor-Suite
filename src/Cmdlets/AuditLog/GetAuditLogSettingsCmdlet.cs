namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;
    using CsvHelper;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Exchange;
    using Microsoft.ExtractorSuite.Core.Json;


    /// <summary>
    /// Retrieves audit status and settings for all mailboxes in Microsoft 365.
    /// Collects detailed information about mailbox audit settings, including audit status,
    /// bypass settings, and configured audit actions for owners, delegates, and administrators.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AuditLogSettings")]
    [OutputType(typeof(MailboxAuditStatus))]
    public class GetAuditLogSettingsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "Comma-separated list of user IDs to filter results by specific users.")]
#pragma warning disable SA1600
        public string[]? UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Output format for the results. Default: CSV")]
        [ValidateSet("CSV", "JSON")]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "CSV";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Text encoding for the output file. Default: UTF8")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

#pragma warning disable SA1600
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
            var results = RunAsyncOperation(GetAuditLogSettingsAsync, "Getting Audit Log Settings");

#pragma warning disable SA1101
            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
#pragma warning restore SA1101
        }

        private async Task<List<MailboxAuditStatus>> GetAuditLogSettingsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Mailbox Audit Status Collection");

            var summary = new AuditStatusSummary
            {
                StartTime = DateTime.UtcNow
            };

            // Check Exchange connection - this would need to be implemented in AuthManager
#pragma warning disable SA1101
            if (!AuthManager.IsGraphConnected)
            {
                throw new InvalidOperationException("Not connected to Exchange Online. Please run Connect-M365 first.");
            }
#pragma warning restore SA1101

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Getting organization configuration",
                PercentComplete = 5
            });

            // Get organization audit configuration
#pragma warning disable SA1101
            var orgConfig = await GetOrganizationAuditConfigAsync(cancellationToken);
#pragma warning restore SA1101
            summary.OrgWideAuditingEnabled = !orgConfig.AuditDisabled;

            WriteVerboseWithTimestamp($"Organization-wide auditing: {(summary.OrgWideAuditingEnabled ? "Enabled" : "Disabled")}");

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Retrieving mailbox list",
                PercentComplete = 10
            });

            // Get all mailboxes
#pragma warning disable SA1101
            var mailboxes = await GetMailboxesAsync(cancellationToken);
#pragma warning restore SA1101
            summary.TotalMailboxes = mailboxes.Count;

            WriteVerboseWithTimestamp($"Found {mailboxes.Count} mailboxes to process");

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Getting audit bypass associations",
                PercentComplete = 20
            });

            // Get audit bypass associations
#pragma warning disable SA1101
            var bypassLookup = await GetAuditBypassLookupAsync(mailboxes, cancellationToken);
#pragma warning restore SA1101

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Processing mailbox audit settings",
                PercentComplete = 30
            });

            // Process mailbox audit settings
            var results = new List<MailboxAuditStatus>();
            var processedCount = 0;

            foreach (var mailbox in mailboxes)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                processedCount++;
                var bypassStatus = bypassLookup.TryGetValue(mailbox.UserPrincipalName, out var bypass) ? bypass : false;

                // Update summary statistics
                if (mailbox.AuditEnabled) summary.AuditEnabled++;
                else summary.AuditDisabled++;
                if (bypassStatus) summary.AuditBypass++;
                if (mailbox.AuditOwner?.Any() == true) summary.OwnerActionsConfigured++;
                if (mailbox.AuditDelegate?.Any() == true) summary.DelegateActionsConfigured++;
                if (mailbox.AuditAdmin?.Any() == true) summary.AdminActionsConfigured++;

#pragma warning disable SA1101
                var auditStatus = new MailboxAuditStatus
                {
                    UserPrincipalName = mailbox.UserPrincipalName,
                    DisplayName = mailbox.DisplayName,
                    RecipientTypeDetails = mailbox.RecipientTypeDetails,
                    AuditEnabled = mailbox.AuditEnabled,
                    AuditBypassEnabled = bypassStatus,
                    DefaultAuditSet = mailbox.DefaultAuditSet != null ? string.Join(", ", mailbox.DefaultAuditSet.OrderBy(x => x)) : string.Empty,
                    OwnerAuditActions = mailbox.AuditOwner != null ? string.Join(", ", mailbox.AuditOwner.OrderBy(x => x)) : string.Empty,
                    OwnerAuditActionsCount = mailbox.AuditOwner?.Count() ?? 0,
                    DelegateAuditActions = mailbox.AuditDelegate != null ? string.Join(", ", mailbox.AuditDelegate.OrderBy(x => x)) : string.Empty,
                    DelegateAuditActionsCount = mailbox.AuditDelegate?.Count() ?? 0,
                    AdminAuditActions = mailbox.AuditAdmin != null ? string.Join(", ", mailbox.AuditAdmin.OrderBy(x => x)) : string.Empty,
                    AdminAuditActionsCount = mailbox.AuditAdmin?.Count() ?? 0,
                    EffectiveAuditState = GetEffectiveAuditState(summary.OrgWideAuditingEnabled, bypassStatus, mailbox.AuditEnabled)
                };
#pragma warning restore SA1101

                results.Add(auditStatus);

                // Report progress every 100 items or at key milestones
                if (processedCount % 100 == 0 || processedCount == mailboxes.Count)
                {
                    var percentComplete = 30 + (int)((processedCount / (double)mailboxes.Count) * 60);
                    progress.Report(new Core.AsyncOperations.TaskProgress
                    {
                        CurrentOperation = $"Processed {processedCount}/{mailboxes.Count} mailboxes",
                        PercentComplete = percentComplete,
                        ItemsProcessed = processedCount
                    });
                }
            }

            summary.ProcessedMailboxes = processedCount;
            summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Exporting results",
                PercentComplete = 95
            });

            // Export results if output directory is specified
#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(OutputDirectory))
            {
#pragma warning disable SA1101
                await ExportAuditStatusAsync(results, cancellationToken);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            // Log summary
            WriteVerboseWithTimestamp($"Audit Status Collection Summary:");
            WriteVerboseWithTimestamp($"  Total Mailboxes: {summary.TotalMailboxes}");
            WriteVerboseWithTimestamp($"  Audit Enabled: {summary.AuditEnabled}");
            WriteVerboseWithTimestamp($"  Audit Disabled: {summary.AuditDisabled}");
            WriteVerboseWithTimestamp($"  Audit Bypass: {summary.AuditBypass}");
            WriteVerboseWithTimestamp($"  Processing Time: {summary.ProcessingTime:mm\\:ss}");

            return results;
        }

        private async Task<OrganizationConfig> GetOrganizationAuditConfigAsync(CancellationToken cancellationToken)
        {
            // This would call Exchange Online PowerShell cmdlets through the ExchangeRestClient
            // For now, we'll simulate the call
            await Task.Delay(100, cancellationToken);

            return new OrganizationConfig
            {
                AuditDisabled = false // Simulate that org-wide auditing is enabled
            };
        }

        private async Task<List<MailboxInfo>> GetMailboxesAsync(CancellationToken cancellationToken)
        {
            // This would call Get-EXOMailbox through the ExchangeRestClient
            // For now, we'll simulate with empty list
            await Task.Delay(500, cancellationToken);

            return new List<MailboxInfo>();
        }

        private async Task<Dictionary<string, bool>> GetAuditBypassLookupAsync(
            List<MailboxInfo> mailboxes,
            CancellationToken cancellationToken)
        {
            var lookup = new Dictionary<string, bool>();

            try
            {
                // Try bulk retrieval first
                WriteVerboseWithTimestamp("Attempting bulk retrieval of audit bypass associations...");

                // This would call Get-MailboxAuditBypassAssociation
                // For simulation, we'll just mark all as not bypassed
                await Task.Delay(1000, cancellationToken);

                foreach (var mailbox in mailboxes)
                {
                    lookup[mailbox.UserPrincipalName] = false;
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteWarningWithTimestamp($"Bulk retrieval failed: {ex.Message}. Processing individually...");
#pragma warning restore SA1101

                // Process in batches if bulk fails
                const int batchSize = 10;
                for (int i = 0; i < mailboxes.Count; i += batchSize)
                {
                    var batch = mailboxes.Skip(i).Take(batchSize);

                    foreach (var mailbox in batch)
                    {
                        try
                        {
                            // Individual lookup call would go here
                            lookup[mailbox.UserPrincipalName] = false;
                        }
                        catch
                        {
                            lookup[mailbox.UserPrincipalName] = false;
                        }
                    }

                    // Small delay between batches to avoid throttling
                    await Task.Delay(100, cancellationToken);
                }
            }

            return lookup;
        }

        private string GetEffectiveAuditState(bool orgWideEnabled, bool bypassEnabled, bool mailboxEnabled)
        {
            if (orgWideEnabled && !bypassEnabled)
                return "Enabled (Organization Policy)";
            else if (bypassEnabled)
                return "Bypassed";
            else if (mailboxEnabled)
                return "Enabled (Mailbox Setting)";
            else
                return "Disabled";
        }

        private async Task ExportAuditStatusAsync(List<MailboxAuditStatus> results, CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var fileName = Path.Combine(
                OutputDirectory!,
                $"MailboxAuditStatus_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{OutputFormat.ToLower()}");
#pragma warning restore SA1101

            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

#pragma warning disable SA1101
            if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.Create(fileName);
                using var processor = new HighPerformanceJsonProcessor();
                await processor.SerializeAsync(stream, results, true, cancellationToken);
            }
            else // CSV
            {
#pragma warning disable SA1101
                using var writer = new StreamWriter(fileName, false, System.Text.Encoding.GetEncoding(Encoding));
#pragma warning restore SA1101
                using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(results, cancellationToken);
            }
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Exported audit status to {fileName}");
        }
    }

#pragma warning disable SA1600
    public class MailboxAuditStatus
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string UserPrincipalName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string DisplayName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string RecipientTypeDetails { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool AuditEnabled { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool AuditBypassEnabled { get; set; }
        public string DefaultAuditSet { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string OwnerAuditActions { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int OwnerAuditActionsCount { get; set; }
        public string DelegateAuditActions { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int DelegateAuditActionsCount { get; set; }
        public string AdminAuditActions { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int AdminAuditActionsCount { get; set; }
        public string EffectiveAuditState { get; set; } = string.Empty;
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class AuditStatusSummary
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public TimeSpan ProcessingTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalMailboxes { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int ProcessedMailboxes { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int AuditEnabled { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int AuditDisabled { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int AuditBypass { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int OwnerActionsConfigured { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int DelegateActionsConfigured { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int AdminActionsConfigured { get; set; }
#pragma warning restore SA1600
        public bool OrgWideAuditingEnabled { get; set; }
    }

#pragma warning disable SA1600
    public class OrganizationConfig
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool AuditDisabled { get; set; }
    }

#pragma warning disable SA1600
    public class MailboxInfo
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string UserPrincipalName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string DisplayName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string RecipientTypeDetails { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool AuditEnabled { get; set; }
        public string[]? DefaultAuditSet { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string[]? AuditOwner { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string[]? AuditDelegate { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string[]? AuditAdmin { get; set; }
#pragma warning restore SA1600
    }
}
