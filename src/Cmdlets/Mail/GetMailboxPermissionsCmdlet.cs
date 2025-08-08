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
    /// Cmdlet to collect mailbox permissions for security investigations
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "MailboxPermissions")]
    [OutputType(typeof(MailboxPermissionsResult))]
    public class GetMailboxPermissionsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve permissions for. If not specified, retrieves for all mailboxes")]
        public string[] UserIds { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
        public string OutputDir { get; set; } = "Output\\MailboxPermissions";

        [Parameter(
            HelpMessage = "File encoding for output files")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(
            HelpMessage = "Include system permissions in the output")]
        public SwitchParameter IncludeSystemPermissions { get; set; }

        private readonly ExchangeRestClient _exchangeClient;

        public GetMailboxPermissionsCmdlet()
        {
            _exchangeClient = new ExchangeRestClient();
        }

        protected override async Task ProcessRecordAsync()
        {
            LogInformation("=== Starting Mailbox Permissions Collection ===");
            
            // Check for authentication
            if (!await _exchangeClient.IsConnectedAsync())
            {
                LogError("Not connected to Exchange Online. Please run Connect-M365 first.");
                return;
            }

            // Create output directory
            var outputDirectory = GetOutputDirectory();
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmm");

            var summary = new MailboxPermissionsSummary
            {
                StartTime = DateTime.Now,
                ProcessedMailboxes = 0,
                TotalPermissions = 0,
                SystemPermissions = 0,
                UserPermissions = 0,
                OutputFiles = new List<string>()
            };

            try
            {
                var mailboxes = await GetMailboxesToProcessAsync();
                LogInformation($"Found {mailboxes.Count} mailboxes to process");

                var allPermissions = new List<MailboxPermissionEntry>();

                foreach (var mailbox in mailboxes)
                {
                    try
                    {
                        LogInformation($"Processing mailbox: {mailbox.UserPrincipalName}");
                        
                        var permissions = await ProcessMailboxPermissionsAsync(mailbox.UserPrincipalName, summary);
                        allPermissions.AddRange(permissions);
                        
                        summary.ProcessedMailboxes++;
                        
                        // Progress reporting
                        if (summary.ProcessedMailboxes % 10 == 0)
                        {
                            LogInformation($"Processed {summary.ProcessedMailboxes}/{mailboxes.Count} mailboxes");
                        }
                    }
                    catch (Exception ex)
                    {
                        LogWarning($"Failed to process mailbox {mailbox.UserPrincipalName}: {ex.Message}");
                    }
                }

                // Write consolidated results
                if (allPermissions.Count > 0)
                {
                    var consolidatedFile = Path.Combine(outputDirectory, $"{timestamp}-AllMailboxPermissions.csv");
                    await WriteResultsToFileAsync(allPermissions, consolidatedFile);
                    summary.OutputFiles.Add(consolidatedFile);
                    
                    LogInformation($"Consolidated permissions written to: {consolidatedFile}");
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
                LogSummary(summary);

                var result = new MailboxPermissionsResult
                {
                    Permissions = allPermissions,
                    Summary = summary
                };

                WriteObject(result);
            }
            catch (Exception ex)
            {
                LogError($"An error occurred during mailbox permissions collection: {ex.Message}");
                throw;
            }
        }

        private async Task<List<ExchangeMailbox>> GetMailboxesToProcessAsync()
        {
            var mailboxes = new List<ExchangeMailbox>();

            if (UserIds != null && UserIds.Length > 0)
            {
                // Process specific users
                foreach (var userId in UserIds)
                {
                    try
                    {
                        var mailbox = await _exchangeClient.GetMailboxAsync(userId);
                        if (mailbox != null)
                        {
                            mailboxes.Add(mailbox);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogWarning($"Could not retrieve mailbox for {userId}: {ex.Message}");
                    }
                }
            }
            else
            {
                // Get all mailboxes
                mailboxes = await _exchangeClient.GetMailboxesAsync(unlimited: true);
            }

            return mailboxes;
        }

        private async Task<List<MailboxPermissionEntry>> ProcessMailboxPermissionsAsync(string userPrincipalName, MailboxPermissionsSummary summary)
        {
            var permissions = new List<MailboxPermissionEntry>();

            try
            {
                // Get mailbox permissions
                var mailboxPermissions = await _exchangeClient.GetMailboxPermissionsAsync(userPrincipalName);
                
                foreach (var permission in mailboxPermissions)
                {
                    var isSystemAccount = IsSystemAccount(permission.User);
                    
                    if (!IncludeSystemPermissions && isSystemAccount)
                    {
                        summary.SystemPermissions++;
                        continue;
                    }

                    var entry = new MailboxPermissionEntry
                    {
                        Mailbox = userPrincipalName,
                        User = permission.User,
                        AccessRights = string.Join(", ", permission.AccessRights ?? new string[0]),
                        IsInherited = permission.IsInherited,
                        Deny = permission.Deny,
                        InheritanceType = permission.InheritanceType,
                        IsSystemAccount = isSystemAccount,
                        PermissionType = "Mailbox"
                    };

                    permissions.Add(entry);
                    
                    if (isSystemAccount)
                        summary.SystemPermissions++;
                    else
                        summary.UserPermissions++;
                }

                // Get recipient permissions
                var recipientPermissions = await _exchangeClient.GetRecipientPermissionsAsync(userPrincipalName);
                
                foreach (var permission in recipientPermissions)
                {
                    var isSystemAccount = IsSystemAccount(permission.Trustee);
                    
                    if (!IncludeSystemPermissions && isSystemAccount)
                    {
                        summary.SystemPermissions++;
                        continue;
                    }

                    var entry = new MailboxPermissionEntry
                    {
                        Mailbox = userPrincipalName,
                        User = permission.Trustee,
                        AccessRights = string.Join(", ", permission.AccessRights ?? new string[0]),
                        IsInherited = permission.Inherited,
                        Deny = false, // Recipient permissions don't typically have deny
                        InheritanceType = permission.InheritanceType,
                        IsSystemAccount = isSystemAccount,
                        PermissionType = "Recipient"
                    };

                    permissions.Add(entry);
                    
                    if (isSystemAccount)
                        summary.SystemPermissions++;
                    else
                        summary.UserPermissions++;
                }

                // Get send-as permissions
                var sendAsPermissions = await _exchangeClient.GetSendAsPermissionsAsync(userPrincipalName);
                
                foreach (var permission in sendAsPermissions)
                {
                    var isSystemAccount = IsSystemAccount(permission.Trustee);
                    
                    if (!IncludeSystemPermissions && isSystemAccount)
                    {
                        summary.SystemPermissions++;
                        continue;
                    }

                    var entry = new MailboxPermissionEntry
                    {
                        Mailbox = userPrincipalName,
                        User = permission.Trustee,
                        AccessRights = "SendAs",
                        IsInherited = permission.Inherited,
                        Deny = permission.Deny,
                        InheritanceType = permission.InheritanceType,
                        IsSystemAccount = isSystemAccount,
                        PermissionType = "SendAs"
                    };

                    permissions.Add(entry);
                    
                    if (isSystemAccount)
                        summary.SystemPermissions++;
                    else
                        summary.UserPermissions++;
                }

                summary.TotalPermissions += permissions.Count;
            }
            catch (Exception ex)
            {
                LogError($"Error retrieving permissions for {userPrincipalName}: {ex.Message}");
                throw;
            }

            return permissions;
        }

        private bool IsSystemAccount(string user)
        {
            if (string.IsNullOrEmpty(user))
                return false;

            var systemAccounts = new[]
            {
                "NT AUTHORITY\\SELF",
                "SELF",
                "NT USER\\SYSTEM",
                "BUILTIN\\Administrators",
                "S-1-5-21", // Domain SIDs
                "S-1-5-32", // Built-in SIDs
                "AUTHORITY\\",
                "BUILTIN\\"
            };

            return systemAccounts.Any(account => 
                user.StartsWith(account, StringComparison.OrdinalIgnoreCase));
        }

        private string GetOutputDirectory()
        {
            var directory = OutputDir;
            
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
                LogInformation($"Created output directory: {directory}");
            }

            return directory;
        }

        private void LogSummary(MailboxPermissionsSummary summary)
        {
            LogInformation("");
            LogInformation("=== Mailbox Permissions Collection Summary ===");
            LogInformation($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
            LogInformation($"Mailboxes Processed: {summary.ProcessedMailboxes:N0}");
            LogInformation($"Total Permissions Found: {summary.TotalPermissions:N0}");
            LogInformation($"  - User Permissions: {summary.UserPermissions:N0}");
            LogInformation($"  - System Permissions: {summary.SystemPermissions:N0}");
            LogInformation("");
            LogInformation("Output Files:");
            foreach (var file in summary.OutputFiles)
            {
                LogInformation($"  - {file}");
            }
            LogInformation("=============================================");
        }

        private async Task WriteResultsToFileAsync(IEnumerable<MailboxPermissionEntry> results, string filePath)
        {
            try
            {
                var directory = Path.GetDirectoryName(filePath);
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Write as CSV
                var csv = ConvertToCsv(results);
                await File.WriteAllTextAsync(filePath, csv);
            }
            catch (Exception ex)
            {
                LogError($"Failed to write results to file {filePath}: {ex.Message}");
                throw;
            }
        }

        private string ConvertToCsv(IEnumerable<MailboxPermissionEntry> results)
        {
            var csv = "Mailbox,User,AccessRights,IsInherited,Deny,InheritanceType,IsSystemAccount,PermissionType" + Environment.NewLine;
            
            foreach (var item in results)
            {
                var values = new[]
                {
                    EscapeCsvValue(item.Mailbox),
                    EscapeCsvValue(item.User),
                    EscapeCsvValue(item.AccessRights),
                    item.IsInherited.ToString(),
                    item.Deny.ToString(),
                    EscapeCsvValue(item.InheritanceType),
                    item.IsSystemAccount.ToString(),
                    EscapeCsvValue(item.PermissionType)
                };
                
                csv += string.Join(",", values) + Environment.NewLine;
            }
            
            return csv;
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

    public class MailboxPermissionsResult
    {
        public List<MailboxPermissionEntry> Permissions { get; set; } = new List<MailboxPermissionEntry>();
        public MailboxPermissionsSummary Summary { get; set; }
    }

    public class MailboxPermissionEntry
    {
        public string Mailbox { get; set; }
        public string User { get; set; }
        public string AccessRights { get; set; }
        public bool IsInherited { get; set; }
        public bool Deny { get; set; }
        public string InheritanceType { get; set; }
        public bool IsSystemAccount { get; set; }
        public string PermissionType { get; set; }
    }

    public class MailboxPermissionsSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public int ProcessedMailboxes { get; set; }
        public int TotalPermissions { get; set; }
        public int SystemPermissions { get; set; }
        public int UserPermissions { get; set; }
        public List<string> OutputFiles { get; set; } = new List<string>();
    }

    // Supporting classes for Exchange permissions
    public class MailboxPermission
    {
        public string User { get; set; }
        public string[] AccessRights { get; set; }
        public bool IsInherited { get; set; }
        public bool Deny { get; set; }
        public string InheritanceType { get; set; }
    }

    public class RecipientPermission
    {
        public string Trustee { get; set; }
        public string[] AccessRights { get; set; }
        public bool Inherited { get; set; }
        public string InheritanceType { get; set; }
    }

    public class SendAsPermission
    {
        public string Trustee { get; set; }
        public bool Inherited { get; set; }
        public bool Deny { get; set; }
        public string InheritanceType { get; set; }
    }
}