using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Exchange;
using Microsoft.ExtractorSuite.Models.Exchange;

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
            _exchangeClient = new ExchangeRestClient(AuthManager);
        }

        protected override async Task ProcessRecordAsync()
        {
            WriteVerbose("=== Starting Mailbox Permissions Collection ===");

            // Check for authentication
            if (!await _exchangeClient.IsConnectedAsync())
            {
                WriteErrorWithTimestamp("Not connected to Exchange Online. Please run Connect-M365 first.");
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
                WriteVerbose($"Found {mailboxes.Count} mailboxes to process");

                var allPermissions = new List<MailboxPermissionEntry>();

                foreach (var mailbox in mailboxes)
                {
                    try
                    {
                        WriteVerbose($"Processing mailbox: {mailbox.UserPrincipalName}");

                        var permissions = await ProcessMailboxPermissionsAsync(mailbox.UserPrincipalName, summary);
                        allPermissions.AddRange(permissions);

                        summary.ProcessedMailboxes++;

                        // Progress reporting
                        if (summary.ProcessedMailboxes % 10 == 0)
                        {
                            WriteVerbose($"Processed {summary.ProcessedMailboxes}/{mailboxes.Count} mailboxes");
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteWarningWithTimestamp($"Failed to process mailbox {mailbox.UserPrincipalName}: {ex.Message}");
                    }
                }

                // Write consolidated results
                if (allPermissions.Count > 0)
                {
                    var consolidatedFile = Path.Combine(outputDirectory, $"{timestamp}-AllMailboxPermissions.csv");
                    await WriteResultsToFileAsync(allPermissions, consolidatedFile);
                    summary.OutputFiles.Add(consolidatedFile);

                    WriteVerbose($"Consolidated permissions written to: {consolidatedFile}");
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
                WriteErrorWithTimestamp($"An error occurred during mailbox permissions collection: {ex.Message}");
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
                            // Convert MailboxInfo to ExchangeMailbox
                            mailboxes.Add(new ExchangeMailbox
                            {
                                UserPrincipalName = mailbox.UserPrincipalName,
                                DisplayName = mailbox.DisplayName,
                                PrimarySmtpAddress = mailbox.Email,
                                RecipientTypeDetails = mailbox.RecipientTypeDetails,
                                WhenCreated = mailbox.WhenCreated,
                                IsMailboxEnabled = true
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteWarningWithTimestamp($"Could not retrieve mailbox for {userId}: {ex.Message}");
                    }
                }
            }
            else
            {
                // Get all mailboxes
                var mailboxUserPrincipalNames = await _exchangeClient.GetMailboxesAsync();
                foreach (var upn in mailboxUserPrincipalNames)
                {
                    try
                    {
                        var mailbox = await _exchangeClient.GetMailboxAsync(upn);
                        if (mailbox != null)
                        {
                            // Convert MailboxInfo to ExchangeMailbox
                            mailboxes.Add(new ExchangeMailbox
                            {
                                UserPrincipalName = mailbox.UserPrincipalName,
                                DisplayName = mailbox.DisplayName,
                                PrimarySmtpAddress = mailbox.Email,
                                RecipientTypeDetails = mailbox.RecipientTypeDetails,
                                WhenCreated = mailbox.WhenCreated,
                                IsMailboxEnabled = true
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteWarningWithTimestamp($"Could not retrieve mailbox for {upn}: {ex.Message}");
                    }
                }
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

                foreach (var permissionObj in mailboxPermissions)
                {
                    var permission = CastToMailboxPermission(permissionObj);
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

                foreach (var permissionObj in recipientPermissions)
                {
                    var permission = CastToRecipientPermission(permissionObj);
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

                foreach (var permissionObj in sendAsPermissions)
                {
                    var permission = CastToSendAsPermission(permissionObj);
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
                WriteErrorWithTimestamp($"Error retrieving permissions for {userPrincipalName}: {ex.Message}");
                throw;
            }

            return permissions;
        }

        private MailboxPermission CastToMailboxPermission(object permissionObj)
        {
            if (permissionObj is System.Text.Json.JsonElement jsonElement)
            {
                return new MailboxPermission
                {
                    User = jsonElement.TryGetProperty("User", out var userProp) ? userProp.GetString() : null,
                    AccessRights = jsonElement.TryGetProperty("AccessRights", out var rightsProp) && rightsProp.ValueKind == System.Text.Json.JsonValueKind.Array
                        ? rightsProp.EnumerateArray().Select(r => r.GetString()).Where(s => s != null).ToArray()
                        : new string[0],
                    IsInherited = jsonElement.TryGetProperty("IsInherited", out var inheritedProp) && inheritedProp.GetBoolean(),
                    Deny = jsonElement.TryGetProperty("Deny", out var denyProp) && denyProp.GetBoolean(),
                    InheritanceType = jsonElement.TryGetProperty("InheritanceType", out var typeProp) ? typeProp.GetString() : null
                };
            }
            return new MailboxPermission();
        }

        private RecipientPermission CastToRecipientPermission(object permissionObj)
        {
            if (permissionObj is System.Text.Json.JsonElement jsonElement)
            {
                return new RecipientPermission
                {
                    Trustee = jsonElement.TryGetProperty("Trustee", out var trusteeProp) ? trusteeProp.GetString() : null,
                    AccessRights = jsonElement.TryGetProperty("AccessRights", out var rightsProp) && rightsProp.ValueKind == System.Text.Json.JsonValueKind.Array
                        ? rightsProp.EnumerateArray().Select(r => r.GetString()).Where(s => s != null).ToArray()
                        : new string[0],
                    Inherited = jsonElement.TryGetProperty("Inherited", out var inheritedProp) && inheritedProp.GetBoolean(),
                    InheritanceType = jsonElement.TryGetProperty("InheritanceType", out var typeProp) ? typeProp.GetString() : null
                };
            }
            return new RecipientPermission();
        }

        private SendAsPermission CastToSendAsPermission(object permissionObj)
        {
            if (permissionObj is System.Text.Json.JsonElement jsonElement)
            {
                return new SendAsPermission
                {
                    Trustee = jsonElement.TryGetProperty("Trustee", out var trusteeProp) ? trusteeProp.GetString() : null,
                    Inherited = jsonElement.TryGetProperty("Inherited", out var inheritedProp) && inheritedProp.GetBoolean(),
                    Deny = jsonElement.TryGetProperty("Deny", out var denyProp) && denyProp.GetBoolean(),
                    InheritanceType = jsonElement.TryGetProperty("InheritanceType", out var typeProp) ? typeProp.GetString() : null
                };
            }
            return new SendAsPermission();
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
                WriteVerbose($"Created output directory: {directory}");
            }

            return directory;
        }

        private void LogSummary(MailboxPermissionsSummary summary)
        {
            WriteVerbose("");
            WriteVerbose("=== Mailbox Permissions Collection Summary ===");
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
            WriteVerbose($"Mailboxes Processed: {summary.ProcessedMailboxes:N0}");
            WriteVerbose($"Total Permissions Found: {summary.TotalPermissions:N0}");
            WriteVerbose($"  - User Permissions: {summary.UserPermissions:N0}");
            WriteVerbose($"  - System Permissions: {summary.SystemPermissions:N0}");
            WriteVerbose("");
            WriteVerbose("Output Files:");
            foreach (var file in summary.OutputFiles)
            {
                WriteVerbose($"  - {file}");
            }
            WriteVerbose("=============================================");
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
                using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Failed to write results to file {filePath}: {ex.Message}");
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
