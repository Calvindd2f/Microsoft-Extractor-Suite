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
    /// Cmdlet to collect mailbox permissions for security investigations
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "MailboxPermissions")]
    [OutputType(typeof(MailboxPermissionsResult))]
    public class GetMailboxPermissionsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve permissions for. If not specified, retrieves for all mailboxes")]
#pragma warning disable SA1600
        public string[] UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
#pragma warning disable SA1600
        public string OutputDir { get; set; } = "Output\\MailboxPermissions";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "File encoding for output files")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Include system permissions in the output")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1309
        public SwitchParameter IncludeSystemPermissions { get; set; }
#pragma warning disable SA1201
        private readonly ExchangeRestClient _exchangeClient;
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning restore SA1309
name

        public GetMailboxPermissionsCmdlet()
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
            WriteVerbose("=== Starting Mailbox Permissions Collection ===");
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

            // Create output directory
#pragma warning disable SA1101
            var outputDirectory = GetOutputDirectory();
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                var mailboxes = await GetMailboxesToProcessAsync();
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"Found {mailboxes.Count} mailboxes to process");
#pragma warning restore SA1101

                var allPermissions = new List<MailboxPermissionEntry>();

                foreach (var mailbox in mailboxes)
                {
                    try
                    {
#pragma warning disable SA1101
                        WriteVerbose($"Processing mailbox: {mailbox.UserPrincipalName}");
#pragma warning restore SA1101

#pragma warning disable SA1101
                        var permissions = await ProcessMailboxPermissionsAsync(mailbox.UserPrincipalName, summary);
#pragma warning restore SA1101
                        allPermissions.AddRange(permissions);

                        summary.ProcessedMailboxes++;

                        // Progress reporting
                        if (summary.ProcessedMailboxes % 10 == 0)
                        {
#pragma warning disable SA1101
                            WriteVerbose($"Processed {summary.ProcessedMailboxes}/{mailboxes.Count} mailboxes");
#pragma warning restore SA1101
                        }
                    }
                    catch (Exception ex)
                    {
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"Failed to process mailbox {mailbox.UserPrincipalName}: {ex.Message}");
#pragma warning restore SA1101
                    }
                }

                // Write consolidated results
                if (allPermissions.Count > 0)
                {
                    var consolidatedFile = Path.Combine(outputDirectory, $"{timestamp}-AllMailboxPermissions.csv");
#pragma warning disable SA1101
                    await WriteResultsToFileAsync(allPermissions, consolidatedFile);
#pragma warning restore SA1101
                    summary.OutputFiles.Add(consolidatedFile);

#pragma warning disable SA1101
                    WriteVerbose($"Consolidated permissions written to: {consolidatedFile}");
#pragma warning restore SA1101
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
#pragma warning disable SA1101
                LogSummary(summary);
#pragma warning restore SA1101

                var result = new MailboxPermissionsResult
                {
                    Permissions = allPermissions,
                    Summary = summary
                };

#pragma warning disable SA1101
                WriteObject(result);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during mailbox permissions collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task<List<ExchangeMailbox>> GetMailboxesToProcessAsync()
        {
            var mailboxes = new List<ExchangeMailbox>();

#pragma warning disable SA1101
            if (UserIds != null && UserIds.Length > 0)
            {
                // Process specific users
#pragma warning disable SA1101
                foreach (var userId in UserIds)
                {
                    try
                    {
#pragma warning disable SA1101
                        var mailbox = await _exchangeClient.GetMailboxAsync(userId);
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"Could not retrieve mailbox for {userId}: {ex.Message}");
#pragma warning restore SA1101
                    }
                }
#pragma warning restore SA1101
            }
            else
            {
                // Get all mailboxes
#pragma warning disable SA1101
                var mailboxUserPrincipalNames = await _exchangeClient.GetMailboxesAsync();
#pragma warning restore SA1101
                foreach (var upn in mailboxUserPrincipalNames)
                {
                    try
                    {
#pragma warning disable SA1101
                        var mailbox = await _exchangeClient.GetMailboxAsync(upn);
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"Could not retrieve mailbox for {upn}: {ex.Message}");
#pragma warning restore SA1101
                    }
                }
            }
#pragma warning restore SA1101

            return mailboxes;
        }

        private async Task<List<MailboxPermissionEntry>> ProcessMailboxPermissionsAsync(string userPrincipalName, MailboxPermissionsSummary summary)
        {
            var permissions = new List<MailboxPermissionEntry>();

            try
            {
                // Get mailbox permissions
#pragma warning disable SA1101
                var mailboxPermissions = await _exchangeClient.GetMailboxPermissionsAsync(userPrincipalName);
#pragma warning restore SA1101

                foreach (var permissionObj in mailboxPermissions)
                {
#pragma warning disable SA1101
                    var permission = CastToMailboxPermission(permissionObj);
#pragma warning restore SA1101
#pragma warning disable SA1101
                    var isSystemAccount = IsSystemAccount(permission.User);
#pragma warning restore SA1101

#pragma warning disable SA1101
                    if (!IncludeSystemPermissions && isSystemAccount)
                    {
                        summary.SystemPermissions++;
                        continue;
                    }
#pragma warning restore SA1101

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
#pragma warning disable SA1101
                var recipientPermissions = await _exchangeClient.GetRecipientPermissionsAsync(userPrincipalName);
#pragma warning restore SA1101

                foreach (var permissionObj in recipientPermissions)
                {
#pragma warning disable SA1101
                    var permission = CastToRecipientPermission(permissionObj);
#pragma warning restore SA1101
#pragma warning disable SA1101
                    var isSystemAccount = IsSystemAccount(permission.Trustee);
#pragma warning restore SA1101

#pragma warning disable SA1101
                    if (!IncludeSystemPermissions && isSystemAccount)
                    {
                        summary.SystemPermissions++;
                        continue;
                    }
#pragma warning restore SA1101

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
#pragma warning disable SA1101
                var sendAsPermissions = await _exchangeClient.GetSendAsPermissionsAsync(userPrincipalName);
#pragma warning restore SA1101

                foreach (var permissionObj in sendAsPermissions)
                {
#pragma warning disable SA1101
                    var permission = CastToSendAsPermission(permissionObj);
#pragma warning restore SA1101
#pragma warning disable SA1101
                    var isSystemAccount = IsSystemAccount(permission.Trustee);
#pragma warning restore SA1101

#pragma warning disable SA1101
                    if (!IncludeSystemPermissions && isSystemAccount)
                    {
                        summary.SystemPermissions++;
                        continue;
                    }
#pragma warning restore SA1101

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
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Error retrieving permissions for {userPrincipalName}: {ex.Message}");
#pragma warning restore SA1101
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

        private void LogSummary(MailboxPermissionsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("=== Mailbox Permissions Collection Summary ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Mailboxes Processed: {summary.ProcessedMailboxes:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Total Permissions Found: {summary.TotalPermissions:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"  - User Permissions: {summary.UserPermissions:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"  - System Permissions: {summary.SystemPermissions:N0}");
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
            WriteVerbose("=============================================");
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                var csv = ConvertToCsv(results);
#pragma warning restore SA1101
                using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to write results to file {filePath}: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private string ConvertToCsv(IEnumerable<MailboxPermissionEntry> results)
        {
            var csv = "Mailbox,User,AccessRights,IsInherited,Deny,InheritanceType,IsSystemAccount,PermissionType" + Environment.NewLine;

            foreach (var item in results)
            {
#pragma warning disable SA1101
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
#pragma warning restore SA1101

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
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class MailboxPermissionsResult
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
        public List<MailboxPermissionEntry> Permissions { get; set; } = new List<MailboxPermissionEntry>();
#pragma warning disable SA1600
        public MailboxPermissionsSummary Summary { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class MailboxPermissionEntry
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Mailbox { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string User { get; set; }
        public string AccessRights { g
#pragma warning restore SA1600
set; }
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsInherited { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool Deny { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string InheritanceType { get; set; }
        public bool IsSystemAccount { get; set; }public string PermissionType { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class MailboxPermissionsSummary
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
        public int ProcessedMailboxes { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalPermissions { get; set; }
#pragma warning restore SA1600
        public int SystemPermissions { get; set; }
        public int UserPermissions { get; set; }public List<string> OutputFiles { get; set; } = new List<string>();
    }
#pragma warning disable SA1600

#pragma warning restore SA1600
    // Supporting classes for Exchange permissions
#pragma warning disable SA1600
    public class MailboxPermission
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string User { get; set; }
        public string[] AccessRights {
#pragma warning restore SA1600
set; }
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsInherited { get; set; }
        public bool Deny { get; set; }public string InheritanceType { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class RecipientPermission
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Trustee { get; set; }
        public string[] AccessRights { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public bool Inherited { get; set; }public string InheritanceType { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class SendAsPermission
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Trustee { get; set; }
#pragma warning restore SA1600
        public bool Inherited { get; set; }
        public bool Deny { get; set; }public string InheritanceType { get; set; }}
}
