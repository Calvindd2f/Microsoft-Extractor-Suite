namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Json;
    using Microsoft.Graph;
    using Microsoft.Graph.Models;


    [Cmdlet(VerbsCommon.Get, "MFA")]
    [OutputType(typeof(MFAStatus))]
#pragma warning disable SA1600
    public class GetMFACmdlet : AsyncBaseCmdlet
#pragma warning restore SA1600
    {
        [Parameter]
#pragma warning disable SA1600
        public string[]? UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeDisabledUsers { get; set; }

        [Parameter]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeGuests { get; set; }

        [Parameter]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "CSV";
#pragma warning restore SA1600

#pragma warning disable SA1600
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                return;
            }
#pragma warning restore SA1101

            var mfaStatuses = RunAsyncOperation(GetMFAStatusAsync, "Get MFA Status");

#pragma warning disable SA1101
            if (!Async.IsPresent && mfaStatuses != null)
            {
                foreach (var status in mfaStatuses)
                {
                    WriteObject(status);
                }
            }
#pragma warning restore SA1101
        }

        private async Task<List<MFAStatus>> GetMFAStatusAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var graphClient = AuthManager.BetaGraphClient ?? AuthManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");
#pragma warning restore SA1101

            var mfaStatuses = new List<MFAStatus>();
            var processedCount = 0;

            try
            {
                // Apply filters
                var filters = new List<string>();

#pragma warning disable SA1101
                if (!IncludeDisabledUsers.IsPresent)
                {
                    filters.Add("accountEnabled eq true");
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (!IncludeGuests.IsPresent)
                {
                    filters.Add("userType eq 'Member'");
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (UserIds != null && UserIds.Length > 0)
                {
#pragma warning disable SA1101
                    var userFilter = string.Join(" or ",
                        UserIds.Select(u => $"userPrincipalName eq '{u}' or mail eq '{u}'"));
#pragma warning restore SA1101
                    filters.Add($"({userFilter})");
                }
#pragma warning restore SA1101

                // Build user query with v5 syntax
                var usersResponse = await graphClient.Users
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Select = new string[]
                        {
                            "id", "displayName", "userPrincipalName", "mail", "accountEnabled",
                            "userType", "createdDateTime", "signInActivity"
                        };
                        requestConfiguration.QueryParameters.Top = 999;

                        if (filters.Any())
                        {
                            requestConfiguration.QueryParameters.Filter = string.Join(" and ", filters);
                        }
                    }, cancellationToken);

                // Process users with v5 PageIterator
                var pageIterator = PageIterator<User, UserCollectionResponse>
                    .CreatePageIterator(
                        graphClient,
                        usersResponse,
                        (user) =>
                        {
                            try
                            {
                                // Run on thread pool to avoid STA thread issues
#pragma warning disable SA1101
                                var mfaStatus = Task.Run(async () =>
                                    await GetUserMFAStatusAsync(graphClient, user, cancellationToken).ConfigureAwait(false))
                                    .GetAwaiter().GetResult();
#pragma warning restore SA1101
                                mfaStatuses.Add(mfaStatus);

                                processedCount++;
                                if (processedCount % 50 == 0)
                                {
                                    progress.Report(new Core.AsyncOperations.TaskProgress
                                    {
                                        CurrentOperation = $"Processing MFA status",
                                        ItemsProcessed = processedCount,
                                        PercentComplete = -1
                                    });
                                }
                            }
                            catch (Exception ex)
                            {
#pragma warning disable SA1101
                                WriteWarningWithTimestamp($"Failed to get MFA status for {user.UserPrincipalName}: {ex.Message}");
#pragma warning restore SA1101
                            }

                            return !cancellationToken.IsCancellationRequested;
                        });

                await pageIterator.IterateAsync(cancellationToken);

                WriteVerboseWithTimestamp($"Retrieved MFA status for {mfaStatuses.Count} users");

                // Generate summary statistics
#pragma warning disable SA1101
                GenerateMFASummary(mfaStatuses);
#pragma warning restore SA1101

                // Export to file if output directory specified
#pragma warning disable SA1101
                if (!string.IsNullOrEmpty(OutputDirectory))
                {
#pragma warning disable SA1101
                    await ExportMFAStatusAsync(mfaStatuses, cancellationToken);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                return mfaStatuses;
            }
            catch (ServiceException ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Graph API error: {ex.Message}", ex);
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task<MFAStatus> GetUserMFAStatusAsync(
            GraphServiceClient graphClient,
            User user,
            CancellationToken cancellationToken)
        {
            var mfaStatus = new MFAStatus
            {
                UserId = user.Id,
                UserPrincipalName = user.UserPrincipalName,
                DisplayName = user.DisplayName,
                AccountEnabled = user.AccountEnabled ?? false,
                UserType = user.UserType,
                CreatedDateTime = user.CreatedDateTime?.DateTime,
                LastSignInDateTime = user.SignInActivity?.LastSignInDateTime?.DateTime
            };

            try
            {
                // Get authentication methods
                var authMethods = await graphClient.Users[user.Id].Authentication.Methods
                    .GetAsync();

                mfaStatus.AuthenticationMethods = new List<string>();
                mfaStatus.HasMFAEnabled = false;

                if (authMethods?.Value != null)
                {
                    foreach (var method in authMethods.Value)
                    {
#pragma warning disable SA1101
                        var methodType = GetAuthMethodType(method);
#pragma warning restore SA1101
                        mfaStatus.AuthenticationMethods.Add(methodType);

                        // Check if this is an MFA method
#pragma warning disable SA1101
                        if (IsMethodMFA(methodType))
                        {
                            mfaStatus.HasMFAEnabled = true;
                        }
#pragma warning restore SA1101
                    }
                }

                // Check for per-user MFA state (legacy)
#pragma warning disable SA1101
                var mfaData = await GetLegacyMFAStateAsync(graphClient, user.Id, cancellationToken);
#pragma warning restore SA1101
                if (mfaData != null)
                {
                    mfaStatus.PerUserMFAState = mfaData.State;
                    mfaStatus.DefaultMFAMethod = mfaData.DefaultMethod;
                }

                // Determine overall MFA status
#pragma warning disable SA1101
                DetermineMFAStatus(mfaStatus);
#pragma warning restore SA1101

                // Check if MFA is enforced by Conditional Access
#pragma warning disable SA1101
                mfaStatus.ConditionalAccessEnforced = await CheckConditionalAccessMFAAsync(
                    graphClient, user.Id, cancellationToken);
#pragma warning restore SA1101
            }
            catch (ServiceException ex) when (ex.ResponseStatusCode == (int)System.Net.HttpStatusCode.Forbidden)
            {
                mfaStatus.Status = "Unknown - Insufficient Permissions";
                WriteVerboseWithTimestamp($"Insufficient permissions to get MFA details for {user.UserPrincipalName}");
            }

            return mfaStatus;
        }

        private string GetAuthMethodType(AuthenticationMethod method)
        {
            return method.OdataType switch
            {
                "#microsoft.graph.phoneAuthenticationMethod" => "Phone",
                "#microsoft.graph.emailAuthenticationMethod" => "Email",
                "#microsoft.graph.passwordAuthenticationMethod" => "Password",
                "#microsoft.graph.fido2AuthenticationMethod" => "FIDO2",
                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" => "Windows Hello",
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" => "Microsoft Authenticator",
                "#microsoft.graph.temporaryAccessPassAuthenticationMethod" => "Temporary Access Pass",
                "#microsoft.graph.softwareOathAuthenticationMethod" => "Software OATH",
                _ => method.OdataType?.Replace("#microsoft.graph.", "").Replace("AuthenticationMethod", "") ?? "Unknown"
            };
        }

        private bool IsMethodMFA(string methodType)
        {
            var mfaMethods = new[]
            {
                "Phone",
                "Microsoft Authenticator",
                "FIDO2",
                "Windows Hello",
                "Software OATH",
                "Email" // Email can be used for MFA in some configurations
            };

            return mfaMethods.Contains(methodType, StringComparer.OrdinalIgnoreCase);
        }

        private void DetermineMFAStatus(MFAStatus status)
        {
            if (status.HasMFAEnabled)
            {
                if (status.AuthenticationMethods.Contains("Microsoft Authenticator"))
                {
                    status.Status = "Enabled - Authenticator App";
                }
                else if (status.AuthenticationMethods.Contains("Phone"))
                {
                    status.Status = "Enabled - Phone";
                }
                else if (status.AuthenticationMethods.Contains("FIDO2") ||
                         status.AuthenticationMethods.Contains("Windows Hello"))
                {
                    status.Status = "Enabled - Passwordless";
                }
                else
                {
                    status.Status = "Enabled - Other";
                }
            }
            else if (status.ConditionalAccessEnforced)
            {
                status.Status = "Required by Conditional Access";
            }
            else if (status.PerUserMFAState == "Enforced")
            {
                status.Status = "Enforced (Legacy)";
            }
            else if (status.PerUserMFAState == "Enabled")
            {
                status.Status = "Enabled (Legacy)";
            }
            else
            {
                status.Status = "Not Configured";
            }
        }

        private async Task<LegacyMFAData?> GetLegacyMFAStateAsync(
            GraphServiceClient graphClient,
            string userId,
            CancellationToken cancellationToken)
        {
            try
            {
                // Try to get legacy per-user MFA state
                var user = await graphClient.Users[userId]
                    .GetAsync(requestConfiguration => {
                        requestConfiguration.QueryParameters.Select = new string[] { "strongAuthenticationRequirements", "strongAuthenticationMethods" };
                    }, cancellationToken);

                // This would need proper property access based on actual Graph API response
                // Legacy MFA properties might not be directly available in Graph
                return null;
            }
            catch
            {
                return null;
            }
        }

        private async Task<bool> CheckConditionalAccessMFAAsync(
            GraphServiceClient graphClient,
            string userId,
            CancellationToken cancellationToken)
        {
            try
            {
                // Check if any Conditional Access policies enforce MFA for this user
                // This is a simplified check - full implementation would evaluate all policies
                var response = await graphClient.Identity.ConditionalAccess.Policies
                    .GetAsync(requestConfiguration => {
                        requestConfiguration.QueryParameters.Filter = "state eq 'enabled'";
                    }, cancellationToken);

                var policies = response?.Value ?? new List<ConditionalAccessPolicy>();

                foreach (var policy in policies)
                {
                    if (policy.GrantControls?.BuiltInControls?.Contains(ConditionalAccessGrantControl.Mfa) == true)
                    {
                        // Check if user is in scope of this policy
                        // This would require evaluating conditions
                        return true;
                    }
                }
            }
            catch
            {
                // Ignore errors in CA check
            }

            return false;
        }

        private void GenerateMFASummary(List<MFAStatus> mfaStatuses)
        {
            var summary = new
            {
                TotalUsers = mfaStatuses.Count,
                MFAEnabled = mfaStatuses.Count(m => m.HasMFAEnabled),
                MFANotConfigured = mfaStatuses.Count(m => !m.HasMFAEnabled),
                AuthenticatorApp = mfaStatuses.Count(m => m.AuthenticationMethods.Contains("Microsoft Authenticator")),
                PhoneAuth = mfaStatuses.Count(m => m.AuthenticationMethods.Contains("Phone")),
                Passwordless = mfaStatuses.Count(m =>
                    m.AuthenticationMethods.Contains("FIDO2") ||
                    m.AuthenticationMethods.Contains("Windows Hello")),
                ConditionalAccessEnforced = mfaStatuses.Count(m => m.ConditionalAccessEnforced),
                LegacyMFA = mfaStatuses.Count(m =>
                    m.PerUserMFAState == "Enabled" ||
                    m.PerUserMFAState == "Enforced")
            };

#pragma warning disable SA1101
            WriteHost("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost("MFA Status Summary", ConsoleColor.Cyan);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost("==================", ConsoleColor.Cyan);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Total Users: {summary.TotalUsers}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"MFA Enabled: {summary.MFAEnabled} ({(summary.MFAEnabled * 100.0 / summary.TotalUsers):F1}%)",
                ConsoleColor.Green);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"MFA Not Configured: {summary.MFANotConfigured} ({(summary.MFANotConfigured * 100.0 / summary.TotalUsers):F1}%)",
                ConsoleColor.Yellow);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost("Authentication Methods:");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"  Authenticator App: {summary.AuthenticatorApp}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"  Phone: {summary.PhoneAuth}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"  Passwordless: {summary.Passwordless}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"  Conditional Access: {summary.ConditionalAccessEnforced}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"  Legacy MFA: {summary.LegacyMFA}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost("");
#pragma warning restore SA1101
        }

        private async Task ExportMFAStatusAsync(
            List<MFAStatus> mfaStatuses,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var fileName = Path.Combine(
                OutputDirectory!,
                $"MFAStatus_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{OutputFormat.ToLower()}");
#pragma warning restore SA1101

            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

#pragma warning disable SA1101
            if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.Create(fileName);
                using var processor = new HighPerformanceJsonProcessor();
                await processor.SerializeAsync(stream, mfaStatuses, true, cancellationToken);
            }
            else // CSV
            {
                // Flatten for CSV export
                var flattenedData = mfaStatuses.Select(m => new
                {
                    m.UserId,
                    m.UserPrincipalName,
                    m.DisplayName,
                    m.AccountEnabled,
                    m.UserType,
                    m.CreatedDateTime,
                    m.LastSignInDateTime,
                    m.HasMFAEnabled,
                    m.Status,
                    AuthMethods = string.Join("; ", m.AuthenticationMethods),
                    m.DefaultMFAMethod,
                    m.PerUserMFAState,
                    m.ConditionalAccessEnforced
                });

                using var writer = new StreamWriter(fileName);
                using var csv = new CsvHelper.CsvWriter(writer, System.Globalization.CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(flattenedData);
            }
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Exported MFA status to {fileName}");
        }

        private void WriteHost(string message, ConsoleColor? color = null)
        {
            if (color.HasValue)
            {
#pragma warning disable SA1101
                Host.UI.WriteLine(color.Value, Host.UI.RawUI.BackgroundColor, message);
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                Host.UI.WriteLine(message);
#pragma warning restore SA1101
            }
        }
    }

#pragma warning disable SA1600
    public class MFAStatus
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string? UserId { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? UserPrincipalName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? DisplayName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool AccountEnabled { get; set; }
        public string? UserType { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? CreatedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? LastSignInDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool HasMFAEnabled { get; set; }
        public string Status { get; set; } = "Unknown";
#pragma warning restore SA1600
#pragma warning disable SA1600
        public List<string> AuthenticationMethods { get; set; } = new();
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? DefaultMFAMethod { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? PerUserMFAState { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool ConditionalAccessEnforced { get; set; }
    }

#pragma warning disable SA1600
    internal class LegacyMFAData
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string? State { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? DefaultMethod { get; set; }
#pragma warning restore SA1600
    }
}
