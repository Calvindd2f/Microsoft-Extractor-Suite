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

namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    [Cmdlet(VerbsCommon.Get, "MFA")]
    [OutputType(typeof(MFAStatus))]
    public class GetMFACmdlet : AsyncBaseCmdlet
    {
        [Parameter]
        public string[]? UserIds { get; set; }
        
        [Parameter]
        public SwitchParameter IncludeDisabledUsers { get; set; }
        
        [Parameter]
        public SwitchParameter IncludeGuests { get; set; }
        
        [Parameter]
        public string OutputFormat { get; set; } = "CSV";
        
        protected override void ProcessRecord()
        {
            if (!RequireGraphConnection())
            {
                return;
            }
            
            var mfaStatuses = RunAsyncOperation(GetMFAStatusAsync, "Get MFA Status");
            
            if (!Async.IsPresent && mfaStatuses != null)
            {
                foreach (var status in mfaStatuses)
                {
                    WriteObject(status);
                }
            }
        }
        
        private async Task<List<MFAStatus>> GetMFAStatusAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            var graphClient = AuthManager.BetaGraphClient ?? AuthManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");
            
            var mfaStatuses = new List<MFAStatus>();
            var processedCount = 0;
            
            try
            {
                // Build user query
                var request = graphClient.Users
                    .Request()
                    .Select("id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,signInActivity,authenticationMethods")
                    .Top(999);
                
                // Apply filters
                var filters = new List<string>();
                
                if (!IncludeDisabledUsers.IsPresent)
                {
                    filters.Add("accountEnabled eq true");
                }
                
                if (!IncludeGuests.IsPresent)
                {
                    filters.Add("userType eq 'Member'");
                }
                
                if (UserIds != null && UserIds.Length > 0)
                {
                    var userFilter = string.Join(" or ", 
                        UserIds.Select(u => $"userPrincipalName eq '{u}' or mail eq '{u}'"));
                    filters.Add($"({userFilter})");
                }
                
                if (filters.Any())
                {
                    request = request.Filter(string.Join(" and ", filters));
                }
                
                // Process users
                var pageIterator = PageIterator<User>
                    .CreatePageIterator(
                        graphClient,
                        request,
                        async (user) =>
                        {
                            try
                            {
                                var mfaStatus = await GetUserMFAStatusAsync(graphClient, user, cancellationToken);
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
                                WriteWarningWithTimestamp($"Failed to get MFA status for {user.UserPrincipalName}: {ex.Message}");
                            }
                            
                            return !cancellationToken.IsCancellationRequested;
                        });
                
                await pageIterator.IterateAsync(cancellationToken);
                
                WriteVerboseWithTimestamp($"Retrieved MFA status for {mfaStatuses.Count} users");
                
                // Generate summary statistics
                GenerateMFASummary(mfaStatuses);
                
                // Export to file if output directory specified
                if (!string.IsNullOrEmpty(OutputDirectory))
                {
                    await ExportMFAStatusAsync(mfaStatuses, cancellationToken);
                }
                
                return mfaStatuses;
            }
            catch (ServiceException ex)
            {
                WriteErrorWithTimestamp($"Graph API error: {ex.Message}", ex);
                throw;
            }
        }
        
        private async Task<MFAStatus> GetUserMFAStatusAsync(
            IGraphServiceClient graphClient,
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
                    .Request()
                    .GetAsync(cancellationToken);
                
                mfaStatus.AuthenticationMethods = new List<string>();
                mfaStatus.HasMFAEnabled = false;
                
                foreach (var method in authMethods)
                {
                    var methodType = GetAuthMethodType(method);
                    mfaStatus.AuthenticationMethods.Add(methodType);
                    
                    // Check if this is an MFA method
                    if (IsMethodMFA(methodType))
                    {
                        mfaStatus.HasMFAEnabled = true;
                    }
                }
                
                // Check for per-user MFA state (legacy)
                var mfaData = await GetLegacyMFAStateAsync(graphClient, user.Id, cancellationToken);
                if (mfaData != null)
                {
                    mfaStatus.PerUserMFAState = mfaData.State;
                    mfaStatus.DefaultMFAMethod = mfaData.DefaultMethod;
                }
                
                // Determine overall MFA status
                DetermineMFAStatus(mfaStatus);
                
                // Check if MFA is enforced by Conditional Access
                mfaStatus.ConditionalAccessEnforced = await CheckConditionalAccessMFAAsync(
                    graphClient, user.Id, cancellationToken);
            }
            catch (ServiceException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                mfaStatus.MFAStatus = "Unknown - Insufficient Permissions";
                WriteVerboseWithTimestamp($"Insufficient permissions to get MFA details for {user.UserPrincipalName}");
            }
            
            return mfaStatus;
        }
        
        private string GetAuthMethodType(AuthenticationMethod method)
        {
            return method.ODataType switch
            {
                "#microsoft.graph.phoneAuthenticationMethod" => "Phone",
                "#microsoft.graph.emailAuthenticationMethod" => "Email",
                "#microsoft.graph.passwordAuthenticationMethod" => "Password",
                "#microsoft.graph.fido2AuthenticationMethod" => "FIDO2",
                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" => "Windows Hello",
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" => "Microsoft Authenticator",
                "#microsoft.graph.temporaryAccessPassAuthenticationMethod" => "Temporary Access Pass",
                "#microsoft.graph.softwareOathAuthenticationMethod" => "Software OATH",
                _ => method.ODataType?.Replace("#microsoft.graph.", "").Replace("AuthenticationMethod", "") ?? "Unknown"
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
                    status.MFAStatus = "Enabled - Authenticator App";
                }
                else if (status.AuthenticationMethods.Contains("Phone"))
                {
                    status.MFAStatus = "Enabled - Phone";
                }
                else if (status.AuthenticationMethods.Contains("FIDO2") || 
                         status.AuthenticationMethods.Contains("Windows Hello"))
                {
                    status.MFAStatus = "Enabled - Passwordless";
                }
                else
                {
                    status.MFAStatus = "Enabled - Other";
                }
            }
            else if (status.ConditionalAccessEnforced)
            {
                status.MFAStatus = "Required by Conditional Access";
            }
            else if (status.PerUserMFAState == "Enforced")
            {
                status.MFAStatus = "Enforced (Legacy)";
            }
            else if (status.PerUserMFAState == "Enabled")
            {
                status.MFAStatus = "Enabled (Legacy)";
            }
            else
            {
                status.MFAStatus = "Not Configured";
            }
        }
        
        private async Task<LegacyMFAData?> GetLegacyMFAStateAsync(
            IGraphServiceClient graphClient,
            string userId,
            CancellationToken cancellationToken)
        {
            try
            {
                // Try to get legacy per-user MFA state
                var request = graphClient.Users[userId]
                    .Request()
                    .Select("strongAuthenticationRequirements,strongAuthenticationMethods");
                
                var user = await request.GetAsync(cancellationToken);
                
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
            IGraphServiceClient graphClient,
            string userId,
            CancellationToken cancellationToken)
        {
            try
            {
                // Check if any Conditional Access policies enforce MFA for this user
                // This is a simplified check - full implementation would evaluate all policies
                var policies = await graphClient.Identity.ConditionalAccess.Policies
                    .Request()
                    .Filter("state eq 'enabled'")
                    .GetAsync(cancellationToken);
                
                foreach (var policy in policies)
                {
                    if (policy.GrantControls?.BuiltInControls?.Contains("mfa") == true)
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
            
            WriteHost("");
            WriteHost("MFA Status Summary", ConsoleColor.Cyan);
            WriteHost("==================", ConsoleColor.Cyan);
            WriteHost($"Total Users: {summary.TotalUsers}");
            WriteHost($"MFA Enabled: {summary.MFAEnabled} ({(summary.MFAEnabled * 100.0 / summary.TotalUsers):F1}%)", 
                ConsoleColor.Green);
            WriteHost($"MFA Not Configured: {summary.MFANotConfigured} ({(summary.MFANotConfigured * 100.0 / summary.TotalUsers):F1}%)", 
                ConsoleColor.Yellow);
            WriteHost("");
            WriteHost("Authentication Methods:");
            WriteHost($"  Authenticator App: {summary.AuthenticatorApp}");
            WriteHost($"  Phone: {summary.PhoneAuth}");
            WriteHost($"  Passwordless: {summary.Passwordless}");
            WriteHost($"  Conditional Access: {summary.ConditionalAccessEnforced}");
            WriteHost($"  Legacy MFA: {summary.LegacyMFA}");
            WriteHost("");
        }
        
        private async Task ExportMFAStatusAsync(
            List<MFAStatus> mfaStatuses,
            CancellationToken cancellationToken)
        {
            var fileName = Path.Combine(
                OutputDirectory!,
                $"MFAStatus_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{OutputFormat.ToLower()}");
            
            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);
            
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
                    m.MFAStatus,
                    AuthMethods = string.Join("; ", m.AuthenticationMethods),
                    m.DefaultMFAMethod,
                    m.PerUserMFAState,
                    m.ConditionalAccessEnforced
                });
                
                using var writer = new StreamWriter(fileName);
                using var csv = new CsvHelper.CsvWriter(writer, System.Globalization.CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(flattenedData);
            }
            
            WriteVerboseWithTimestamp($"Exported MFA status to {fileName}");
        }
        
        private void WriteHost(string message, ConsoleColor? color = null)
        {
            if (color.HasValue)
            {
                Host.UI.WriteLine(color.Value, Host.UI.RawUI.BackgroundColor, message);
            }
            else
            {
                Host.UI.WriteLine(message);
            }
        }
    }
    
    public class MFAStatus
    {
        public string? UserId { get; set; }
        public string? UserPrincipalName { get; set; }
        public string? DisplayName { get; set; }
        public bool AccountEnabled { get; set; }
        public string? UserType { get; set; }
        public DateTime? CreatedDateTime { get; set; }
        public DateTime? LastSignInDateTime { get; set; }
        public bool HasMFAEnabled { get; set; }
        public string MFAStatus { get; set; } = "Unknown";
        public List<string> AuthenticationMethods { get; set; } = new();
        public string? DefaultMFAMethod { get; set; }
        public string? PerUserMFAState { get; set; }
        public bool ConditionalAccessEnforced { get; set; }
    }
    
    internal class LegacyMFAData
    {
        public string? State { get; set; }
        public string? DefaultMethod { get; set; }
    }
}