namespace Microsoft.ExtractorSuite.Cmdlets.Security
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
    using Microsoft.ExtractorSuite.Core.Json;
    using Microsoft.Graph;
    using Microsoft.Graph.Models;


    /// <summary>
    /// Retrieves all Conditional Access Policies from Microsoft Entra ID.
    /// Provides detailed information about policy conditions, controls, and configurations.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "ConditionalAccessPolicy")]
    [OutputType(typeof(ConditionalAccessPolicyInfo))]
    public class GetConditionalAccessPolicyCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "Output format for the results. Default: CSV")]
        [ValidateSet("CSV", "JSON")]

        public string OutputFormat { get; set; } = "CSV";


        [Parameter(HelpMessage = "Text encoding for the output file. Default: UTF8")]

        public string Encoding { get; set; } = "UTF8";



        protected override void ProcessRecord()
        {
            var results = RunAsyncOperation(GetConditionalAccessPoliciesAsync, "Getting Conditional Access Policies");
            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
        }

        private async Task<List<ConditionalAccessPolicyInfo>> GetConditionalAccessPoliciesAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Conditional Access Policy Collection");

            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Not connected to Microsoft Graph. Please run Connect-M365 first.");
            }

            var graphClient = AuthManager.GraphClient!;

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Retrieving Conditional Access Policies",
                PercentComplete = 10
            });

            var summary = new ConditionalAccessSummary
            {
                StartTime = DateTime.UtcNow
            };

            var results = new List<ConditionalAccessPolicyInfo>();

            try
            {
                WriteVerboseWithTimestamp("Fetching all Conditional Access policies...");

                // Get all Conditional Access policies
                var policies = await graphClient.Identity.ConditionalAccess.Policies
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Top = 999;
                    }, cancellationToken);

                if (policies?.Value == null)
                {
                    WriteWarningWithTimestamp("No Conditional Access policies found or insufficient permissions");
                    return results;
                }

                WriteVerboseWithTimestamp($"Found {policies.Value.Count} Conditional Access policies");
                summary.TotalPolicies = policies.Value.Count;

                var processedCount = 0;

                foreach (var policy in policies.Value)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    processedCount++;
                    WriteVerboseWithTimestamp($"Processing policy: {policy.DisplayName}");

                    var policyInfo = MapPolicyToInfo(policy);
                    results.Add(policyInfo);

                    // Update summary statistics
                    switch (policy.State)
                    {
                        case ConditionalAccessPolicyState.Enabled:
                            summary.EnabledPolicies++;
                            break;
                        case ConditionalAccessPolicyState.Disabled:
                            summary.DisabledPolicies++;
                            break;
                        case ConditionalAccessPolicyState.EnabledForReportingButNotEnforced:
                            summary.ReportOnlyPolicies++;
                            break;
                    }

                    var progressPercent = 10 + (int)((processedCount / (double)policies.Value.Count) * 70);
                    progress.Report(new Core.AsyncOperations.TaskProgress
                    {
                        CurrentOperation = $"Processed {processedCount}/{policies.Value.Count} policies",
                        PercentComplete = progressPercent,
                        ItemsProcessed = processedCount
                    });
                }

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Exporting results",
                    PercentComplete = 85
                });

                // Export results if output directory is specified
                if (!string.IsNullOrEmpty(OutputDirectory))
                {
                    await ExportPoliciesAsync(results, cancellationToken);
                }

                summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

                // Log summary
                WriteVerboseWithTimestamp($"Conditional Access Policy Summary:");
                WriteVerboseWithTimestamp($"  Total Policies: {summary.TotalPolicies}");
                WriteVerboseWithTimestamp($"  Enabled Policies: {summary.EnabledPolicies}");
                WriteVerboseWithTimestamp($"  Disabled Policies: {summary.DisabledPolicies}");
                WriteVerboseWithTimestamp($"  Report-Only Policies: {summary.ReportOnlyPolicies}");
                WriteVerboseWithTimestamp($"  Processing Time: {summary.ProcessingTime:mm\\:ss}");

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Collection completed",
                    PercentComplete = 100
                });
            }
            catch (ServiceException ex)
            {
                WriteErrorWithTimestamp($"Microsoft Graph API error: {ex.ResponseStatusCode} - {ex.Message}", ex);
                throw;
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Error retrieving Conditional Access policies: {ex.Message}", ex);
                throw;
            }

            return results;
        }

        private ConditionalAccessPolicyInfo MapPolicyToInfo(ConditionalAccessPolicy policy)
        {
            return new ConditionalAccessPolicyInfo
            {
                // Basic Information
                DisplayName = policy.DisplayName ?? "",
                Id = policy.Id ?? "",
                State = policy.State?.ToString() ?? "",
                CreatedDateTime = policy.CreatedDateTime?.DateTime,
                ModifiedDateTime = policy.ModifiedDateTime?.DateTime,
                Description = policy.Description ?? "",

                // Users and Groups
                IncludeUsers = JoinStringArray(policy.Conditions?.Users?.IncludeUsers),
                ExcludeUsers = JoinStringArray(policy.Conditions?.Users?.ExcludeUsers),
                IncludeGroups = JoinStringArray(policy.Conditions?.Users?.IncludeGroups),
                ExcludeGroups = JoinStringArray(policy.Conditions?.Users?.ExcludeGroups),
                IncludeRoles = JoinStringArray(policy.Conditions?.Users?.IncludeRoles),
                ExcludeRoles = JoinStringArray(policy.Conditions?.Users?.ExcludeRoles),

                // Applications
                IncludeApplications = JoinStringArray(policy.Conditions?.Applications?.IncludeApplications),
                ExcludeApplications = JoinStringArray(policy.Conditions?.Applications?.ExcludeApplications),
                ClientAppTypes = policy.Conditions?.ClientAppTypes != null ? string.Join("; ", policy.Conditions.ClientAppTypes.Select(c => c?.ToString() ?? "")) : "",
                IncludeUserActions = JoinStringArray(policy.Conditions?.Applications?.IncludeUserActions),

                // Platforms
                IncludePlatforms = policy.Conditions?.Platforms?.IncludePlatforms != null ? string.Join("; ", policy.Conditions.Platforms.IncludePlatforms.Select(p => p?.ToString() ?? "")) : "",
                ExcludePlatforms = policy.Conditions?.Platforms?.ExcludePlatforms != null ? string.Join("; ", policy.Conditions.Platforms.ExcludePlatforms.Select(p => p?.ToString() ?? "")) : "",

                // Locations
                IncludeLocations = JoinStringArray(policy.Conditions?.Locations?.IncludeLocations),
                ExcludeLocations = JoinStringArray(policy.Conditions?.Locations?.ExcludeLocations),

                // Risk Levels
                UserRiskLevels = policy.Conditions?.UserRiskLevels != null ? string.Join("; ", policy.Conditions.UserRiskLevels.Select(r => r?.ToString() ?? "")) : "",
                SignInRiskLevels = policy.Conditions?.SignInRiskLevels != null ? string.Join("; ", policy.Conditions.SignInRiskLevels.Select(r => r?.ToString() ?? "")) : "",
                ServicePrincipalRiskLevels = policy.Conditions?.ServicePrincipalRiskLevels != null ? string.Join("; ", policy.Conditions.ServicePrincipalRiskLevels.Select(r => r?.ToString() ?? "")) : "",

                // Device States and Filters
                IncludeDeviceStates = "", // IncludeDeviceStates removed in SDK v5
                ExcludeDeviceStates = "", // ExcludeDeviceStates removed in SDK v5
                DeviceFilter = FormatDeviceFilter(policy.Conditions?.Devices?.DeviceFilter),

                // Grant Controls
                BuiltInControls = policy.GrantControls?.BuiltInControls != null ? string.Join("; ", policy.GrantControls.BuiltInControls.Select(c => c?.ToString() ?? "")) : "",
                CustomAuthenticationFactors = JoinStringArray(policy.GrantControls?.CustomAuthenticationFactors),
                GrantOperator = policy.GrantControls?.Operator?.ToString() ?? "",
                TermsOfUse = JoinStringArray(policy.GrantControls?.TermsOfUse),

                // Session Controls
                ApplicationEnforcedRestrictions = policy.SessionControls?.ApplicationEnforcedRestrictions?.IsEnabled ?? false,
                CloudAppSecurity = policy.SessionControls?.CloudAppSecurity?.IsEnabled ?? false,
                DisableResilienceDefaults = policy.SessionControls?.DisableResilienceDefaults ?? false,
                PersistentBrowser = policy.SessionControls?.PersistentBrowser?.Mode?.ToString() ?? "",
                SignInFrequency = FormatSignInFrequency(policy.SessionControls?.SignInFrequency),

                // Additional Properties
                DeviceFilterMode = policy.Conditions?.Devices?.DeviceFilter?.Mode?.ToString() ?? "",
                DeviceFilterRule = policy.Conditions?.Devices?.DeviceFilter?.Rule ?? "",

                // Compliance and Authentication Context
                AuthenticationContextClassReferences = JoinStringArray(policy.Conditions?.Applications?.IncludeAuthenticationContextClassReferences),
                InsiderRiskLevels = "" // InsiderRiskLevels not available in SDK v5
            };
        }

        private string JoinStringArray(IEnumerable<string>? items)
        {
            return items != null ? string.Join("; ", items) : "";
        }

        private string JoinEnumArray<T>(IEnumerable<T>? items) where T : Enum
        {
            return items != null ? string.Join("; ", items.Select(i => i.ToString())) : "";
        }

        private string FormatDeviceFilter(ConditionalAccessFilter? filter)
        {
            if (filter?.Rule == null)
                return "Not Configured";

            return $"{filter.Mode}: {filter.Rule}";
        }

        private string FormatSignInFrequency(SignInFrequencySessionControl? signInFrequency)
        {
            if (signInFrequency?.Value == null || signInFrequency?.Type == null)
                return "";

            return $"{signInFrequency.Value} {signInFrequency.Type}";
        }

        private async Task ExportPoliciesAsync(List<ConditionalAccessPolicyInfo> policies, CancellationToken cancellationToken)
        {
            var fileName = Path.Combine(
                OutputDirectory!,
                $"ConditionalAccessPolicies_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{OutputFormat.ToLower()}");

            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

            if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.Create(fileName);
                using var processor = new HighPerformanceJsonProcessor();
                await processor.SerializeAsync(stream, policies, true, cancellationToken);
            }
            else // CSV
            {
                using var writer = new StreamWriter(fileName, false, System.Text.Encoding.GetEncoding(Encoding));
                using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(policies, cancellationToken);
            }

            WriteVerboseWithTimestamp($"Exported {policies.Count} Conditional Access policies to {fileName}");
        }
    }


    public class ConditionalAccessPolicyInfo

    {
        // Basic Information

        public string DisplayName { get; set; } = string.Empty;


        public string Id { get; set; } = string.Empty;


        public string State { get; set; } = string.Empty;


        public DateTime? CreatedDateTime { get; set; }


        public DateTime? ModifiedDateTime { get; set; }


        public string Description { get; set; } = string.Empty;


        // Users and Groups

        public string IncludeUsers { get; set; } = string.Empty;


        public string ExcludeUsers { get; set; } = string.Empty;


        public string IncludeGroups { get; set; } = string.Empty;


        public string ExcludeGroups { get; set; } = string.Empty;


        public string IncludeRoles { get; set; } = string.Empty;


        public string ExcludeRoles { get; set; } = string.Empty;


        // Applications

        public string IncludeApplications { get; set; } = string.Empty;


        public string ExcludeApplications { get; set; } = string.Empty;


        public string ClientAppTypes { get; set; } = string.Empty;


        public string IncludeUserActions { get; set; } = string.Empty;


        // Platforms

        public string IncludePlatforms { get; set; } = string.Empty;


        public string ExcludePlatforms { get; set; } = string.Empty;


        // Locations

        public string IncludeLocations { get; set; } = string.Empty;


        public string ExcludeLocations { get; set; } = string.Empty;


        // Risk Levels

        public string UserRiskLevels { get; set; } = string.Empty;


        public string SignInRiskLevels { get; set; } = string.Empty;


        public string ServicePrincipalRiskLevels { get; set; } = string.Empty;


        // Device States and Filters

        public string IncludeDeviceStates { get; set; } = string.Empty;


        public string ExcludeDeviceStates { get; set; } = string.Empty;


        public string DeviceFilter { get; set; } = string.Empty;


        // Grant Controls

        public string BuiltInControls { get; set; } = string.Empty;


        public string CustomAuthenticationFactors { get; set; } = string.Empty;


        public string GrantOperator { get; set; } = string.Empty;


        public string TermsOfUse { get; set; } = string.Empty;


        // Session Controls



        public bool ApplicationEnforcedRestrictions { get; set; }


        public bool CloudAppSecurity { get; set; }


        public bool DisableResilienceDefaults { get; set; }
        public string PersistentBrowser { get; set; } = string.Empty;


        public string SignInFrequency { get; set; } = string.Empty;


        // Additional Properties

        public string DeviceFilterMode { get; set; } = string.Empty;


        public string DeviceFilterRule { get; set; } = string.Empty;


        public string AuthenticationContextClassReferences { get; set; } = string.Empty;


        public string InsiderRiskLevels { get; set; } = string.Empty;

    }


    public class ConditionalAccessSummary

    {



        public DateTime StartTime { get; set; }


        public TimeSpan ProcessingTime { get; set; }


        public int TotalPolicies { get; set; }


        public int EnabledPolicies { get; set; }


        public int DisabledPolicies { get; set; }

        public int ReportOnlyPolicies { get; set; }
    }
}
