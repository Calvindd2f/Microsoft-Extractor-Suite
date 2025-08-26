namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Graph;
    using Microsoft.Graph.Models;


    /// <summary>
    /// Cmdlet to collect product licenses and assignments for analysis
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "ProductLicenses")]
    [OutputType(typeof(ProductLicensesResult))]
    public class GetProductLicensesCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve license information for. If not specified, retrieves for all users")]
#pragma warning disable SA1600
        public string[] UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
#pragma warning disable SA1600
        public string OutputDir { get; set; } = "Output\\Licenses";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "File encoding for output files")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Include detailed service plan information")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeServicePlans { get; set; }

        [Parameter(
            HelpMessage = "Include license compatibility analysis")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeCompatibilityAnalysis { get; set; }

        [Parameter(
            HelpMessage = "Include license usage statistics")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeUsageStatistics { get; set; }

        [Parameter(
            HelpMessage = "Operation mode: All, ByUser, Summary")]
        [ValidateSet("All", "ByUser", "Summary")]
#pragma warning disable SA1600
        public string Mode { get; set; } = "All";
#pragma warning restore SA1600

#pragma warning disable SA1309
#pragma warning disable SA1201
        private GraphApiClient? _graphClient;
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning restore SA1309
sho

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
#pragma warning disable SA1101
            if (AuthManager.GraphClient != null)
            {
#pragma warning disable SA1101
                _graphClient = new GraphApiClient(AuthManager.GraphClient);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        protected override async Task ProcessRecordAsync()
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting Product Licenses Collection ===");
#pragma warning restore SA1101

            // Check for authentication
#pragma warning disable SA1101
            if (_graphClient == null || !await _graphClient.IsConnectedAsync())
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp("Not connected to Microsoft Graph. Please run Connect-M365 first.");
#pragma warning restore SA1101
                return;
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            var outputDirectory = GetOutputDirectory();
#pragma warning restore SA1101
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmm");

            var summary = new ProductLicensesSummary
            {
                StartTime = DateTime.Now,
                ProcessedUsers = 0,
                TotalLicenses = 0,
                AssignedLicenses = 0,
                UnassignedLicenses = 0,
                OutputFiles = new List<string>()
            };

            try
            {
#pragma warning disable SA1101
                switch (Mode.ToUpperInvariant())
                {
                    case "ALL":
#pragma warning disable SA1101
                        await ProcessAllLicensesAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                    case "BYUSER":
#pragma warning disable SA1101
                        await ProcessLicensesByUserAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                    case "SUMMARY":
#pragma warning disable SA1101
                        await ProcessLicenseSummaryAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (IncludeCompatibilityAnalysis)
                {
#pragma warning disable SA1101
                    await ProcessCompatibilityAnalysisAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
#pragma warning disable SA1101
                LogSummary(summary);
#pragma warning restore SA1101

                var result = new ProductLicensesResult
                {
                    Licenses = new List<ProductLicense>(),
                    UserLicenses = new List<UserLicense>(),
                    CompatibilityAnalysis = new List<LicenseCompatibility>(),
                    Summary = summary
                };

#pragma warning disable SA1101
                WriteObject(result);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during product licenses collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task ProcessAllLicensesAsync(string outputDirectory, string timestamp, ProductLicensesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Processing all product licenses...");
#pragma warning restore SA1101

            // Get all available SKUs
#pragma warning disable SA1101
            var subscribedSkus = await _graphClient.GetSubscribedSkusAsync();
#pragma warning restore SA1101
            var licenses = new List<ProductLicense>();

            foreach (var sku in subscribedSkus)
            {
#pragma warning disable SA1101
                var license = new ProductLicense
                {
                    SkuId = sku.SkuId?.ToString() ?? string.Empty,
                    SkuPartNumber = sku.SkuPartNumber,
                    ProductName = GetProductName(sku.SkuPartNumber),
                    ConsumedUnits = sku.ConsumedUnits ?? 0,
                    PrepaidUnits = ProcessPrepaidUnits(sku.PrepaidUnits),
                    ServicePlans = IncludeServicePlans ? ProcessServicePlans(sku.ServicePlans) : new List<ServicePlan>(),
                    CapabilityStatus = sku.CapabilityStatus
                };
#pragma warning restore SA1101

                license.AvailableUnits = license.PrepaidUnits.Enabled - license.ConsumedUnits;
                licenses.Add(license);

                summary.TotalLicenses += license.PrepaidUnits.Enabled;
                summary.AssignedLicenses += license.ConsumedUnits;
                summary.UnassignedLicenses += license.AvailableUnits;
            }

            if (licenses.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-ProductLicenses.csv");
#pragma warning disable SA1101
                await WriteProductLicensesAsync(licenses, fileName);
#pragma warning restore SA1101
                summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                WriteVerbose($"Product licenses written to: {fileName}");
#pragma warning restore SA1101
            }

            // Get user license assignments
#pragma warning disable SA1101
            await ProcessUserLicenseAssignmentsAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
        }

        private async Task ProcessLicensesByUserAsync(string outputDirectory, string timestamp, ProductLicensesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Processing licenses by user...");
#pragma warning restore SA1101

            var userLicenses = new List<UserLicense>();
            var users = new List<User>();

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
                        var user = await _graphClient.GetUserAsync(userId);
#pragma warning restore SA1101
                        if (user != null)
                        {
                            users.Add(user);
                        }
                    }
                    catch (Exception ex)
                    {
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"Could not retrieve user {userId}: {ex.Message}");
#pragma warning restore SA1101
                    }
                }
#pragma warning restore SA1101
            }
            else
            {
                // Get all licensed users
#pragma warning disable SA1101
                users = (await _graphClient.GetUsersWithLicensesAsync()).ToList();
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            foreach (var user in users)
            {
                try
                {
#pragma warning disable SA1101
                    var userLicense = await ProcessUserLicenseAsync(user);
#pragma warning restore SA1101
                    userLicenses.Add(userLicense);
                    summary.ProcessedUsers++;
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Failed to process licenses for user {user.UserPrincipalName}: {ex.Message}");
#pragma warning restore SA1101
                }
            }

            if (userLicenses.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-UserLicenses.csv");
#pragma warning disable SA1101
                await WriteUserLicensesAsync(userLicenses, fileName);
#pragma warning restore SA1101
                summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                WriteVerbose($"User licenses written to: {fileName}");
#pragma warning restore SA1101
            }
        }

        private async Task ProcessLicenseSummaryAsync(string outputDirectory, string timestamp, ProductLicensesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Processing license summary...");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var subscribedSkus = await _graphClient.GetSubscribedSkusAsync();
#pragma warning restore SA1101
            var licenseSummaries = new List<LicenseSummary>();

            foreach (var sku in subscribedSkus)
            {
#pragma warning disable SA1101
                var licenseSummary = new LicenseSummary
                {
                    ProductName = GetProductName(sku.SkuPartNumber),
                    SkuPartNumber = sku.SkuPartNumber,
                    TotalLicenses = sku.PrepaidUnits?.Enabled ?? 0,
                    AssignedLicenses = sku.ConsumedUnits ?? 0,
                    AvailableLicenses = (sku.PrepaidUnits?.Enabled ?? 0) - (sku.ConsumedUnits ?? 0),
                    UtilizationPercentage = CalculateUtilizationPercentage(sku.ConsumedUnits ?? 0, sku.PrepaidUnits?.Enabled ?? 0)
                };
#pragma warning restore SA1101

                licenseSummaries.Add(licenseSummary);

                summary.TotalLicenses += licenseSummary.TotalLicenses;
                summary.AssignedLicenses += licenseSummary.AssignedLicenses;
                summary.UnassignedLicenses += licenseSummary.AvailableLicenses;
            }

            if (licenseSummaries.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-LicenseSummary.csv");
#pragma warning disable SA1101
                await WriteLicenseSummaryAsync(licenseSummaries, fileName);
#pragma warning restore SA1101
                summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                WriteVerbose($"License summary written to: {fileName}");
#pragma warning restore SA1101
            }
        }

        private async Task ProcessCompatibilityAnalysisAsync(string outputDirectory, string timestamp, ProductLicensesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Processing license compatibility analysis...");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var subscribedSkus = await _graphClient.GetSubscribedSkusAsync();
#pragma warning restore SA1101
            var compatibilityResults = new List<LicenseCompatibility>();

            // Analyze conflicting service plans
            foreach (var sku1 in subscribedSkus)
            {
                foreach (var sku2 in subscribedSkus)
                {
                    if (sku1.SkuId?.ToString() == sku2.SkuId?.ToString()) continue;

#pragma warning disable SA1101
                    var conflicts = FindServicePlanConflicts(sku1.ServicePlans, sku2.ServicePlans);
#pragma warning restore SA1101
                    if (conflicts.Count > 0)
                    {
                        var compatibility = new LicenseCompatibility
                        {
                            License1 = sku1.SkuPartNumber,
                            License2 = sku2.SkuPartNumber,
                            ConflictingServicePlans = conflicts,
                            CompatibilityStatus = "Conflicting",
                            RecommendedAction = "Review conflicting service plans before assigning both licenses"
                        };

                        compatibilityResults.Add(compatibility);
                    }
                }
            }

            if (compatibilityResults.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-LicenseCompatibility.csv");
#pragma warning disable SA1101
                await WriteLicenseCompatibilityAsync(compatibilityResults, fileName);
#pragma warning restore SA1101
                summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                WriteVerbose($"License compatibility analysis written to: {fileName}");
#pragma warning restore SA1101
            }
        }

        private async Task ProcessUserLicenseAssignmentsAsync(string outputDirectory, string timestamp, ProductLicensesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("Processing user license assignments...");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var users = await _graphClient.GetUsersWithLicensesAsync();
#pragma warning restore SA1101
            var userLicenseAssignments = new List<UserLicenseAssignment>();

            foreach (var user in users)
            {
                try
                {
                    if (user.AssignedLicenses != null)
                    {
                        foreach (var assignedLicense in user.AssignedLicenses)
                        {
#pragma warning disable SA1101
                            var assignment = new UserLicenseAssignment
                            {
                                UserId = user.Id,
                                UserPrincipalName = user.UserPrincipalName,
                                DisplayName = user.DisplayName,
                                SkuId = assignedLicense.SkuId?.ToString() ?? string.Empty,
                                DisabledPlans = assignedLicense.DisabledPlans?.Select(d => d.ToString()).ToList() ?? new List<string>(),
                                AssignmentSource = DetermineAssignmentSource(assignedLicense),
                                LastUpdated = DateTime.Now
                            };
#pragma warning restore SA1101

                            userLicenseAssignments.Add(assignment);
                        }
                    }

                    summary.ProcessedUsers++;
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Failed to process license assignments for user {user.UserPrincipalName}: {ex.Message}");
#pragma warning restore SA1101
                }
            }

            if (userLicenseAssignments.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-UserLicenseAssignments.csv");
#pragma warning disable SA1101
                await WriteUserLicenseAssignmentsAsync(userLicenseAssignments, fileName);
#pragma warning restore SA1101
                summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                WriteVerbose($"User license assignments written to: {fileName}");
#pragma warning restore SA1101
            }
        }

        private async Task<UserLicense> ProcessUserLicenseAsync(User user)
        {
            var userLicense = new UserLicense
            {
                UserId = user.Id,
                UserPrincipalName = user.UserPrincipalName,
                DisplayName = user.DisplayName,
                Department = user.Department,
                JobTitle = user.JobTitle,
                AccountEnabled = user.AccountEnabled ?? false,
                Licenses = new List<string>(),
                TotalLicenseCost = 0
            };

            if (user.AssignedLicenses != null)
            {
#pragma warning disable SA1101
                var subscribedSkus = await _graphClient.GetSubscribedSkusAsync();
#pragma warning restore SA1101

                foreach (var assignedLicense in user.AssignedLicenses)
                {
                    var sku = subscribedSkus.FirstOrDefault(s => s.SkuId == assignedLicense.SkuId);
                    if (sku != null)
                    {
#pragma warning disable SA1101
                        var productName = GetProductName(sku.SkuPartNumber);
#pragma warning restore SA1101
                        userLicense.Licenses.Add(productName);
                        // Note: Cost calculation would require additional pricing data
                    }
                }
            }

            return userLicense;
        }

        private PrepaidUnits ProcessPrepaidUnits(dynamic prepaidUnits)
        {
            if (prepaidUnits == null)
                return new PrepaidUnits();

            return new PrepaidUnits
            {
                Enabled = prepaidUnits.Enabled ?? 0,
                Suspended = prepaidUnits.Suspended ?? 0,
                Warning = prepaidUnits.Warning ?? 0
            };
        }

        private List<ServicePlan> ProcessServicePlans(dynamic servicePlans)
        {
            var plans = new List<ServicePlan>();

            if (servicePlans != null)
            {
                foreach (var plan in servicePlans)
                {
                    var servicePlan = new ServicePlan
                    {
                        ServicePlanId = plan.ServicePlanId?.ToString() ?? string.Empty,
                        ServicePlanName = plan.ServicePlanName,
                        ProvisioningStatus = plan.ProvisioningStatus,
                        AppliesTo = plan.AppliesTo
                    };

                    plans.Add(servicePlan);
                }
            }

            return plans;
        }

        private List<string> FindServicePlanConflicts(dynamic servicePlans1, dynamic servicePlans2)
        {
            var conflicts = new List<string>();

            // This would contain logic to identify conflicting service plans
            // For now, return empty list as placeholder

            return conflicts;
        }

        private string GetProductName(string skuPartNumber)
        {
            // Map common SKU part numbers to friendly names
            var productNames = new Dictionary<string, string>
            {
                { "ENTERPRISEPACK", "Microsoft 365 E3" },
                { "ENTERPRISEPREMIUM", "Microsoft 365 E5" },
                { "SPB", "Microsoft 365 Business Premium" },
                { "SPE_E3", "Microsoft 365 E3" },
                { "SPE_E5", "Microsoft 365 E5" },
                { "EXCHANGESTANDARD", "Exchange Online Plan 1" },
                { "EXCHANGEENTERPRISE", "Exchange Online Plan 2" },
                { "SHAREPOINTSTANDARD", "SharePoint Online Plan 1" },
                { "SHAREPOINTENTERPRISE", "SharePoint Online Plan 2" }
            };

            return productNames.TryGetValue(skuPartNumber, out var productName) ? productName : skuPartNumber;
        }

        private double CalculateUtilizationPercentage(int consumed, int total)
        {
            if (total == 0) return 0;
            return Math.Round((double)consumed / total * 100, 2);
        }

        private string DetermineAssignmentSource(dynamic assignedLicense)
        {
            // Logic to determine if license was assigned directly or via group
            // This would require additional API calls to check group memberships
            return "Direct"; // Placeholder
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

        private void LogSummary(ProductLicensesSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("=== Product Licenses Collection Summary ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Users Processed: {summary.ProcessedUsers:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Total Licenses: {summary.TotalLicenses:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Assigned Licenses: {summary.AssignedLicenses:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Unassigned Licenses: {summary.UnassignedLicenses:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Utilization Rate: {(summary.TotalLicenses > 0 ? Math.Round((double)summary.AssignedLicenses / summary.TotalLicenses * 100, 1) : 0):F1}%");
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
            WriteVerbose("============================================");
#pragma warning restore SA1101
        }

        // Write methods for different file types
        private async Task WriteProductLicensesAsync(IEnumerable<ProductLicense> licenses, string filePath)
        {
            var csv = "SkuId,SkuPartNumber,ProductName,ConsumedUnits,EnabledUnits,AvailableUnits,CapabilityStatus" + Environment.NewLine;

            foreach (var license in licenses)
            {
#pragma warning disable SA1101
                var values = new[]
                {
                    EscapeCsvValue(license.SkuId),
                    EscapeCsvValue(license.SkuPartNumber),
                    EscapeCsvValue(license.ProductName),
                    license.ConsumedUnits.ToString(),
                    license.PrepaidUnits.Enabled.ToString(),
                    license.AvailableUnits.ToString(),
                    EscapeCsvValue(license.CapabilityStatus)
                };
#pragma warning restore SA1101

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteUserLicensesAsync(IEnumerable<UserLicense> licenses, string filePath)
        {
            var csv = "UserId,UserPrincipalName,DisplayName,Department,JobTitle,AccountEnabled,Licenses,TotalLicenseCost" + Environment.NewLine;

            foreach (var license in licenses)
            {
#pragma warning disable SA1101
                var values = new[]
                {
                    EscapeCsvValue(license.UserId),
                    EscapeCsvValue(license.UserPrincipalName),
                    EscapeCsvValue(license.DisplayName),
                    EscapeCsvValue(license.Department),
                    EscapeCsvValue(license.JobTitle),
                    license.AccountEnabled.ToString(),
                    EscapeCsvValue(string.Join("; ", license.Licenses)),
                    license.TotalLicenseCost.ToString("F2")
                };
#pragma warning restore SA1101

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteLicenseSummaryAsync(IEnumerable<LicenseSummary> summaries, string filePath)
        {
            var csv = "ProductName,SkuPartNumber,TotalLicenses,AssignedLicenses,AvailableLicenses,UtilizationPercentage" + Environment.NewLine;

            foreach (var summary in summaries)
            {
#pragma warning disable SA1101
                var values = new[]
                {
                    EscapeCsvValue(summary.ProductName),
                    EscapeCsvValue(summary.SkuPartNumber),
                    summary.TotalLicenses.ToString(),
                    summary.AssignedLicenses.ToString(),
                    summary.AvailableLicenses.ToString(),
                    summary.UtilizationPercentage.ToString("F1")
                };
#pragma warning restore SA1101

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteLicenseCompatibilityAsync(IEnumerable<LicenseCompatibility> compatibilities, string filePath)
        {
            var csv = "License1,License2,ConflictingServicePlans,CompatibilityStatus,RecommendedAction" + Environment.NewLine;

            foreach (var compatibility in compatibilities)
            {
#pragma warning disable SA1101
                var values = new[]
                {
                    EscapeCsvValue(compatibility.License1),
                    EscapeCsvValue(compatibility.License2),
                    EscapeCsvValue(string.Join("; ", compatibility.ConflictingServicePlans)),
                    EscapeCsvValue(compatibility.CompatibilityStatus),
                    EscapeCsvValue(compatibility.RecommendedAction)
                };
#pragma warning restore SA1101

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteUserLicenseAssignmentsAsync(IEnumerable<UserLicenseAssignment> assignments, string filePath)
        {
            var csv = "UserId,UserPrincipalName,DisplayName,SkuId,DisabledPlans,AssignmentSource,LastUpdated" + Environment.NewLine;

            foreach (var assignment in assignments)
            {
#pragma warning disable SA1101
                var values = new[]
                {
                    EscapeCsvValue(assignment.UserId),
                    EscapeCsvValue(assignment.UserPrincipalName),
                    EscapeCsvValue(assignment.DisplayName),
                    EscapeCsvValue(assignment.SkuId),
                    EscapeCsvValue(string.Join("; ", assignment.DisabledPlans)),
                    EscapeCsvValue(assignment.AssignmentSource),
                    assignment.LastUpdated.ToString("yyyy-MM-dd HH:mm:ss")
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
    public class ProductLicensesResult
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
        public List<ProductLicense> Licenses { get; set; } = new List<ProductLicense>();
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        public List<UserLicense> UserLicenses { get; set; }
List<UserLicense>();
        public List<LicenseCompatibility> CompatibilityAnalysis { get; set; } = new List<LicenseCompatibility>();
#pragma warning disable SA1600
        public ProductLicensesSummary Summary { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class ProductLicense
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string SkuId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string SkuPartNumber { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ProductName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int ConsumedUnits { get; set; }
        public PrepaidUnits PrepaidUnits { get; set; } = new PrepaidUnits();
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        public int AvailableUnits { get; set; }
        public List<ServicePlan> ServicePlans { get; set; } = new List<ServicePlan>();
#pragma warning disable SA1600
        public string CapabilityStatus { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class PrepaidUnits
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int Enabled { get; set; }
        public int Suspended { get; set; }public int Warning { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class ServicePlan
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ServicePlanId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ServicePlanName { get; set; }
        public string ProvisioningStatus { get; set; }public string AppliesTo { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class UserLicense
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserPrincipalName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string DisplayName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Department { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string JobTitle { get; set; }
#pragma warning restore SA1600
        public bool AccountEnabled { get; set; }
        public List<string> Licenses { get; set; } = new List<string>();
#pragma warning disable SA1600
        public decimal TotalLicenseCost { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class LicenseSummary
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string ProductName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string SkuPartNumber { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalLicenses { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int AssignedLicenses { get; set; }
        public int AvailableLicenses { get; set; }public double UtilizationPercentage { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class LicenseCompatibility
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string License1 { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string License2 { get; set; }
        public List<string> ConflictingServicePlans {
#pragma warning restore SA1600
List<string>();
#pragma warning disable SA1600
        public string CompatibilityStatus { get; set; }public string RecommendedAction { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class UserLicenseAssignment
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserId { get; set; }
        public string UserPrincipalName {
#pragma warning restore SA1600
set; }
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string DisplayName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string SkuId { get; set; }
#pragma warning restore SA1600
        public List<string> DisabledPlans { get; set; }
List<string>();
#pragma warning disable SA1600
        public string AssignmentSource { get; set; }public DateTime LastUpdated { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class ProductLicensesSummary
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
        public int ProcessedUsers { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalLicenses { get; set; }
#pragma warning restore SA1600
        public int AssignedLicenses { get; set; }
        public int UnassignedLicenses { get; set; }public List<string> OutputFiles { get; set; } = new List<string>();
    }
}
