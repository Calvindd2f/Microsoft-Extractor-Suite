using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Graph;

namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    /// <summary>
    /// Cmdlet to collect product licenses and assignments for analysis
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "ProductLicenses")]
    [OutputType(typeof(ProductLicensesResult))]
    public class GetProductLicensesCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve license information for. If not specified, retrieves for all users")]
        public string[] UserIds { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
        public string OutputDir { get; set; } = "Output\\Licenses";

        [Parameter(
            HelpMessage = "File encoding for output files")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(
            HelpMessage = "Include detailed service plan information")]
        public SwitchParameter IncludeServicePlans { get; set; }

        [Parameter(
            HelpMessage = "Include license compatibility analysis")]
        public SwitchParameter IncludeCompatibilityAnalysis { get; set; }

        [Parameter(
            HelpMessage = "Include license usage statistics")]
        public SwitchParameter IncludeUsageStatistics { get; set; }

        [Parameter(
            HelpMessage = "Operation mode: All, ByUser, Summary")]
        [ValidateSet("All", "ByUser", "Summary")]
        public string Mode { get; set; } = "All";

        private readonly GraphApiClient _graphClient;

        public GetProductLicensesCmdlet()
        {
            _graphClient = new GraphApiClient();
        }

        protected override async Task ProcessRecordAsync()
        {
            LogInformation("=== Starting Product Licenses Collection ===");
            
            // Check for authentication
            if (!await _graphClient.IsConnectedAsync())
            {
                LogError("Not connected to Microsoft Graph. Please run Connect-M365 first.");
                return;
            }

            var outputDirectory = GetOutputDirectory();
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
                switch (Mode.ToUpperInvariant())
                {
                    case "ALL":
                        await ProcessAllLicensesAsync(outputDirectory, timestamp, summary);
                        break;
                    case "BYUSER":
                        await ProcessLicensesByUserAsync(outputDirectory, timestamp, summary);
                        break;
                    case "SUMMARY":
                        await ProcessLicenseSummaryAsync(outputDirectory, timestamp, summary);
                        break;
                }

                if (IncludeCompatibilityAnalysis)
                {
                    await ProcessCompatibilityAnalysisAsync(outputDirectory, timestamp, summary);
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
                LogSummary(summary);

                var result = new ProductLicensesResult
                {
                    Licenses = new List<ProductLicense>(),
                    UserLicenses = new List<UserLicense>(),
                    CompatibilityAnalysis = new List<LicenseCompatibility>(),
                    Summary = summary
                };

                WriteObject(result);
            }
            catch (Exception ex)
            {
                LogError($"An error occurred during product licenses collection: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessAllLicensesAsync(string outputDirectory, string timestamp, ProductLicensesSummary summary)
        {
            LogInformation("Processing all product licenses...");

            // Get all available SKUs
            var subscribedSkus = await _graphClient.GetSubscribedSkusAsync();
            var licenses = new List<ProductLicense>();

            foreach (var sku in subscribedSkus)
            {
                var license = new ProductLicense
                {
                    SkuId = sku.SkuId,
                    SkuPartNumber = sku.SkuPartNumber,
                    ProductName = GetProductName(sku.SkuPartNumber),
                    ConsumedUnits = sku.ConsumedUnits ?? 0,
                    PrepaidUnits = ProcessPrepaidUnits(sku.PrepaidUnits),
                    ServicePlans = IncludeServicePlans ? ProcessServicePlans(sku.ServicePlans) : new List<ServicePlan>(),
                    CapabilityStatus = sku.CapabilityStatus
                };

                license.AvailableUnits = license.PrepaidUnits.Enabled - license.ConsumedUnits;
                licenses.Add(license);

                summary.TotalLicenses += license.PrepaidUnits.Enabled;
                summary.AssignedLicenses += license.ConsumedUnits;
                summary.UnassignedLicenses += license.AvailableUnits;
            }

            if (licenses.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-ProductLicenses.csv");
                await WriteProductLicensesAsync(licenses, fileName);
                summary.OutputFiles.Add(fileName);
                
                LogInformation($"Product licenses written to: {fileName}");
            }

            // Get user license assignments
            await ProcessUserLicenseAssignmentsAsync(outputDirectory, timestamp, summary);
        }

        private async Task ProcessLicensesByUserAsync(string outputDirectory, string timestamp, ProductLicensesSummary summary)
        {
            LogInformation("Processing licenses by user...");

            var userLicenses = new List<UserLicense>();
            var users = new List<dynamic>();

            if (UserIds != null && UserIds.Length > 0)
            {
                // Process specific users
                foreach (var userId in UserIds)
                {
                    try
                    {
                        var user = await _graphClient.GetUserAsync(userId);
                        if (user != null)
                        {
                            users.Add(user);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogWarning($"Could not retrieve user {userId}: {ex.Message}");
                    }
                }
            }
            else
            {
                // Get all licensed users
                users = await _graphClient.GetUsersWithLicensesAsync();
            }

            foreach (var user in users)
            {
                try
                {
                    var userLicense = await ProcessUserLicenseAsync(user);
                    userLicenses.Add(userLicense);
                    summary.ProcessedUsers++;
                }
                catch (Exception ex)
                {
                    LogWarning($"Failed to process licenses for user {user.UserPrincipalName}: {ex.Message}");
                }
            }

            if (userLicenses.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-UserLicenses.csv");
                await WriteUserLicensesAsync(userLicenses, fileName);
                summary.OutputFiles.Add(fileName);
                
                LogInformation($"User licenses written to: {fileName}");
            }
        }

        private async Task ProcessLicenseSummaryAsync(string outputDirectory, string timestamp, ProductLicensesSummary summary)
        {
            LogInformation("Processing license summary...");

            var subscribedSkus = await _graphClient.GetSubscribedSkusAsync();
            var licenseSummaries = new List<LicenseSummary>();

            foreach (var sku in subscribedSkus)
            {
                var licenseSummary = new LicenseSummary
                {
                    ProductName = GetProductName(sku.SkuPartNumber),
                    SkuPartNumber = sku.SkuPartNumber,
                    TotalLicenses = sku.PrepaidUnits?.Enabled ?? 0,
                    AssignedLicenses = sku.ConsumedUnits ?? 0,
                    AvailableLicenses = (sku.PrepaidUnits?.Enabled ?? 0) - (sku.ConsumedUnits ?? 0),
                    UtilizationPercentage = CalculateUtilizationPercentage(sku.ConsumedUnits ?? 0, sku.PrepaidUnits?.Enabled ?? 0)
                };

                licenseSummaries.Add(licenseSummary);

                summary.TotalLicenses += licenseSummary.TotalLicenses;
                summary.AssignedLicenses += licenseSummary.AssignedLicenses;
                summary.UnassignedLicenses += licenseSummary.AvailableLicenses;
            }

            if (licenseSummaries.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-LicenseSummary.csv");
                await WriteLicenseSummaryAsync(licenseSummaries, fileName);
                summary.OutputFiles.Add(fileName);
                
                LogInformation($"License summary written to: {fileName}");
            }
        }

        private async Task ProcessCompatibilityAnalysisAsync(string outputDirectory, string timestamp, ProductLicensesSummary summary)
        {
            LogInformation("Processing license compatibility analysis...");

            var subscribedSkus = await _graphClient.GetSubscribedSkusAsync();
            var compatibilityResults = new List<LicenseCompatibility>();

            // Analyze conflicting service plans
            foreach (var sku1 in subscribedSkus)
            {
                foreach (var sku2 in subscribedSkus)
                {
                    if (sku1.SkuId == sku2.SkuId) continue;

                    var conflicts = FindServicePlanConflicts(sku1.ServicePlans, sku2.ServicePlans);
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
                await WriteLicenseCompatibilityAsync(compatibilityResults, fileName);
                summary.OutputFiles.Add(fileName);
                
                LogInformation($"License compatibility analysis written to: {fileName}");
            }
        }

        private async Task ProcessUserLicenseAssignmentsAsync(string outputDirectory, string timestamp, ProductLicensesSummary summary)
        {
            LogInformation("Processing user license assignments...");

            var users = await _graphClient.GetUsersWithLicensesAsync();
            var userLicenseAssignments = new List<UserLicenseAssignment>();

            foreach (var user in users)
            {
                try
                {
                    if (user.AssignedLicenses != null)
                    {
                        foreach (var assignedLicense in user.AssignedLicenses)
                        {
                            var assignment = new UserLicenseAssignment
                            {
                                UserId = user.Id,
                                UserPrincipalName = user.UserPrincipalName,
                                DisplayName = user.DisplayName,
                                SkuId = assignedLicense.SkuId,
                                DisabledPlans = assignedLicense.DisabledPlans?.ToList() ?? new List<string>(),
                                AssignmentSource = DetermineAssignmentSource(assignedLicense),
                                LastUpdated = DateTime.Now
                            };

                            userLicenseAssignments.Add(assignment);
                        }
                    }

                    summary.ProcessedUsers++;
                }
                catch (Exception ex)
                {
                    LogWarning($"Failed to process license assignments for user {user.UserPrincipalName}: {ex.Message}");
                }
            }

            if (userLicenseAssignments.Count > 0)
            {
                var fileName = Path.Combine(outputDirectory, $"{timestamp}-UserLicenseAssignments.csv");
                await WriteUserLicenseAssignmentsAsync(userLicenseAssignments, fileName);
                summary.OutputFiles.Add(fileName);
                
                LogInformation($"User license assignments written to: {fileName}");
            }
        }

        private async Task<UserLicense> ProcessUserLicenseAsync(dynamic user)
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
                var subscribedSkus = await _graphClient.GetSubscribedSkusAsync();
                
                foreach (var assignedLicense in user.AssignedLicenses)
                {
                    var sku = subscribedSkus.FirstOrDefault(s => s.SkuId == assignedLicense.SkuId);
                    if (sku != null)
                    {
                        var productName = GetProductName(sku.SkuPartNumber);
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
                        ServicePlanId = plan.ServicePlanId,
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
            var directory = OutputDir;
            
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
                LogInformation($"Created output directory: {directory}");
            }

            return directory;
        }

        private void LogSummary(ProductLicensesSummary summary)
        {
            LogInformation("");
            LogInformation("=== Product Licenses Collection Summary ===");
            LogInformation($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
            LogInformation($"Users Processed: {summary.ProcessedUsers:N0}");
            LogInformation($"Total Licenses: {summary.TotalLicenses:N0}");
            LogInformation($"Assigned Licenses: {summary.AssignedLicenses:N0}");
            LogInformation($"Unassigned Licenses: {summary.UnassignedLicenses:N0}");
            LogInformation($"Utilization Rate: {(summary.TotalLicenses > 0 ? Math.Round((double)summary.AssignedLicenses / summary.TotalLicenses * 100, 1) : 0):F1}%");
            LogInformation("");
            LogInformation("Output Files:");
            foreach (var file in summary.OutputFiles)
            {
                LogInformation($"  - {file}");
            }
            LogInformation("============================================");
        }

        // Write methods for different file types
        private async Task WriteProductLicensesAsync(IEnumerable<ProductLicense> licenses, string filePath)
        {
            var csv = "SkuId,SkuPartNumber,ProductName,ConsumedUnits,EnabledUnits,AvailableUnits,CapabilityStatus" + Environment.NewLine;
            
            foreach (var license in licenses)
            {
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
                
                csv += string.Join(",", values) + Environment.NewLine;
            }
            
            await File.WriteAllTextAsync(filePath, csv);
        }

        private async Task WriteUserLicensesAsync(IEnumerable<UserLicense> licenses, string filePath)
        {
            var csv = "UserId,UserPrincipalName,DisplayName,Department,JobTitle,AccountEnabled,Licenses,TotalLicenseCost" + Environment.NewLine;
            
            foreach (var license in licenses)
            {
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
                
                csv += string.Join(",", values) + Environment.NewLine;
            }
            
            await File.WriteAllTextAsync(filePath, csv);
        }

        private async Task WriteLicenseSummaryAsync(IEnumerable<LicenseSummary> summaries, string filePath)
        {
            var csv = "ProductName,SkuPartNumber,TotalLicenses,AssignedLicenses,AvailableLicenses,UtilizationPercentage" + Environment.NewLine;
            
            foreach (var summary in summaries)
            {
                var values = new[]
                {
                    EscapeCsvValue(summary.ProductName),
                    EscapeCsvValue(summary.SkuPartNumber),
                    summary.TotalLicenses.ToString(),
                    summary.AssignedLicenses.ToString(),
                    summary.AvailableLicenses.ToString(),
                    summary.UtilizationPercentage.ToString("F1")
                };
                
                csv += string.Join(",", values) + Environment.NewLine;
            }
            
            await File.WriteAllTextAsync(filePath, csv);
        }

        private async Task WriteLicenseCompatibilityAsync(IEnumerable<LicenseCompatibility> compatibilities, string filePath)
        {
            var csv = "License1,License2,ConflictingServicePlans,CompatibilityStatus,RecommendedAction" + Environment.NewLine;
            
            foreach (var compatibility in compatibilities)
            {
                var values = new[]
                {
                    EscapeCsvValue(compatibility.License1),
                    EscapeCsvValue(compatibility.License2),
                    EscapeCsvValue(string.Join("; ", compatibility.ConflictingServicePlans)),
                    EscapeCsvValue(compatibility.CompatibilityStatus),
                    EscapeCsvValue(compatibility.RecommendedAction)
                };
                
                csv += string.Join(",", values) + Environment.NewLine;
            }
            
            await File.WriteAllTextAsync(filePath, csv);
        }

        private async Task WriteUserLicenseAssignmentsAsync(IEnumerable<UserLicenseAssignment> assignments, string filePath)
        {
            var csv = "UserId,UserPrincipalName,DisplayName,SkuId,DisabledPlans,AssignmentSource,LastUpdated" + Environment.NewLine;
            
            foreach (var assignment in assignments)
            {
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
                
                csv += string.Join(",", values) + Environment.NewLine;
            }
            
            await File.WriteAllTextAsync(filePath, csv);
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
    public class ProductLicensesResult
    {
        public List<ProductLicense> Licenses { get; set; } = new List<ProductLicense>();
        public List<UserLicense> UserLicenses { get; set; } = new List<UserLicense>();
        public List<LicenseCompatibility> CompatibilityAnalysis { get; set; } = new List<LicenseCompatibility>();
        public ProductLicensesSummary Summary { get; set; }
    }

    public class ProductLicense
    {
        public string SkuId { get; set; }
        public string SkuPartNumber { get; set; }
        public string ProductName { get; set; }
        public int ConsumedUnits { get; set; }
        public PrepaidUnits PrepaidUnits { get; set; } = new PrepaidUnits();
        public int AvailableUnits { get; set; }
        public List<ServicePlan> ServicePlans { get; set; } = new List<ServicePlan>();
        public string CapabilityStatus { get; set; }
    }

    public class PrepaidUnits
    {
        public int Enabled { get; set; }
        public int Suspended { get; set; }
        public int Warning { get; set; }
    }

    public class ServicePlan
    {
        public string ServicePlanId { get; set; }
        public string ServicePlanName { get; set; }
        public string ProvisioningStatus { get; set; }
        public string AppliesTo { get; set; }
    }

    public class UserLicense
    {
        public string UserId { get; set; }
        public string UserPrincipalName { get; set; }
        public string DisplayName { get; set; }
        public string Department { get; set; }
        public string JobTitle { get; set; }
        public bool AccountEnabled { get; set; }
        public List<string> Licenses { get; set; } = new List<string>();
        public decimal TotalLicenseCost { get; set; }
    }

    public class LicenseSummary
    {
        public string ProductName { get; set; }
        public string SkuPartNumber { get; set; }
        public int TotalLicenses { get; set; }
        public int AssignedLicenses { get; set; }
        public int AvailableLicenses { get; set; }
        public double UtilizationPercentage { get; set; }
    }

    public class LicenseCompatibility
    {
        public string License1 { get; set; }
        public string License2 { get; set; }
        public List<string> ConflictingServicePlans { get; set; } = new List<string>();
        public string CompatibilityStatus { get; set; }
        public string RecommendedAction { get; set; }
    }

    public class UserLicenseAssignment
    {
        public string UserId { get; set; }
        public string UserPrincipalName { get; set; }
        public string DisplayName { get; set; }
        public string SkuId { get; set; }
        public List<string> DisabledPlans { get; set; } = new List<string>();
        public string AssignmentSource { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    public class ProductLicensesSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public int ProcessedUsers { get; set; }
        public int TotalLicenses { get; set; }
        public int AssignedLicenses { get; set; }
        public int UnassignedLicenses { get; set; }
        public List<string> OutputFiles { get; set; } = new List<string>();
    }
}