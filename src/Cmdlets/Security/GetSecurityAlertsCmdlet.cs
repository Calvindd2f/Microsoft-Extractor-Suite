using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Graph;

namespace Microsoft.ExtractorSuite.Cmdlets.Security
{
    /// <summary>
    /// Cmdlet to retrieve security alerts from Microsoft Graph Security API
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "SecurityAlerts")]
    [OutputType(typeof(SecurityAlertsResult))]
    public class GetSecurityAlertsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
        public string OutputDir { get; set; } = "Output\\SecurityAlerts";

        [Parameter(
            HelpMessage = "File encoding for output files")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(
            HelpMessage = "Specific alert ID to retrieve")]
        public string AlertId { get; set; }

        [Parameter(
            HelpMessage = "Number of days to look back for alerts")]
        public int DaysBack { get; set; } = 90;

        [Parameter(
            HelpMessage = "Custom filter string to apply to the alert retrieval")]
        public string Filter { get; set; }

        [Parameter(
            HelpMessage = "Use version 2 of the Security API")]
        public SwitchParameter UseV2Api { get; set; }

        private readonly GraphApiClient _graphClient;
        private readonly string[] RequiredScopes = { "SecurityEvents.Read.All" };

        public GetSecurityAlertsCmdlet()
        {
            _graphClient = new GraphApiClient();
        }

        protected override async Task ProcessRecordAsync()
        {
            LogInformation("=== Starting Security Alerts Collection ===");
            
            // Check for authentication and scopes
            if (!await _graphClient.IsConnectedAsync())
            {
                LogError("Not connected to Microsoft Graph. Please run Connect-M365 first.");
                return;
            }

            var authInfo = await _graphClient.GetAuthenticationInfoAsync();
            var missingScopes = RequiredScopes.Except(authInfo.Scopes).ToList();
            if (missingScopes.Count > 0)
            {
                LogWarning($"Missing required scopes: {string.Join(", ", missingScopes)}");
            }

            var outputDirectory = GetOutputDirectory();
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmm");

            var summary = new SecurityAlertsSummary
            {
                StartTime = DateTime.Now,
                TotalAlerts = 0,
                SeverityBreakdown = new Dictionary<string, int>(),
                StatusBreakdown = new Dictionary<string, int>(),
                VendorBreakdown = new Dictionary<string, int>(),
                OutputFile = string.Empty
            };

            try
            {
                // Determine which API version to use
                var useV2 = UseV2Api || (authInfo.AuthType == "Application");
                var apiVersion = useV2 ? "v2" : "v1";
                
                LogInformation($"Using Security API {apiVersion} based on authentication type: {authInfo.AuthType}");

                var alerts = await RetrieveSecurityAlertsAsync(useV2, summary);

                if (alerts.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-SecurityAlerts.csv");
                    await WriteSecurityAlertsAsync(alerts, fileName);
                    summary.OutputFile = fileName;
                    
                    LogInformation($"Security alerts written to: {fileName}");
                }
                else
                {
                    LogInformation("No security alerts found matching the specified criteria.");
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
                LogSummary(summary);

                var result = new SecurityAlertsResult
                {
                    Alerts = alerts,
                    Summary = summary
                };

                WriteObject(result);
            }
            catch (Exception ex)
            {
                LogError($"An error occurred during security alerts collection: {ex.Message}");
                throw;
            }
        }

        private async Task<List<SecurityAlert>> RetrieveSecurityAlertsAsync(bool useV2, SecurityAlertsSummary summary)
        {
            var alerts = new List<SecurityAlert>();

            try
            {
                var parameters = BuildSearchParameters();
                
                if (!string.IsNullOrEmpty(AlertId))
                {
                    LogInformation($"Retrieving specific alert: {AlertId}");
                    
                    var specificAlert = useV2 
                        ? await _graphClient.GetSecurityAlertV2Async(AlertId)
                        : await _graphClient.GetSecurityAlertV1Async(AlertId);
                    
                    if (specificAlert != null)
                    {
                        alerts.Add(ProcessSecurityAlert(specificAlert, useV2, summary));
                    }
                }
                else
                {
                    LogInformation("Retrieving security alerts...");
                    
                    var allAlerts = useV2
                        ? await _graphClient.GetSecurityAlertsV2Async(parameters)
                        : await _graphClient.GetSecurityAlertsV1Async(parameters);
                    
                    foreach (var alert in allAlerts)
                    {
                        alerts.Add(ProcessSecurityAlert(alert, useV2, summary));
                    }
                }
            }
            catch (Exception ex)
            {
                LogError($"Failed to retrieve security alerts: {ex.Message}");
                throw;
            }

            return alerts;
        }

        private Dictionary<string, object> BuildSearchParameters()
        {
            var parameters = new Dictionary<string, object>();

            if (DaysBack > 0 && string.IsNullOrEmpty(AlertId))
            {
                var startDate = DateTime.UtcNow.AddDays(-DaysBack);
                var timeFilter = $"createdDateTime ge {startDate:yyyy-MM-ddTHH:mm:ss.fffZ}";
                
                if (!string.IsNullOrEmpty(Filter))
                {
                    parameters["Filter"] = $"({Filter}) and ({timeFilter})";
                    LogInformation($"Using combined filter: {parameters["Filter"]}");
                }
                else
                {
                    parameters["Filter"] = timeFilter;
                    LogInformation($"Filtering alerts from {startDate:yyyy-MM-dd}");
                }
            }
            else if (!string.IsNullOrEmpty(Filter))
            {
                parameters["Filter"] = Filter;
                LogInformation($"Using custom filter: {Filter}");
            }

            return parameters;
        }

        private SecurityAlert ProcessSecurityAlert(dynamic alert, bool isV2, SecurityAlertsSummary summary)
        {
            summary.TotalAlerts++;
            
            var securityAlert = new SecurityAlert
            {
                Id = alert.Id?.ToString(),
                Title = alert.Title?.ToString(),
                Category = alert.Category?.ToString(),
                Severity = alert.Severity?.ToString(),
                Status = alert.Status?.ToString(),
                CreatedDateTime = alert.CreatedDateTime,
                EventDateTime = alert.EventDateTime,
                LastModifiedDateTime = alert.LastModifiedDateTime,
                AssignedTo = alert.AssignedTo?.ToString(),
                Description = alert.Description?.ToString(),
                DetectionSource = alert.DetectionSource?.ToString(),
                AzureTenantId = alert.AzureTenantId?.ToString(),
                AzureSubscriptionId = alert.AzureSubscriptionId?.ToString(),
                Confidence = alert.Confidence,
                ActivityGroupName = alert.ActivityGroupName?.ToString(),
                ClosedDateTime = alert.ClosedDateTime,
                Feedback = alert.Feedback?.ToString(),
                LastEventDateTime = alert.LastEventDateTime
            };

            // Update severity breakdown
            var severity = securityAlert.Severity ?? "Unknown";
            if (summary.SeverityBreakdown.ContainsKey(severity))
                summary.SeverityBreakdown[severity]++;
            else
                summary.SeverityBreakdown[severity] = 1;

            // Update status breakdown
            var status = securityAlert.Status ?? "Unknown";
            if (summary.StatusBreakdown.ContainsKey(status))
                summary.StatusBreakdown[status]++;
            else
                summary.StatusBreakdown[status] = 1;

            // Process affected users
            if (alert.UserStates != null)
            {
                var userDetails = new List<string>();
                foreach (var userState in alert.UserStates)
                {
                    var userInfo = userState.UserPrincipalName?.ToString() ?? userState.Name?.ToString() ?? "Unknown";
                    var logonIP = userState.LogonIP?.ToString() ?? "null";
                    userDetails.Add($"{userInfo}/{logonIP}");
                }
                securityAlert.AffectedUser = string.Join("; ", userDetails);
            }

            // Process affected hosts
            if (alert.HostStates != null)
            {
                var hostDetails = new List<string>();
                foreach (var hostState in alert.HostStates)
                {
                    var hostName = hostState.NetBiosName?.ToString() ?? 
                                  hostState.PrivateHostName?.ToString() ?? "Unknown";
                    var privateIP = hostState.PrivateIpAddress?.ToString() ?? "null";
                    hostDetails.Add($"{hostName}/{privateIP}");
                }
                securityAlert.AffectedHost = string.Join("; ", hostDetails);
            }

            // Process source materials
            if (alert.SourceMaterials != null)
            {
                var sourceMaterials = new List<string>();
                foreach (var material in alert.SourceMaterials)
                {
                    sourceMaterials.Add(material.ToString());
                }
                securityAlert.SourceURL = string.Join("; ", sourceMaterials);
            }

            // Process cloud app states
            if (alert.CloudAppStates != null)
            {
                var cloudApps = new List<string>();
                foreach (var appState in alert.CloudAppStates)
                {
                    var name = appState.Name?.ToString() ?? "Unknown";
                    var instance = appState.InstanceName?.ToString() ?? "Unknown";
                    cloudApps.Add($"{name}: {instance}");
                }
                securityAlert.CloudAppStates = string.Join("; ", cloudApps);
            }

            // Process comments
            if (alert.Comments != null)
            {
                var comments = new List<string>();
                foreach (var comment in alert.Comments)
                {
                    var commentText = comment.Comment?.ToString() ?? "";
                    var createdBy = comment.CreatedBy?.User?.DisplayName?.ToString();
                    
                    if (!string.IsNullOrEmpty(createdBy))
                        comments.Add($"{commentText} - {createdBy}");
                    else
                        comments.Add(commentText);
                }
                securityAlert.Comments = string.Join("; ", comments);
            }

            // Process tags
            if (alert.Tags != null)
            {
                securityAlert.Tags = string.Join(", ", alert.Tags);
            }

            // Process vendor information
            if (alert.VendorInformation != null)
            {
                securityAlert.Vendor = alert.VendorInformation.Vendor?.ToString();
                securityAlert.Provider = alert.VendorInformation.Provider?.ToString();
                securityAlert.SubProvider = alert.VendorInformation.SubProvider?.ToString();
                securityAlert.ProviderVersion = alert.VendorInformation.ProviderVersion?.ToString();

                // Update vendor breakdown
                var vendor = securityAlert.Vendor ?? "Unknown";
                if (summary.VendorBreakdown.ContainsKey(vendor))
                    summary.VendorBreakdown[vendor]++;
                else
                    summary.VendorBreakdown[vendor] = 1;
            }

            // Process incident IDs
            if (alert.IncidentIds != null)
            {
                securityAlert.IncidentIds = string.Join(", ", alert.IncidentIds);
            }

            return securityAlert;
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

        private void LogSummary(SecurityAlertsSummary summary)
        {
            LogInformation("");
            LogInformation("=== Security Alert Analysis Results ===");
            LogInformation($"Total Alerts: {summary.TotalAlerts}");
            
            if (summary.SeverityBreakdown.Count > 0)
            {
                LogInformation("");
                LogInformation("Severity Distribution:");
                foreach (var kvp in summary.SeverityBreakdown.OrderByDescending(x => x.Value))
                {
                    LogInformation($"  - {kvp.Key}: {kvp.Value}");
                }
            }

            if (summary.StatusBreakdown.Count > 0)
            {
                LogInformation("");
                LogInformation("Status Distribution:");
                foreach (var kvp in summary.StatusBreakdown.OrderByDescending(x => x.Value))
                {
                    LogInformation($"  - {kvp.Key}: {kvp.Value}");
                }
            }

            if (summary.VendorBreakdown.Count > 0)
            {
                LogInformation("");
                LogInformation("Vendor Distribution:");
                foreach (var kvp in summary.VendorBreakdown.OrderByDescending(x => x.Value))
                {
                    LogInformation($"  - {kvp.Key}: {kvp.Value}");
                }
            }

            if (!string.IsNullOrEmpty(summary.OutputFile))
            {
                LogInformation("");
                LogInformation($"Output File: {summary.OutputFile}");
            }

            LogInformation("");
            LogInformation($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
            LogInformation("==========================================");
        }

        private async Task WriteSecurityAlertsAsync(IEnumerable<SecurityAlert> alerts, string filePath)
        {
            var csv = "Id,Title,Category,Severity,Status,CreatedDateTime,EventDateTime,LastModifiedDateTime,AssignedTo,Description,DetectionSource,AffectedUser,AffectedHost,AzureTenantId,AzureSubscriptionId,Confidence,ActivityGroupName,ClosedDateTime,Feedback,LastEventDateTime,SourceURL,CloudAppStates,Comments,Tags,Vendor,Provider,SubProvider,ProviderVersion,IncidentIds" + Environment.NewLine;
            
            foreach (var alert in alerts)
            {
                var values = new[]
                {
                    EscapeCsvValue(alert.Id),
                    EscapeCsvValue(alert.Title),
                    EscapeCsvValue(alert.Category),
                    EscapeCsvValue(alert.Severity),
                    EscapeCsvValue(alert.Status),
                    alert.CreatedDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    alert.EventDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    alert.LastModifiedDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(alert.AssignedTo),
                    EscapeCsvValue(alert.Description),
                    EscapeCsvValue(alert.DetectionSource),
                    EscapeCsvValue(alert.AffectedUser),
                    EscapeCsvValue(alert.AffectedHost),
                    EscapeCsvValue(alert.AzureTenantId),
                    EscapeCsvValue(alert.AzureSubscriptionId),
                    alert.Confidence?.ToString() ?? "",
                    EscapeCsvValue(alert.ActivityGroupName),
                    alert.ClosedDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(alert.Feedback),
                    alert.LastEventDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(alert.SourceURL),
                    EscapeCsvValue(alert.CloudAppStates),
                    EscapeCsvValue(alert.Comments),
                    EscapeCsvValue(alert.Tags),
                    EscapeCsvValue(alert.Vendor),
                    EscapeCsvValue(alert.Provider),
                    EscapeCsvValue(alert.SubProvider),
                    EscapeCsvValue(alert.ProviderVersion),
                    EscapeCsvValue(alert.IncidentIds)
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
    public class SecurityAlertsResult
    {
        public List<SecurityAlert> Alerts { get; set; } = new List<SecurityAlert>();
        public SecurityAlertsSummary Summary { get; set; }
    }

    public class SecurityAlert
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public string Category { get; set; }
        public string Severity { get; set; }
        public string Status { get; set; }
        public DateTime? CreatedDateTime { get; set; }
        public DateTime? EventDateTime { get; set; }
        public DateTime? LastModifiedDateTime { get; set; }
        public string AssignedTo { get; set; }
        public string Description { get; set; }
        public string DetectionSource { get; set; }
        public string AffectedUser { get; set; }
        public string AffectedHost { get; set; }
        public string AzureTenantId { get; set; }
        public string AzureSubscriptionId { get; set; }
        public int? Confidence { get; set; }
        public string ActivityGroupName { get; set; }
        public DateTime? ClosedDateTime { get; set; }
        public string Feedback { get; set; }
        public DateTime? LastEventDateTime { get; set; }
        public string SourceURL { get; set; }
        public string CloudAppStates { get; set; }
        public string Comments { get; set; }
        public string Tags { get; set; }
        public string Vendor { get; set; }
        public string Provider { get; set; }
        public string SubProvider { get; set; }
        public string ProviderVersion { get; set; }
        public string IncidentIds { get; set; }
    }

    public class SecurityAlertsSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public int TotalAlerts { get; set; }
        public Dictionary<string, int> SeverityBreakdown { get; set; } = new Dictionary<string, int>();
        public Dictionary<string, int> StatusBreakdown { get; set; } = new Dictionary<string, int>();
        public Dictionary<string, int> VendorBreakdown { get; set; } = new Dictionary<string, int>();
        public string OutputFile { get; set; }
    }
}