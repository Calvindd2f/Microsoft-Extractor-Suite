using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Graph;
using Microsoft.Graph;
using Microsoft.Graph.Models;

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
        public string? AlertId { get; set; }

        [Parameter(
            HelpMessage = "Number of days to look back for alerts")]
        public int DaysBack { get; set; } = 90;

        [Parameter(
            HelpMessage = "Custom filter string to apply to the alert retrieval")]
        public string? Filter { get; set; }

        [Parameter(
            HelpMessage = "Use version 2 of the Security API")]
        public SwitchParameter UseV2Api { get; set; }

        private readonly string[] RequiredScopes = { "SecurityEvents.Read.All" };

        protected override async Task ProcessRecordAsync()
        {
            WriteVerbose("=== Starting Security Alerts Collection ===");

            // Check for authentication
            if (!RequireGraphConnection())
            {
                return;
            }

            var authInfo = await AuthManager.GetAuthenticationInfoAsync();
            WriteVerbose($"Connected to tenant: {authInfo.TenantId}");

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
                // Use Graph client for Security API
                var graphClient = AuthManager.GraphClient ?? throw new InvalidOperationException("Graph client not initialized");
                
                var alerts = await RetrieveSecurityAlertsAsync(graphClient, summary);

                if (alerts.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-SecurityAlerts.csv");
                    await WriteSecurityAlertsAsync(alerts, fileName);
                    summary.OutputFile = fileName;

                    WriteVerbose($"Security alerts written to: {fileName}");
                }
                else
                {
                    WriteVerbose("No security alerts found matching the specified criteria.");
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
                WriteErrorWithTimestamp($"An error occurred during security alerts collection: {ex.Message}");
                throw;
            }
        }

        private async Task<List<SecurityAlert>> RetrieveSecurityAlertsAsync(GraphServiceClient graphClient, SecurityAlertsSummary summary)
        {
            var alerts = new List<SecurityAlert>();

            try
            {
                WriteVerbose("Retrieving security alerts from Microsoft Graph...");

                // Get security alerts using Graph SDK
                var alertsResponse = await graphClient.Security.Alerts_v2.GetAsync(requestConfiguration =>
                {
                    var filter = BuildODataFilter();
                    if (!string.IsNullOrEmpty(filter))
                    {
                        requestConfiguration.QueryParameters.Filter = filter;
                    }
                    
                    requestConfiguration.QueryParameters.Top = 1000; // Max results per page
                    requestConfiguration.QueryParameters.Orderby = new[] { "createdDateTime desc" };
                });

                if (alertsResponse?.Value != null)
                {
                    foreach (var alert in alertsResponse.Value)
                    {
                        alerts.Add(ProcessSecurityAlert(alert, summary));
                    }
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Failed to retrieve security alerts: {ex.Message}");
                throw;
            }

            return alerts;
        }

        private string BuildODataFilter()
        {
            var filters = new List<string>();

            if (DaysBack > 0 && string.IsNullOrEmpty(AlertId))
            {
                var startDate = DateTime.UtcNow.AddDays(-DaysBack);
                var timeFilter = $"createdDateTime ge {startDate:yyyy-MM-ddTHH:mm:ss.fffZ}";
                filters.Add(timeFilter);
                WriteVerbose($"Filtering alerts from {startDate:yyyy-MM-dd}");
            }

            if (!string.IsNullOrEmpty(AlertId))
            {
                filters.Add($"id eq '{AlertId}'");
            }

            if (!string.IsNullOrEmpty(Filter))
            {
                filters.Add($"({Filter})");
                WriteVerbose($"Using custom filter: {Filter}");
            }

            return filters.Any() ? string.Join(" and ", filters) : string.Empty;
        }

        private SecurityAlert ProcessSecurityAlert(Microsoft.Graph.Models.Security.Alert alert, SecurityAlertsSummary summary)
        {
            summary.TotalAlerts++;

            var securityAlert = new SecurityAlert
            {
                Id = alert.Id ?? string.Empty,
                Title = alert.Title ?? string.Empty,
                Category = alert.Category ?? string.Empty,
                Severity = alert.Severity?.ToString(),
                Status = alert.Status?.ToString(),
                CreatedDateTime = alert.CreatedDateTime?.DateTime,
                LastModifiedDateTime = null, // LastModifiedDateTime not available in Alert model
                AssignedTo = alert.AssignedTo ?? string.Empty,
                Description = alert.Description ?? string.Empty,
                Confidence = null, // confidence not directly available in Alert model
                AzureTenantId = alert.TenantId ?? string.Empty,
                Feedback = alert.Status?.ToString() ?? string.Empty
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

            // Simplified processing for affected entities
            securityAlert.AffectedUser = "N/A"; // Simplified - would need to process Evidence or ActorDisplayName
            securityAlert.AffectedHost = "N/A"; // Simplified - would need to process Evidence
            securityAlert.SourceURL = alert.IncidentWebUrl?.ToString() ?? "N/A";

            return securityAlert;
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

        private void LogSummary(SecurityAlertsSummary summary)
        {
            WriteVerbose("");
            WriteVerbose("=== Security Alert Analysis Results ===");
            WriteVerbose($"Total Alerts: {summary.TotalAlerts}");

            if (summary.SeverityBreakdown.Count > 0)
            {
                WriteVerbose("");
                WriteVerbose("Severity Distribution:");
                foreach (var kvp in summary.SeverityBreakdown.OrderByDescending(x => x.Value))
                {
                    WriteVerbose($"  - {kvp.Key}: {kvp.Value}");
                }
            }

            if (summary.StatusBreakdown.Count > 0)
            {
                WriteVerbose("");
                WriteVerbose("Status Distribution:");
                foreach (var kvp in summary.StatusBreakdown.OrderByDescending(x => x.Value))
                {
                    WriteVerbose($"  - {kvp.Key}: {kvp.Value}");
                }
            }

            if (summary.VendorBreakdown.Count > 0)
            {
                WriteVerbose("");
                WriteVerbose("Vendor Distribution:");
                foreach (var kvp in summary.VendorBreakdown.OrderByDescending(x => x.Value))
                {
                    WriteVerbose($"  - {kvp.Key}: {kvp.Value}");
                }
            }

            if (!string.IsNullOrEmpty(summary.OutputFile))
            {
                WriteVerbose("");
                WriteVerbose($"Output File: {summary.OutputFile}");
            }

            WriteVerbose("");
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
            WriteVerbose("==========================================");
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

    // Supporting classes
    public class SecurityAlertsResult
    {
        public List<SecurityAlert> Alerts { get; set; } = new List<SecurityAlert>();
        public SecurityAlertsSummary Summary { get; set; } = new SecurityAlertsSummary();
    }

    public class SecurityAlert
    {
        public string Id { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string? Severity { get; set; }
        public string? Status { get; set; }
        public DateTime? CreatedDateTime { get; set; }
        public DateTime? EventDateTime { get; set; }
        public DateTime? LastModifiedDateTime { get; set; }
        public string? AssignedTo { get; set; }
        public string? Description { get; set; }
        public string? DetectionSource { get; set; }
        public string? AffectedUser { get; set; }
        public string? AffectedHost { get; set; }
        public string? AzureTenantId { get; set; }
        public string? AzureSubscriptionId { get; set; }
        public int? Confidence { get; set; }
        public string? ActivityGroupName { get; set; }
        public DateTime? ClosedDateTime { get; set; }
        public string? Feedback { get; set; }
        public DateTime? LastEventDateTime { get; set; }
        public string? SourceURL { get; set; }
        public string? CloudAppStates { get; set; }
        public string? Comments { get; set; }
        public string? Tags { get; set; }
        public string? Vendor { get; set; }
        public string? Provider { get; set; }
        public string? SubProvider { get; set; }
        public string? ProviderVersion { get; set; }
        public string? IncidentIds { get; set; }
    }

    public class SecurityAlertsSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public int TotalAlerts { get; set; }
        public Dictionary<string, int> SeverityBreakdown { get; set; } = new Dictionary<string, int>();
        public Dictionary<string, int> StatusBreakdown { get; set; } = new Dictionary<string, int>();
        public Dictionary<string, int> VendorBreakdown { get; set; } = new Dictionary<string, int>();
        public string OutputFile { get; set; } = string.Empty;
    }
}
