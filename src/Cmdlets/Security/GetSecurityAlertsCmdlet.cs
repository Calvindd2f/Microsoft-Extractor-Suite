namespace Microsoft.ExtractorSuite.Cmdlets.Security
{
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
#pragma warning disable SA1600
        public string OutputDir { get; set; } = "Output\\SecurityAlerts";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "File encoding for output files")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Specific alert ID to retrieve")]
#pragma warning disable SA1600
        public string? AlertId { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Number of days to look back for alerts")]
#pragma warning disable SA1600
        public int DaysBack { get; set; } = 90;
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Custom filter string to apply to the alert retrieval")]
#pragma warning disable SA1600
        public string? Filter { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Use version 2 of the Security API")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1201
        public SwitchParameter UseV2Api { get; set; }
        private readonly string[] RequiredScopes = { "SecurityEvents.Read.All" };
#pragma warning restore SA1201

#pragma warning disable SA1600
        protected override async Task ProcessRecordAsync()
#pragma warning restore SA1600
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting Security Alerts Collection ===");
#pragma warning restore SA1101

            // Check for authentication
#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                return;
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            var authInfo = await AuthManager.GetAuthenticationInfoAsync();
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Connected to tenant: {authInfo.TenantId}");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var outputDirectory = GetOutputDirectory();
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                var graphClient = AuthManager.GraphClient ?? throw new InvalidOperationException("Graph client not initialized");
#pragma warning restore SA1101

#pragma warning disable SA1101
                var alerts = await RetrieveSecurityAlertsAsync(graphClient, summary);
#pragma warning restore SA1101

                if (alerts.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-SecurityAlerts.csv");
#pragma warning disable SA1101
                    await WriteSecurityAlertsAsync(alerts, fileName);
#pragma warning restore SA1101
                    summary.OutputFile = fileName;

#pragma warning disable SA1101
                    WriteVerbose($"Security alerts written to: {fileName}");
#pragma warning restore SA1101
                }
                else
                {
#pragma warning disable SA1101
                    WriteVerbose("No security alerts found matching the specified criteria.");
#pragma warning restore SA1101
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
#pragma warning disable SA1101
                LogSummary(summary);
#pragma warning restore SA1101

                var result = new SecurityAlertsResult
                {
                    Alerts = alerts,
                    Summary = summary
                };

#pragma warning disable SA1101
                WriteObject(result);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during security alerts collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task<List<SecurityAlert>> RetrieveSecurityAlertsAsync(GraphServiceClient graphClient, SecurityAlertsSummary summary)
        {
            var alerts = new List<SecurityAlert>();

            try
            {
#pragma warning disable SA1101
                WriteVerbose("Retrieving security alerts from Microsoft Graph...");
#pragma warning restore SA1101

                // Get security alerts using Graph SDK
                var alertsResponse = await graphClient.Security.Alerts_v2.GetAsync(requestConfiguration =>
                {
#pragma warning disable SA1101
                    var filter = BuildODataFilter();
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                        alerts.Add(ProcessSecurityAlert(alert, summary));
#pragma warning restore SA1101
                    }
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to retrieve security alerts: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }

            return alerts;
        }

        private string BuildODataFilter()
        {
            var filters = new List<string>();

#pragma warning disable SA1101
            if (DaysBack > 0 && string.IsNullOrEmpty(AlertId))
            {
#pragma warning disable SA1101
                var startDate = DateTime.UtcNow.AddDays(-DaysBack);
#pragma warning restore SA1101
                var timeFilter = $"createdDateTime ge {startDate:yyyy-MM-ddTHH:mm:ss.fffZ}";
                filters.Add(timeFilter);
#pragma warning disable SA1101
                WriteVerbose($"Filtering alerts from {startDate:yyyy-MM-dd}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(AlertId))
            {
#pragma warning disable SA1101
                filters.Add($"id eq '{AlertId}'");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(Filter))
            {
#pragma warning disable SA1101
                filters.Add($"({Filter})");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"Using custom filter: {Filter}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

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

        private void LogSummary(SecurityAlertsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("=== Security Alert Analysis Results ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Total Alerts: {summary.TotalAlerts}");
#pragma warning restore SA1101

            if (summary.SeverityBreakdown.Count > 0)
            {
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose("Severity Distribution:");
#pragma warning restore SA1101
                foreach (var kvp in summary.SeverityBreakdown.OrderByDescending(x => x.Value))
                {
#pragma warning disable SA1101
                    WriteVerbose($"  - {kvp.Key}: {kvp.Value}");
#pragma warning restore SA1101
                }
            }

            if (summary.StatusBreakdown.Count > 0)
            {
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose("Status Distribution:");
#pragma warning restore SA1101
                foreach (var kvp in summary.StatusBreakdown.OrderByDescending(x => x.Value))
                {
#pragma warning disable SA1101
                    WriteVerbose($"  - {kvp.Key}: {kvp.Value}");
#pragma warning restore SA1101
                }
            }

            if (summary.VendorBreakdown.Count > 0)
            {
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose("Vendor Distribution:");
#pragma warning restore SA1101
                foreach (var kvp in summary.VendorBreakdown.OrderByDescending(x => x.Value))
                {
#pragma warning disable SA1101
                    WriteVerbose($"  - {kvp.Key}: {kvp.Value}");
#pragma warning restore SA1101
                }
            }

            if (!string.IsNullOrEmpty(summary.OutputFile))
            {
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"Output File: {summary.OutputFile}");
#pragma warning restore SA1101
            }

#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("==========================================");
#pragma warning restore SA1101
        }

        private async Task WriteSecurityAlertsAsync(IEnumerable<SecurityAlert> alerts, string filePath)
        {
            var csv = "Id,Title,Category,Severity,Status,CreatedDateTime,EventDateTime,LastModifiedDateTime,AssignedTo,Description,DetectionSource,AffectedUser,AffectedHost,AzureTenantId,AzureSubscriptionId,Confidence,ActivityGroupName,ClosedDateTime,Feedback,LastEventDateTime,SourceURL,CloudAppStates,Comments,Tags,Vendor,Provider,SubProvider,ProviderVersion,IncidentIds" + Environment.NewLine;

            foreach (var alert in alerts)
            {
#pragma warning disable SA1101
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

    // Supporting classes
#pragma warning disable SA1600
    public class SecurityAlertsResult
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public List<SecurityAlert> Alerts { get; set; } = new List<SecurityAlert>();
#pragma warning restore SA1600
#pragma warning disable SA1600
        public SecurityAlertsSummary Summary { get; set; } = new SecurityAlertsSummary();
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class SecurityAlert
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string Id { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Title { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Category { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Severity { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Status { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? CreatedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? EventDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? LastModifiedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? AssignedTo { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Description { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? DetectionSource { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? AffectedUser { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? AffectedHost { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? AzureTenantId { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? AzureSubscriptionId { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public int? Confidence { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? ActivityGroupName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? ClosedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Feedback { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? LastEventDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? SourceURL { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? CloudAppStates { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Comments { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Tags { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Vendor { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Provider { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? SubProvider { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? ProviderVersion { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? IncidentIds { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class SecurityAlertsSummary
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalAlerts { get; set; }
        public Dictionary<string, int> SeverityBreakdown { get; set; } = new Dictionary<string, int>();
#pragma warning restore SA1600
#pragma warning disable SA1600
        public Dictionary<string, int> StatusBreakdown { get; set; } = new Dictionary<string, int>();
#pragma warning restore SA1600
#pragma warning disable SA1600
        public Dictionary<string, int> VendorBreakdown { get; set; } = new Dictionary<string, int>();
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string OutputFile { get; set; } = string.Empty;
#pragma warning restore SA1600
    }
}
