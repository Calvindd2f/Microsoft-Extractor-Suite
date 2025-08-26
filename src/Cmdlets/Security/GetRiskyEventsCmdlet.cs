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


    /// <summary>
    /// Cmdlet to retrieve risky users and risk detections from Entra ID Identity Protection
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "RiskyEvents")]
    [OutputType(typeof(RiskyEventsResult))]
    public class GetRiskyEventsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to retrieve risky events for. If not specified, retrieves for all risky users")]
        public string[] UserIds { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
        public string OutputDir { get; set; } = "Output\\RiskyEvents";

        [Parameter(
            HelpMessage = "File encoding for output files")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(
            HelpMessage = "Operation mode: RiskyUsers, RiskyDetections, or Both")]
        [ValidateSet("RiskyUsers", "RiskyDetections", "Both")]
        public string Mode { get; set; } = "Both";

        [Parameter(
            HelpMessage = "Include only high-risk events")]
        #pragma warning disable SA1309
        public SwitchParameter HighRiskOnly { get; set; }
#pragma warning disable SA1201
        private GraphApiClient? _graphClient;
#pragma warning restore SA1201
        private readonly string[] RequiredScopes = {"IdentityRiskEvent.Read.All", "IdentityRiskyUser.Read.All" };

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            if (AuthManager.GraphClient != null)
            {
                _graphClient = new GraphApiClient(AuthManager.GraphClient);
            }
        }

        protected override async Task ProcessRecordAsync()
        {
            WriteVerbose("=== Starting Risky Events Collection ===");

            // Check for authentication and scopes
            if (_graphClient == null || !await _graphClient.IsConnectedAsync())
            {
                WriteErrorWithTimestamp("Not connected to Microsoft Graph. Please run Connect-M365 first.");
                return;
            }

            var authInfo = await _graphClient!.GetAuthenticationInfoAsync();
            // Note: Scope checking is not available through Graph API directly
            // Continuing without scope validation
            WriteVerbose("Proceeding with risky events collection...");

            var outputDirectory = GetOutputDirectory();
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmm");

            var summary = new RiskyEventsSummary
            {
                StartTime = DateTime.Now,
                TotalRiskyUsers = 0,
                TotalRiskDetections = 0,
                RiskLevelBreakdown = new Dictionary<string, int>(),
                RiskStateBreakdown = new Dictionary<string, int>(),
                OutputFiles = new List<string>()
            };

            try
            {
                switch (Mode.ToUpperInvariant())
                {
                    case "RISKYUSERS":
                        await ProcessRiskyUsersAsync(outputDirectory, timestamp, summary);
                        break;
                    case "RISKYDETECTIONS":
                        await ProcessRiskyDetectionsAsync(outputDirectory, timestamp, summary);
                        break;
                    case "BOTH":
                        await ProcessRiskyUsersAsync(outputDirectory, timestamp, summary);
                        await ProcessRiskyDetectionsAsync(outputDirectory, timestamp, summary);
                        break;
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
                LogSummary(summary);

                var result = new RiskyEventsResult
                {
                    RiskyUsers = new List<RiskyUser>(),
                    RiskDetections = new List<RiskDetection>(),
                    Summary = summary
                };

                WriteObject(result);
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during risky events collection: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessRiskyUsersAsync(string outputDirectory, string timestamp, RiskyEventsSummary summary)
        {
            WriteVerbose("=== Starting Risky Users Collection ===");

            var riskyUsers = new List<RiskyUser>();

            try
            {
                if (UserIds != null && UserIds.Length > 0)
                {
                    // Process specific users
                    WriteVerbose($"Processing {UserIds.Length} specific users");

                    foreach (var userId in UserIds)
                    {
                        try
                        {
                            var user = await _graphClient.GetRiskyUserAsync(userId);
                            if (user != null)
                            {
                                var riskyUser = ProcessRiskyUserData(user);

                                if (!HighRiskOnly || riskyUser.RiskLevel == "High")
                                {
                                    riskyUsers.Add(riskyUser);
                                    UpdateRiskSummary(riskyUser, summary);
                                }
                            }
                            else
                            {
                                WriteVerbose($"User ID {userId} not found or not risky.");
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteErrorWithTimestamp($"Failed to retrieve data for User ID {userId}: {ex.Message}");
                        }
                    }
                }
                else
                {
                    // Get all risky users
                    WriteVerbose("Processing all risky users");

                    var allRiskyUsers = await _graphClient.GetRiskyUsersAsync();

                    foreach (var user in allRiskyUsers)
                    {
                        try
                        {
                            var riskyUser = ProcessRiskyUserData(user);

                            if (!HighRiskOnly || riskyUser.RiskLevel == "High")
                            {
                                riskyUsers.Add(riskyUser);
                                UpdateRiskSummary(riskyUser, summary);
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteWarningWithTimestamp($"Failed to process risky user: {ex.Message}");
                        }
                    }
                }

                if (riskyUsers.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-RiskyUsers.csv");
                    await WriteRiskyUsersAsync(riskyUsers, fileName);
                    summary.OutputFiles.Add(fileName);

                    WriteVerbose($"Risky users data written to: {fileName}");
                    summary.TotalRiskyUsers = riskyUsers.Count;
                }
                else
                {
                    WriteVerbose("No risky users found");
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during risky users collection: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessRiskyDetectionsAsync(string outputDirectory, string timestamp, RiskyEventsSummary summary)
        {
            WriteVerbose("=== Starting Risky Detections Collection ===");

            var riskDetections = new List<RiskDetection>();

            try
            {
                if (UserIds != null && UserIds.Length > 0)
                {
                    // Process specific users
                    WriteVerbose($"Processing risky detections for {UserIds.Length} specific users");

                    foreach (var userId in UserIds)
                    {
                        try
                        {
                            var detections = await _graphClient.GetRiskDetectionsAsync($"userPrincipalName eq '{userId}'");

                            foreach (var detection in detections)
                            {
                                var riskDetection = ProcessRiskDetectionData(detection);

                                if (!HighRiskOnly || riskDetection.RiskLevel == "High")
                                {
                                    riskDetections.Add(riskDetection);
                                    UpdateDetectionSummary(riskDetection, summary);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteErrorWithTimestamp($"Failed to retrieve risk detections for User ID {userId}: {ex.Message}");
                        }
                    }
                }
                else
                {
                    // Get all risk detections
                    WriteVerbose("Processing all risk detections");

                    var allDetections = await _graphClient.GetRiskDetectionsAsync();

                    foreach (var detection in allDetections)
                    {
                        try
                        {
                            var riskDetection = ProcessRiskDetectionData(detection);

                            if (!HighRiskOnly || riskDetection.RiskLevel == "High")
                            {
                                riskDetections.Add(riskDetection);
                                UpdateDetectionSummary(riskDetection, summary);
                            }
                        }
                        catch (Exception ex)
                        {
                            WriteWarningWithTimestamp($"Failed to process risk detection: {ex.Message}");
                        }
                    }
                }

                if (riskDetections.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-RiskyDetections.csv");
                    await WriteRiskDetectionsAsync(riskDetections, fileName);
                    summary.OutputFiles.Add(fileName);

                    WriteVerbose($"Risk detections data written to: {fileName}");
                    summary.TotalRiskDetections = riskDetections.Count;
                }
                else
                {
                    WriteVerbose("No risk detections found");
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"An error occurred during risk detections collection: {ex.Message}");

                if (ex.Message.Contains("license") || ex.Message.Contains("feature"))
                {
                    WriteErrorWithTimestamp("Check that the target tenant is licensed for this feature");
                }

                throw;
            }
        }

        private RiskyUser ProcessRiskyUserData(dynamic user)
        {
            return new RiskyUser
            {
                Id = user.Id?.ToString(),
                IsDeleted = user.IsDeleted ?? false,
                IsProcessing = user.IsProcessing ?? false,
                RiskDetail = user.RiskDetail?.ToString(),
                RiskLastUpdatedDateTime = user.RiskLastUpdatedDateTime,
                RiskLevel = user.RiskLevel?.ToString(),
                RiskState = user.RiskState?.ToString(),
                UserDisplayName = user.UserDisplayName?.ToString(),
                UserPrincipalName = user.UserPrincipalName?.ToString(),
                AdditionalProperties = ProcessAdditionalProperties(user.AdditionalProperties)
            };
        }

        private RiskDetection ProcessRiskDetectionData(dynamic detection)
        {
            return new RiskDetection
            {
                Activity = detection.Activity?.ToString(),
                ActivityDateTime = detection.ActivityDateTime,
                AdditionalInfo = detection.AdditionalInfo?.ToString(),
                CorrelationId = detection.CorrelationId?.ToString(),
                DetectedDateTime = detection.DetectedDateTime,
                IpAddress = detection.IPAddress?.ToString(),
                Id = detection.Id?.ToString(),
                LastUpdatedDateTime = detection.LastUpdatedDateTime,
                City = detection.Location?.City?.ToString(),
                CountryOrRegion = detection.Location?.CountryOrRegion?.ToString(),
                State = detection.Location?.State?.ToString(),
                RequestId = detection.RequestId?.ToString(),
                RiskDetail = detection.RiskDetail?.ToString(),
                RiskEventType = detection.RiskEventType?.ToString(),
                RiskLevel = detection.RiskLevel?.ToString(),
                RiskState = detection.RiskState?.ToString(),
                DetectionTimingType = detection.DetectionTimingType?.ToString(),
                Source = detection.Source?.ToString(),
                TokenIssuerType = detection.TokenIssuerType?.ToString(),
                UserDisplayName = detection.UserDisplayName?.ToString(),
                UserId = detection.UserId?.ToString(),
                UserPrincipalName = detection.UserPrincipalName?.ToString(),
                AdditionalProperties = ProcessAdditionalProperties(detection.AdditionalProperties)
            };
        }

        private string ProcessAdditionalProperties(dynamic additionalProperties)
        {
            if (additionalProperties == null)
                return string.Empty;

            try
            {
                var properties = new List<string>();
                foreach (var property in additionalProperties)
                {
                    properties.Add($"{property.Key}: {property.Value}");
                }
                return string.Join(", ", properties);
            }
            catch
            {
                return additionalProperties.ToString();
            }
        }

        private void UpdateRiskSummary(RiskyUser riskyUser, RiskyEventsSummary summary)
        {
            // Update risk level breakdown
            if (!string.IsNullOrEmpty(riskyUser.RiskLevel))
            {
                if (summary.RiskLevelBreakdown.ContainsKey(riskyUser.RiskLevel))
                    summary.RiskLevelBreakdown[riskyUser.RiskLevel]++;
                else
                    summary.RiskLevelBreakdown[riskyUser.RiskLevel] = 1;
            }

            // Update risk state breakdown
            if (!string.IsNullOrEmpty(riskyUser.RiskState))
            {
                if (summary.RiskStateBreakdown.ContainsKey(riskyUser.RiskState))
                    summary.RiskStateBreakdown[riskyUser.RiskState]++;
                else
                    summary.RiskStateBreakdown[riskyUser.RiskState] = 1;
            }
        }

        private void UpdateDetectionSummary(RiskDetection riskDetection, RiskyEventsSummary summary)
        {
            // Update risk level breakdown
            if (!string.IsNullOrEmpty(riskDetection.RiskLevel))
            {
                if (summary.RiskLevelBreakdown.ContainsKey(riskDetection.RiskLevel))
                    summary.RiskLevelBreakdown[riskDetection.RiskLevel]++;
                else
                    summary.RiskLevelBreakdown[riskDetection.RiskLevel] = 1;
            }

            // Update risk state breakdown
            if (!string.IsNullOrEmpty(riskDetection.RiskState))
            {
                if (summary.RiskStateBreakdown.ContainsKey(riskDetection.RiskState))
                    summary.RiskStateBreakdown[riskDetection.RiskState]++;
                else
                    summary.RiskStateBreakdown[riskDetection.RiskState] = 1;
            }
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

        private void LogSummary(RiskyEventsSummary summary)
        {
            WriteVerbose("");
            WriteVerbose("=== Risky Events Collection Summary ===");
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
            WriteVerbose($"Total Risky Users: {summary.TotalRiskyUsers:N0}");
            WriteVerbose($"Total Risk Detections: {summary.TotalRiskDetections:N0}");

            if (summary.RiskLevelBreakdown.Count > 0)
            {
                WriteVerbose("");
                WriteVerbose("Risk Level Breakdown:");
                foreach (var kvp in summary.RiskLevelBreakdown.OrderByDescending(x => x.Value))
                {
                    WriteVerbose($"  - {kvp.Key}: {kvp.Value:N0}");
                }
            }

            if (summary.RiskStateBreakdown.Count > 0)
            {
                WriteVerbose("");
                WriteVerbose("Risk State Breakdown:");
                foreach (var kvp in summary.RiskStateBreakdown.OrderByDescending(x => x.Value))
                {
                    WriteVerbose($"  - {kvp.Key}: {kvp.Value:N0}");
                }
            }

            WriteVerbose("");
            WriteVerbose("Output Files:");
            foreach (var file in summary.OutputFiles)
            {
                WriteVerbose($"  - {file}");
            }
            WriteVerbose("==========================================");
        }

        private async Task WriteRiskyUsersAsync(IEnumerable<RiskyUser> users, string filePath)
        {
            var csv = "Id,IsDeleted,IsProcessing,RiskDetail,RiskLastUpdatedDateTime,RiskLevel,RiskState,UserDisplayName,UserPrincipalName,AdditionalProperties" + Environment.NewLine;

            foreach (var user in users)
            {
                var values = new[]
                {
                    EscapeCsvValue(user.Id),
                    user.IsDeleted.ToString(),
                    user.IsProcessing.ToString(),
                    EscapeCsvValue(user.RiskDetail),
                    user.RiskLastUpdatedDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(user.RiskLevel),
                    EscapeCsvValue(user.RiskState),
                    EscapeCsvValue(user.UserDisplayName),
                    EscapeCsvValue(user.UserPrincipalName),
                    EscapeCsvValue(user.AdditionalProperties)
                };

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteRiskDetectionsAsync(IEnumerable<RiskDetection> detections, string filePath)
        {
            var csv = "Activity,ActivityDateTime,AdditionalInfo,CorrelationId,DetectedDateTime,IpAddress,Id,LastUpdatedDateTime,City,CountryOrRegion,State,RequestId,RiskDetail,RiskEventType,RiskLevel,RiskState,DetectionTimingType,Source,TokenIssuerType,UserDisplayName,UserId,UserPrincipalName,AdditionalProperties" + Environment.NewLine;

            foreach (var detection in detections)
            {
                var values = new[]
                {
                    EscapeCsvValue(detection.Activity),
                    detection.ActivityDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(detection.AdditionalInfo),
                    EscapeCsvValue(detection.CorrelationId),
                    detection.DetectedDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(detection.IpAddress),
                    EscapeCsvValue(detection.Id),
                    detection.LastUpdatedDateTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                    EscapeCsvValue(detection.City),
                    EscapeCsvValue(detection.CountryOrRegion),
                    EscapeCsvValue(detection.State),
                    EscapeCsvValue(detection.RequestId),
                    EscapeCsvValue(detection.RiskDetail),
                    EscapeCsvValue(detection.RiskEventType),
                    EscapeCsvValue(detection.RiskLevel),
                    EscapeCsvValue(detection.RiskState),
                    EscapeCsvValue(detection.DetectionTimingType),
                    EscapeCsvValue(detection.Source),
                    EscapeCsvValue(detection.TokenIssuerType),
                    EscapeCsvValue(detection.UserDisplayName),
                    EscapeCsvValue(detection.UserId),
                    EscapeCsvValue(detection.UserPrincipalName),
                    EscapeCsvValue(detection.AdditionalProperties)
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
    public class RiskyEventsResult
    {
        public List<RiskyUser> RiskyUsers { get; set; }
List<RiskyUser>();
        public List<RiskDetection> RiskDetections { get; set; } = new List<RiskDetection>();
        public RiskyEventsSummary Summary { get; set; }
    }

    public class RiskyUser
    {
        #pragma warning disable SA1600
        public string Id { get; set; }
        #pragma warning disable SA1600
        public bool IsDeleted { get; set; }
        #pragma warning disable SA1600
        public bool IsProcessing { get; set; }
        #pragma warning disable SA1600
        public string RiskDetail { get; set; }
#pragma warning disable SA1201
        public DateTime? RiskLastUpdatedDateTime { get; set; }
#pragma warning restore SA1201
        #pragma warning disable SA1600
        public string RiskLevel { get; set; }
        #pragma warning disable SA1600
        public string RiskState { get; set; }
        #pragma warning disable SA1600
        public string UserDisplayName { get; set; }
        public string UserPrincipalName { get; set; }public string AdditionalProperties { get; set; }
    }

    public class RiskDetection
    {
        #pragma warning disable SA1600
        public string Activity { get; set; }
        public DateTime? ActivityDateTime { get; set; }
        #pragma warning disable SA1600
        public string AdditionalInfo { get; set; }
        #pragma warning disable SA1600
        public string CorrelationId { get; set; }
#pragma warning disable SA1201
        public DateTime? DetectedDateTime { get; set; }
#pragma warning restore SA1201
        #pragma warning disable SA1600
        public string IpAddress { get; set; }
        #pragma warning disable SA1600
        public string Id { get; set; }
        public DateTime? LastUpdatedDateTime { get; set; }
        #pragma warning disable SA1600
        public string City { get; set; }
        #pragma warning disable SA1600
        public string CountryOrRegion { get; set; }
        #pragma warning disable SA1600
        public string State { get; set; }
        #pragma warning disable SA1600
        public string RequestId { get; set; }
        #pragma warning disable SA1600
        public string RiskDetail { get; set; }
        #pragma warning disable SA1600
        public string RiskEventType { get; set; }
        #pragma warning disable SA1600
        public string RiskLevel { get; set; }
        #pragma warning disable SA1600
        public string RiskState { get; set; }
        #pragma warning disable SA1600
        public string DetectionTimingType { get; set; }
        #pragma warning disable SA1600
        public string Source { get; set; }
        #pragma warning disable SA1600
        public string TokenIssuerType { get; set; }
        #pragma warning disable SA1600
        public string UserDisplayName { get; set; }
        #pragma warning disable SA1600
        public string UserId { get; set; }
        public string UserPrincipalName { get; set; }public string AdditionalProperties { get; set; }
    }

    public class RiskyEventsSummary
    {
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set;}
        #pragma warning disable SA1600
        public int TotalRiskyUsers { get; set; }
        #pragma warning disable SA1600
        public int TotalRiskDetections { get; set; }
        public Dictionary<string, int> RiskLevelBreakdown { get; set; } = new
int>();
        public Dictionary<string, int> RiskStateBreakdown { get; set; } = new Dictionary<string, int>();
        public List<string> OutputFiles { get; set; } = new List<string>();
    }
}
