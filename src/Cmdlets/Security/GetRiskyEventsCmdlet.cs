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
#pragma warning disable SA1600
        public string[] UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]
#pragma warning disable SA1600
        public string OutputDir { get; set; } = "Output\\RiskyEvents";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "File encoding for output files")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Operation mode: RiskyUsers, RiskyDetections, or Both")]
        [ValidateSet("RiskyUsers", "RiskyDetections", "Both")]
#pragma warning disable SA1600
        public string Mode { get; set; } = "Both";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Include only high-risk events")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1309
        public SwitchParameter HighRiskOnly { get; set; }
#pragma warning disable SA1201
        private GraphApiClient? _graphClient;
#pragma warning restore SA1201
#pragma warning disable SA1600
        private readonly string[] RequiredScopes = {
#pragma warning restore SA1600
documented "IdentityRiskEvent.Read.All", "IdentityRiskyUser.Read.All" };

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
            WriteVerbose("=== Starting Risky Events Collection ===");
#pragma warning restore SA1101

            // Check for authentication and scopes
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
            var authInfo = await _graphClient!.GetAuthenticationInfoAsync();
#pragma warning restore SA1101
            // Note: Scope checking is not available through Graph API directly
            // Continuing without scope validation
#pragma warning disable SA1101
            WriteVerbose("Proceeding with risky events collection...");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var outputDirectory = GetOutputDirectory();
#pragma warning restore SA1101
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
#pragma warning disable SA1101
                switch (Mode.ToUpperInvariant())
                {
                    case "RISKYUSERS":
#pragma warning disable SA1101
                        await ProcessRiskyUsersAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                    case "RISKYDETECTIONS":
#pragma warning disable SA1101
                        await ProcessRiskyDetectionsAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                    case "BOTH":
#pragma warning disable SA1101
                        await ProcessRiskyUsersAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
#pragma warning disable SA1101
                        await ProcessRiskyDetectionsAsync(outputDirectory, timestamp, summary);
#pragma warning restore SA1101
                        break;
                }
#pragma warning restore SA1101

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
#pragma warning disable SA1101
                LogSummary(summary);
#pragma warning restore SA1101

                var result = new RiskyEventsResult
                {
                    RiskyUsers = new List<RiskyUser>(),
                    RiskDetections = new List<RiskDetection>(),
                    Summary = summary
                };

#pragma warning disable SA1101
                WriteObject(result);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during risky events collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task ProcessRiskyUsersAsync(string outputDirectory, string timestamp, RiskyEventsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting Risky Users Collection ===");
#pragma warning restore SA1101

            var riskyUsers = new List<RiskyUser>();

            try
            {
#pragma warning disable SA1101
                if (UserIds != null && UserIds.Length > 0)
                {
                    // Process specific users
#pragma warning disable SA1101
                    WriteVerbose($"Processing {UserIds.Length} specific users");
#pragma warning restore SA1101

#pragma warning disable SA1101
                    foreach (var userId in UserIds)
                    {
                        try
                        {
#pragma warning disable SA1101
                            var user = await _graphClient.GetRiskyUserAsync(userId);
#pragma warning restore SA1101
                            if (user != null)
                            {
#pragma warning disable SA1101
                                var riskyUser = ProcessRiskyUserData(user);
#pragma warning restore SA1101

#pragma warning disable SA1101
                                if (!HighRiskOnly || riskyUser.RiskLevel == "High")
                                {
                                    riskyUsers.Add(riskyUser);
#pragma warning disable SA1101
                                    UpdateRiskSummary(riskyUser, summary);
#pragma warning restore SA1101
                                }
#pragma warning restore SA1101
                            }
                            else
                            {
#pragma warning disable SA1101
                                WriteVerbose($"User ID {userId} not found or not risky.");
#pragma warning restore SA1101
                            }
                        }
                        catch (Exception ex)
                        {
#pragma warning disable SA1101
                            WriteErrorWithTimestamp($"Failed to retrieve data for User ID {userId}: {ex.Message}");
#pragma warning restore SA1101
                        }
                    }
#pragma warning restore SA1101
                }
                else
                {
                    // Get all risky users
#pragma warning disable SA1101
                    WriteVerbose("Processing all risky users");
#pragma warning restore SA1101

#pragma warning disable SA1101
                    var allRiskyUsers = await _graphClient.GetRiskyUsersAsync();
#pragma warning restore SA1101

                    foreach (var user in allRiskyUsers)
                    {
                        try
                        {
#pragma warning disable SA1101
                            var riskyUser = ProcessRiskyUserData(user);
#pragma warning restore SA1101

#pragma warning disable SA1101
                            if (!HighRiskOnly || riskyUser.RiskLevel == "High")
                            {
                                riskyUsers.Add(riskyUser);
#pragma warning disable SA1101
                                UpdateRiskSummary(riskyUser, summary);
#pragma warning restore SA1101
                            }
#pragma warning restore SA1101
                        }
                        catch (Exception ex)
                        {
#pragma warning disable SA1101
                            WriteWarningWithTimestamp($"Failed to process risky user: {ex.Message}");
#pragma warning restore SA1101
                        }
                    }
                }
#pragma warning restore SA1101

                if (riskyUsers.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-RiskyUsers.csv");
#pragma warning disable SA1101
                    await WriteRiskyUsersAsync(riskyUsers, fileName);
#pragma warning restore SA1101
                    summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                    WriteVerbose($"Risky users data written to: {fileName}");
#pragma warning restore SA1101
                    summary.TotalRiskyUsers = riskyUsers.Count;
                }
                else
                {
#pragma warning disable SA1101
                    WriteVerbose("No risky users found");
#pragma warning restore SA1101
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during risky users collection: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task ProcessRiskyDetectionsAsync(string outputDirectory, string timestamp, RiskyEventsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting Risky Detections Collection ===");
#pragma warning restore SA1101

            var riskDetections = new List<RiskDetection>();

            try
            {
#pragma warning disable SA1101
                if (UserIds != null && UserIds.Length > 0)
                {
                    // Process specific users
#pragma warning disable SA1101
                    WriteVerbose($"Processing risky detections for {UserIds.Length} specific users");
#pragma warning restore SA1101

#pragma warning disable SA1101
                    foreach (var userId in UserIds)
                    {
                        try
                        {
#pragma warning disable SA1101
                            var detections = await _graphClient.GetRiskDetectionsAsync($"userPrincipalName eq '{userId}'");
#pragma warning restore SA1101

                            foreach (var detection in detections)
                            {
#pragma warning disable SA1101
                                var riskDetection = ProcessRiskDetectionData(detection);
#pragma warning restore SA1101

#pragma warning disable SA1101
                                if (!HighRiskOnly || riskDetection.RiskLevel == "High")
                                {
                                    riskDetections.Add(riskDetection);
#pragma warning disable SA1101
                                    UpdateDetectionSummary(riskDetection, summary);
#pragma warning restore SA1101
                                }
#pragma warning restore SA1101
                            }
                        }
                        catch (Exception ex)
                        {
#pragma warning disable SA1101
                            WriteErrorWithTimestamp($"Failed to retrieve risk detections for User ID {userId}: {ex.Message}");
#pragma warning restore SA1101
                        }
                    }
#pragma warning restore SA1101
                }
                else
                {
                    // Get all risk detections
#pragma warning disable SA1101
                    WriteVerbose("Processing all risk detections");
#pragma warning restore SA1101

#pragma warning disable SA1101
                    var allDetections = await _graphClient.GetRiskDetectionsAsync();
#pragma warning restore SA1101

                    foreach (var detection in allDetections)
                    {
                        try
                        {
#pragma warning disable SA1101
                            var riskDetection = ProcessRiskDetectionData(detection);
#pragma warning restore SA1101

#pragma warning disable SA1101
                            if (!HighRiskOnly || riskDetection.RiskLevel == "High")
                            {
                                riskDetections.Add(riskDetection);
#pragma warning disable SA1101
                                UpdateDetectionSummary(riskDetection, summary);
#pragma warning restore SA1101
                            }
#pragma warning restore SA1101
                        }
                        catch (Exception ex)
                        {
#pragma warning disable SA1101
                            WriteWarningWithTimestamp($"Failed to process risk detection: {ex.Message}");
#pragma warning restore SA1101
                        }
                    }
                }
#pragma warning restore SA1101

                if (riskDetections.Count > 0)
                {
                    var fileName = Path.Combine(outputDirectory, $"{timestamp}-RiskyDetections.csv");
#pragma warning disable SA1101
                    await WriteRiskDetectionsAsync(riskDetections, fileName);
#pragma warning restore SA1101
                    summary.OutputFiles.Add(fileName);

#pragma warning disable SA1101
                    WriteVerbose($"Risk detections data written to: {fileName}");
#pragma warning restore SA1101
                    summary.TotalRiskDetections = riskDetections.Count;
                }
                else
                {
#pragma warning disable SA1101
                    WriteVerbose("No risk detections found");
#pragma warning restore SA1101
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during risk detections collection: {ex.Message}");
#pragma warning restore SA1101

                if (ex.Message.Contains("license") || ex.Message.Contains("feature"))
                {
#pragma warning disable SA1101
                    WriteErrorWithTimestamp("Check that the target tenant is licensed for this feature");
#pragma warning restore SA1101
                }

                throw;
            }
        }

        private RiskyUser ProcessRiskyUserData(dynamic user)
        {
#pragma warning disable SA1101
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
#pragma warning restore SA1101
        }

        private RiskDetection ProcessRiskDetectionData(dynamic detection)
        {
#pragma warning disable SA1101
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
#pragma warning restore SA1101
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

        private void LogSummary(RiskyEventsSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("=== Risky Events Collection Summary ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Total Risky Users: {summary.TotalRiskyUsers:N0}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Total Risk Detections: {summary.TotalRiskDetections:N0}");
#pragma warning restore SA1101

            if (summary.RiskLevelBreakdown.Count > 0)
            {
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose("Risk Level Breakdown:");
#pragma warning restore SA1101
                foreach (var kvp in summary.RiskLevelBreakdown.OrderByDescending(x => x.Value))
                {
#pragma warning disable SA1101
                    WriteVerbose($"  - {kvp.Key}: {kvp.Value:N0}");
#pragma warning restore SA1101
                }
            }

            if (summary.RiskStateBreakdown.Count > 0)
            {
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose("Risk State Breakdown:");
#pragma warning restore SA1101
                foreach (var kvp in summary.RiskStateBreakdown.OrderByDescending(x => x.Value))
                {
#pragma warning disable SA1101
                    WriteVerbose($"  - {kvp.Key}: {kvp.Value:N0}");
#pragma warning restore SA1101
                }
            }

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
            WriteVerbose("==========================================");
#pragma warning restore SA1101
        }

        private async Task WriteRiskyUsersAsync(IEnumerable<RiskyUser> users, string filePath)
        {
            var csv = "Id,IsDeleted,IsProcessing,RiskDetail,RiskLastUpdatedDateTime,RiskLevel,RiskState,UserDisplayName,UserPrincipalName,AdditionalProperties" + Environment.NewLine;

            foreach (var user in users)
            {
#pragma warning disable SA1101
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
#pragma warning restore SA1101

                csv += string.Join(",", values) + Environment.NewLine;
            }

            using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
        }

        private async Task WriteRiskDetectionsAsync(IEnumerable<RiskDetection> detections, string filePath)
        {
            var csv = "Activity,ActivityDateTime,AdditionalInfo,CorrelationId,DetectedDateTime,IpAddress,Id,LastUpdatedDateTime,City,CountryOrRegion,State,RequestId,RiskDetail,RiskEventType,RiskLevel,RiskState,DetectionTimingType,Source,TokenIssuerType,UserDisplayName,UserId,UserPrincipalName,AdditionalProperties" + Environment.NewLine;

            foreach (var detection in detections)
            {
#pragma warning disable SA1101
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
    public class RiskyEventsResult
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        public List<RiskyUser> RiskyUsers { get; set; }
List<RiskyUser>();
        public List<RiskDetection> RiskDetections { get; set; } = new List<RiskDetection>();
#pragma warning disable SA1600
        public RiskyEventsSummary Summary { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class RiskyUser
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Id { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsDeleted { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsProcessing { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RiskDetail { get; set; }
#pragma warning disable SA1201
        public DateTime? RiskLastUpdatedDateTime { get; set; }
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RiskLevel { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RiskState { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserDisplayName { get; set; }
        public string UserPrincipalName { get; set; }public string AdditionalProperties { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class RiskDetection
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Activity { get; set; }
        public DateTime? ActivityDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string AdditionalInfo { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string CorrelationId { get; set; }
#pragma warning disable SA1201
        public DateTime? DetectedDateTime { get; set; }
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string IpAddress { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Id { get; set; }
        public DateTime? LastUpdatedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string City { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string CountryOrRegion { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string State { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RequestId { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RiskDetail { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RiskEventType { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RiskLevel { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string RiskState { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string DetectionTimingType { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string Source { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string TokenIssuerType { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserDisplayName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string UserId { get; set; }
        public string UserPrincipalName { get; set; }public string AdditionalProperties { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class RiskyEventsSummary
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set;}
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalRiskyUsers { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalRiskDetections { get; set; }
        public Dictionary<string, int> RiskLevelBreakdown { get; set; } = new
#pragma warning restore SA1600
int>();
        public Dictionary<string, int> RiskStateBreakdown { get; set; } = new Dictionary<string, int>();
        public List<string> OutputFiles { get; set; } = new List<string>();
    }
}
