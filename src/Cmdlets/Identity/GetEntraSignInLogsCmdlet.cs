namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Threading.Tasks.Dataflow;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Logging;
    using Microsoft.ExtractorSuite.Models.Graph;
    using Microsoft.Graph;
    using Microsoft.Graph.Models;


    /// <summary>
    /// Retrieves Entra ID (Azure AD) sign-in logs with advanced filtering and performance optimizations.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "EntraSignInLogs")]
    [OutputType(typeof(SignInLog))]
    [Alias("Get-AzureADSignInLogs", "Get-AADSignInLogs")]
    public class GetEntraSignInLogsCmdlet : BaseCmdlet
    {
        #region Parameters

        [Parameter(
            HelpMessage = "Start date for sign-in logs. Default: -30 days")]
#pragma warning disable SA1600
        public DateTime? StartDate { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "End date for sign-in logs. Default: Now")]
#pragma warning disable SA1600
        public DateTime? EndDate { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Filter by user principal name(s)")]
#pragma warning disable SA1600
        public string[]? UserPrincipalNames { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Filter by application ID(s)")]
#pragma warning disable SA1600
        public string[]? ApplicationIds { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Filter by IP address")]
#pragma warning disable SA1600
        public string? IPAddress { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Filter by sign-in status: Success, Failure, All")]
        [ValidateSet("Success", "Failure", "All")]
#pragma warning disable SA1600
        public string StatusFilter { get; set; } = "All";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Filter by risk level: None, Low, Medium, High, All")]
        [ValidateSet("None", "Low", "Medium", "High", "All")]
#pragma warning disable SA1600
        public string RiskLevel { get; set; } = "All";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Filter by conditional access status")]
        [ValidateSet("Success", "Failure", "NotApplied", "All")]
#pragma warning disable SA1600
        public string ConditionalAccessStatus { get; set; } = "All";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Include only interactive sign-ins")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter InteractiveOnly { get; set; }

        [Parameter(
            HelpMessage = "Include only risky sign-ins")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter RiskyOnly { get; set; }

        [Parameter(
            HelpMessage = "Include guest user sign-ins")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeGuests { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results")]
#pragma warning disable SA1600
        public string OutputDir { get; set; } = Path.Combine("Output", "EntraSignInLogs");
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output format: CSV, JSON, JSONL")]
        [ValidateSet("CSV", "JSON", "JSONL")]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "JSONL";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Maximum parallel requests")]
        [ValidateRange(1, 20)]
#pragma warning disable SA1600
        public int MaxParallelRequests { get; set; } = 10;
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Include detailed analysis")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter DetailedAnalysis { get; set; }

        [Parameter(
            HelpMessage = "Export suspicious activities separately")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter ExportSuspicious { get; set; }

        #endregion

        #region Private Fields

#pragma warning disable SA1309
#pragma warning disable SA1201
        private GraphServiceClient? _graphClient;
#pragma warning restore SA1201
#pragma warning disable SA1309
        private readonly Statistics _stats = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private readonly List<SignInLog> _allSignIns = new();
#pragma warning restore SA1309
#pragma warning disable SA1600
#pragma warning disable SA1309
sho
#pragma warning restore SA1600
        private readonly List<SuspiciousActivity> _suspiciousActivities = new();
#pragma warning restore SA1309
#pragma warning disable SA1309
        private string _sessionId = string.Empty;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private bool _csvHeaderWritten;
#pragma warning restore SA1309

        #endregion

        protected override void BeginProcessing()
        {
            base.BeginProcessing();

#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                throw new PSInvalidOperationException(
                    "Not connected to Microsoft Graph. Please run Connect-M365 -Service Graph first.");
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            _graphClient = AuthManager.GraphClient;
#pragma warning restore SA1101
#pragma warning disable SA1101
            _sessionId = Guid.NewGuid().ToString("N").Substring(0, 8);
#pragma warning restore SA1101

            // Set default dates (Graph API limitation: max 30 days for sign-in logs)
#pragma warning disable SA1101
            EndDate ??= DateTime.UtcNow;
#pragma warning restore SA1101
#pragma warning disable SA1101
            StartDate ??= EndDate.Value.AddDays(-30);
#pragma warning restore SA1101

            // Validate date range
#pragma warning disable SA1101
            if ((EndDate.Value - StartDate.Value).TotalDays > 30)
            {
#pragma warning disable SA1101
                WriteWarning("Sign-in logs are limited to 30 days. Adjusting start date.");
#pragma warning restore SA1101
#pragma warning disable SA1101
                StartDate = EndDate.Value.AddDays(-30);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            // Create output directory
#pragma warning disable SA1101
            if (!Directory.Exists(OutputDir))
            {
#pragma warning disable SA1101
                Directory.CreateDirectory(OutputDir);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            Logger?.LogInfo("=== Starting Entra Sign-In Logs Collection ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.LogInfo($"Date Range: {StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            Logger?.LogInfo($"Output Format: {OutputFormat}");
#pragma warning restore SA1101
#pragma warning disable SA1600
#pragma warning disable SA1101
            Logger?.LogInfo($"Output Directory: {OutputDir}");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
#pragma warning disable SA1101
                Logger.LogDebug($"Session ID: {_sessionId}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"Status Filter: {StatusFilter}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"Risk Level: {RiskLevel}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"Interactive Only: {InteractiveOnly}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                Logger.LogDebug($"Max Parallel Requests: {MaxParallelRequests}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        protected override void ProcessRecord()
        {
            try
            {
                var startTime = DateTime.UtcNow;

#pragma warning disable SA1101
                WriteHost("Retrieving Entra sign-in logs...\n", ConsoleColor.Cyan);
#pragma warning restore SA1101

                // Build filter query
#pragma warning disable SA1101
                var filter = BuildFilterQuery();
#pragma warning restore SA1101

                // Process sign-in logs
#pragma warning disable SA1101
                RunAsync(ProcessSignInLogsAsync(filter));
#pragma warning restore SA1101

                var duration = DateTime.UtcNow - startTime;

                // Analyze results if requested
#pragma warning disable SA1101
                if (DetailedAnalysis)
                {
#pragma warning disable SA1101
                    PerformDetailedAnalysis();
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                // Export results
#pragma warning disable SA1101
                ExportResults();
#pragma warning restore SA1101

                // Export suspicious activities if requested
#pragma warning disable SA1101
                if (ExportSuspicious && _suspiciousActivities.Any())
                {
#pragma warning disable SA1101
                    ExportSuspiciousActivities();
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                // Display statistics
#pragma warning disable SA1101
                DisplayStatistics(duration);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                Logger?.WriteErrorWithTimestamp($"Error processing sign-in logs: {ex.Message}", ex);
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to process sign-in logs: {ex.Message}", ex);
#pragma warning restore SA1101
            }
        }

        private async Task ProcessSignInLogsAsync(string filter)
        {
#pragma warning disable SA1101
            if (_graphClient == null)
            {
                throw new InvalidOperationException("Graph client not initialized");
            }
#pragma warning restore SA1101

            try
            {
#pragma warning disable SA1101
                var signInsResponse = await _graphClient.AuditLogs.SignIns
                    .GetAsync(requestConfiguration =>
#pragma warning disable SA1101
                    {
                        requestConfiguration.QueryParameters.Filter = filter;
                        requestConfiguration.QueryParameters.Select = new[]
                        {
                            "id", "createdDateTime", "userPrincipalName", "userId", "userDisplayName",
                            "appId", "appDisplayName", "ipAddress", "clientAppUsed", "correlationId",
                            "conditionalAccessStatus", "isInteractive", "riskDetail", "riskLevelAggregated",
                            "riskLevelDuringSignIn", "riskState", "riskEventTypes", "riskEventTypes_v2",
                            "status", "deviceDetail", "location", "appliedConditionalAccessPolicies",
                            "authenticationMethodsUsed", "mfaDetail", "tokenIssuerType", "resourceDisplayName"
                        };
                        requestConfiguration.QueryParameters.Orderby = new[] { "createdDateTime desc" };
                        requestConfiguration.QueryParameters.Top = 999;
                    }, CancellationToken);
#pragma warning restore SA1101

                var pageCount = 0;

#pragma warning disable SA1101
                var pageIterator = PageIterator<Microsoft.Graph.Models.SignIn, Microsoft.Graph.Models.SignInCollectionResponse>
                    .CreatePageIterator(
                        _graphClient,
                        signInsResponse,
                        async (signIn) =>
                        {
#pragma warning disable SA1101
                            var log = ConvertToSignInLog(signIn);
#pragma warning restore SA1101
#pragma warning disable SA1101
                            ProcessSignInLog(log);
#pragma warning restore SA1101
#pragma warning disable SA1101
                            _allSignIns.Add(log);
#pragma warning restore SA1101
#pragma warning disable SA1101
                            return !CancellationToken.IsCancellationRequested;
#pragma warning restore SA1101
                        });
#pragma warning restore SA1101

#pragma warning disable SA1101
                await pageIterator.IterateAsync(CancellationToken);
#pragma warning restore SA1101

#pragma warning disable SA1101
                WriteProgressSafe("Processing Sign-In Logs", "Complete", 100);
#pragma warning restore SA1101
            }
            catch (ServiceException ex)
            {
#pragma warning disable SA1101
                Logger?.WriteErrorWithTimestamp($"Graph API error: {ex.Message}", ex);
#pragma warning restore SA1101
                throw new PSInvalidOperationException($"Failed to retrieve sign-in logs: {ex.Message}", ex);
            }
        }

        private SignInLog ConvertToSignInLog(Microsoft.Graph.Models.SignIn graphSignIn)
        {
            return new SignInLog
            {
                Id = graphSignIn.Id,
                CreatedDateTime = graphSignIn.CreatedDateTime ?? DateTimeOffset.MinValue,
                UserDisplayName = graphSignIn.UserDisplayName,
                UserPrincipalName = graphSignIn.UserPrincipalName,
                UserId = graphSignIn.UserId,
                AppId = graphSignIn.AppId,
                AppDisplayName = graphSignIn.AppDisplayName,
                IpAddress = graphSignIn.IpAddress,
                ClientAppUsed = graphSignIn.ClientAppUsed,
                CorrelationId = graphSignIn.CorrelationId,
                ConditionalAccessStatus = graphSignIn.ConditionalAccessStatus?.ToString(),
                IsInteractive = graphSignIn.IsInteractive ?? false,
                RiskDetail = graphSignIn.RiskDetail?.ToString(),
                RiskLevelAggregated = graphSignIn.RiskLevelAggregated?.ToString(),
                RiskLevelDuringSignIn = graphSignIn.RiskLevelDuringSignIn?.ToString(),
                RiskState = graphSignIn.RiskState?.ToString(),
                RiskEventTypes = graphSignIn.RiskEventTypesV2?.ToList(),
                RiskEventTypesV2 = graphSignIn.RiskEventTypesV2?.ToList(), // Map to v2 as well
                Status = graphSignIn.Status != null ? new Microsoft.ExtractorSuite.Models.Graph.SignInStatus
                {
                    ErrorCode = graphSignIn.Status.ErrorCode ?? 0,
                    FailureReason = graphSignIn.Status.FailureReason,
                    AdditionalDetails = graphSignIn.Status.AdditionalDetails
                } : null,
                DeviceDetail = graphSignIn.DeviceDetail != null ? new Microsoft.ExtractorSuite.Models.Graph.DeviceDetail
                {
                    DeviceId = graphSignIn.DeviceDetail.DeviceId,
                    DisplayName = graphSignIn.DeviceDetail.DisplayName,
                    OperatingSystem = graphSignIn.DeviceDetail.OperatingSystem,
                    Browser = graphSignIn.DeviceDetail.Browser,
                    IsCompliant = graphSignIn.DeviceDetail.IsCompliant,
                    IsManaged = graphSignIn.DeviceDetail.IsManaged,
                    TrustType = graphSignIn.DeviceDetail.TrustType
                } : null,
                Location = graphSignIn.Location != null ? new Microsoft.ExtractorSuite.Models.Graph.SignInLocation
                {
                    City = graphSignIn.Location.City,
                    State = graphSignIn.Location.State,
                    CountryOrRegion = graphSignIn.Location.CountryOrRegion,
                    GeoCoordinates = graphSignIn.Location.GeoCoordinates != null ? new Microsoft.ExtractorSuite.Models.Graph.GeoCoordinates
                    {
                        Latitude = graphSignIn.Location.GeoCoordinates.Latitude,
                        Longitude = graphSignIn.Location.GeoCoordinates.Longitude
                    } : null
                } : null
            };
        }

        private void ProcessSignInLog(SignInLog log)
        {
#pragma warning disable SA1101
            _stats.TotalSignIns++;
#pragma warning restore SA1101

            // Count by status
            if (log.Status?.ErrorCode == 0)
            {
#pragma warning disable SA1101
                _stats.SuccessfulSignIns++;
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                _stats.FailedSignIns++;
#pragma warning restore SA1101
            }

            // Count interactive
            if (log.IsInteractive)
            {
#pragma warning disable SA1101
                _stats.InteractiveSignIns++;
#pragma warning restore SA1101
            }

            // Count risky
            if (!string.IsNullOrEmpty(log.RiskLevelAggregated) &&
                log.RiskLevelAggregated != "none" &&
                log.RiskLevelAggregated != "hidden")
            {
#pragma warning disable SA1101
                _stats.RiskySignIns++;
#pragma warning restore SA1101
            }

            // Count guest sign-ins
            if (log.UserType == "Guest")
            {
#pragma warning disable SA1101
                _stats.GuestSignIns++;
#pragma warning restore SA1101
            }

            // Check for suspicious patterns
#pragma warning disable SA1101
            CheckForSuspiciousActivity(log);
#pragma warning restore SA1101

            // Track unique users and applications
            if (!string.IsNullOrEmpty(log.UserPrincipalName))
            {
#pragma warning disable SA1101
                _stats.UniqueUsers.Add(log.UserPrincipalName);
#pragma warning restore SA1101
            }

            if (!string.IsNullOrEmpty(log.AppId))
            {
#pragma warning disable SA1101
                _stats.UniqueApplications.Add(log.AppId);
#pragma warning restore SA1101
            }

            // Track locations
            if (log.Location?.CountryOrRegion != null)
            {
#pragma warning disable SA1101
                var currentCount = _stats.CountryCount.TryGetValue(log.Location.CountryOrRegion, out var count) ? count : 0;
#pragma warning restore SA1101
#pragma warning disable SA1101
                _stats.CountryCount[log.Location.CountryOrRegion] = currentCount + 1;
#pragma warning restore SA1101
            }
        }

        private void CheckForSuspiciousActivity(SignInLog log)
        {
            var suspiciousReasons = new List<string>();

            // Check for high risk
            if (log.RiskLevelAggregated == "high" || log.RiskLevelDuringSignIn == "high")
            {
                suspiciousReasons.Add("High risk level detected");
            }

            // Check for suspicious risk events
            if (log.RiskEventTypesV2?.Any(e =>
                e.IndexOf("unfamiliar", StringComparison.OrdinalIgnoreCase) >= 0 ||
                e.IndexOf("anonymous", StringComparison.OrdinalIgnoreCase) >= 0 ||
                e.IndexOf("malware", StringComparison.OrdinalIgnoreCase) >= 0 ||
                e.IndexOf("impossible", StringComparison.OrdinalIgnoreCase) >= 0) == true)
            {
                suspiciousReasons.Add($"Suspicious risk events: {string.Join(", ", log.RiskEventTypesV2)}");
            }

            // Check for legacy authentication
            if (log.ClientAppUsed?.IndexOf("legacy", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                suspiciousReasons.Add("Legacy authentication protocol used");
            }

            // Check for conditional access bypass attempts
            if (log.ConditionalAccessStatus == "failure" && log.Status?.ErrorCode == 0)
            {
                suspiciousReasons.Add("Conditional access bypassed");
            }

            // Check for unusual locations (simplified check)
            if (log.Location?.CountryOrRegion != null)
            {
                // In production, compare against organization's normal locations
                var unusualCountries = new[] { "North Korea", "Iran", "Syria" };
                if (unusualCountries.Contains(log.Location.CountryOrRegion))
                {
                    suspiciousReasons.Add($"Sign-in from unusual location: {log.Location.CountryOrRegion}");
                }
            }

            if (suspiciousReasons.Any())
            {
#pragma warning disable SA1101
                _suspiciousActivities.Add(new SuspiciousActivity
                {
                    SignInId = log.Id,
                    UserPrincipalName = log.UserPrincipalName,
                    Timestamp = log.CreatedDateTime,
                    Reasons = suspiciousReasons,
                    RiskLevel = log.RiskLevelAggregated ?? "Unknown",
                    IpAddress = log.IpAddress,
                    Application = log.AppDisplayName
                });
#pragma warning restore SA1101
            }
        }

        private string BuildFilterQuery()
        {
            var filters = new List<string>();

            // Date filter
#pragma warning disable SA1101
            filters.Add($"createdDateTime ge {StartDate:yyyy-MM-ddTHH:mm:ssZ} and createdDateTime le {EndDate:yyyy-MM-ddTHH:mm:ssZ}");
#pragma warning restore SA1101

            // User filter
            if (UserPrincipalNames != null && UserPrincipalNames.Any())
            {
                var userFilter = string.Join(" or ", UserPrincipalNames.Select(u => $"userPrincipalName eq '{u}'"));
                filters.Add($"({userFilter})");
            }

            // Application filter
            if (ApplicationIds != null && ApplicationIds.Any())
            {
                var appFilter = string.Join(" or ", ApplicationIds.Select(a => $"appId eq '{a}'"));
                filters.Add($"({appFilter})");
            }

            // Status filter
            if (StatusFilter == "Success")
            {
                filters.Add("status/errorCode eq 0");
            }
            else if (StatusFilter == "Failure")
            {
                filters.Add("status/errorCode ne 0");
            }

            // Risk level filter
            if (RiskLevel != "All")
            {
                filters.Add($"riskLevelAggregated eq '{RiskLevel.ToLower()}'");
            }

            // Interactive filter
            if (InteractiveOnly)
            {
                filters.Add("isInteractive eq true");
            }

            // Guest filter
            if (!IncludeGuests)
            {
                filters.Add("userType ne 'Guest'");
            }

            return string.Join(" and ", filters);

            // Date filter
#pragma warning disable SA1101
            filters.Add($"createdDateTime ge {StartDate:yyyy-MM-ddTHH:mm:ssZ} and createdDateTime le {EndDate:yyyy-MM-ddTHH:mm:ssZ}");
#pragma warning restore SA1101

            // User filter
            if (UserPrincipalNames != null && UserPrincipalNames.Any())
            {
                var userFilter = string.Join(" or ", UserPrincipalNames.Select(u => $"userPrincipalName eq '{u}'"));
                filters.Add($"({userFilter})");
            }

            // Application filter
            if (ApplicationIds != null && ApplicationIds.Any())
            {
                var appFilter = string.Join(" or ", ApplicationIds.Select(a => $"appId eq '{a}'"));
                filters.Add($"({appFilter})");
            }

            // Status filter
            if (StatusFilter == "Success")
            {
                filters.Add("status/errorCode eq 0");
            }
            else if (StatusFilter == "Failure")
            {
                filters.Add("status/errorCode ne 0");
            }

            // Risk level filter
            if (RiskLevel != "All")
            {
                filters.Add($"riskLevelAggregated eq '{RiskLevel.ToLower()}'");
            }

            // Interactive filter
            if (InteractiveOnly)
            {
                filters.Add("isInteractive eq true");
            }

            // Guest filter
            if (!IncludeGuests)
            {
                filters.Add("userType ne 'Guest'");
            }

            return string.Join(" and ", filters);
        }

        private void PerformDetailedAnalysis()
        {
#pragma warning disable SA1101
            WriteHost("\n=== Performing Detailed Analysis ===\n", ConsoleColor.Cyan);
#pragma warning restore SA1101

            // Time-based analysis
#pragma warning disable SA1101
            var hourlyDistribution = _allSignIns
                .GroupBy(s => s.CreatedDateTime.Hour)
                .OrderBy(g => g.Key)
                .ToDictionary(g => g.Key, g => g.Count());
#pragma warning restore SA1101

            // Find peak hours
            var peakHour = hourlyDistribution.OrderByDescending(kvp => kvp.Value).FirstOrDefault();
#pragma warning disable SA1101
            _stats.PeakHour = $"{peakHour.Key:00}:00 ({peakHour.Value} sign-ins)";
#pragma warning restore SA1101

            // Failed sign-in analysis
#pragma warning disable SA1101
            var failedSignIns = _allSignIns.Where(s => s.Status?.ErrorCode != 0).ToList();
#pragma warning restore SA1101
            if (failedSignIns.Any())
            {
                var topFailureReasons = failedSignIns
                    .GroupBy(s => s.Status?.FailureReason ?? "Unknown")
                    .OrderByDescending(g => g.Count())
                    .Take(5)
                    .ToDictionary(g => g.Key, g => g.Count());

#pragma warning disable SA1101
                _stats.TopFailureReasons = topFailureReasons;
#pragma warning restore SA1101
            }

            // Application usage analysis
#pragma warning disable SA1101
            var topApps = _allSignIns
                .Where(s => !string.IsNullOrEmpty(s.AppDisplayName))
                .GroupBy(s => s.AppDisplayName)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToDictionary(g => g.Key!, g => g.Count());
#pragma warning restore SA1101

#pragma warning disable SA1101
            _stats.TopApplications = topApps;
#pragma warning restore SA1101
        }

        private void ExportResults()
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
#pragma warning disable SA1101
            var filename = Path.Combine(OutputDir, $"SignInLogs_{_sessionId}_{timestamp}.{OutputFormat.ToLower()}");
#pragma warning restore SA1101

#pragma warning disable SA1101
            switch (OutputFormat.ToUpper())
            {
                case "CSV":
#pragma warning disable SA1101
                    ExportToCsv(filename);
#pragma warning restore SA1101
                    break;
                case "JSON":
#pragma warning disable SA1101
                    ExportToJson(filename);
#pragma warning restore SA1101
                    break;
                case "JSONL":
#pragma warning disable SA1101
                    ExportToJsonl(filename);
#pragma warning restore SA1101
                    break;
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            WriteHost($"\nExported {_allSignIns.Count} sign-in logs to: {filename}\n", ConsoleColor.Green);
#pragma warning restore SA1101
        }

        private void ExportToCsv(string filename)
        {
            using var writer = new StreamWriter(filename, false, Encoding.UTF8);

            // Write header
            writer.WriteLine("Id,Timestamp,UserPrincipalName,UserDisplayName,AppId,AppDisplayName,IPAddress," +
                           "Status,ErrorCode,FailureReason,RiskLevel,IsInteractive,ConditionalAccess," +
                           "Location,DeviceOS,Browser,IsCompliant,IsManaged");

#pragma warning disable SA1101
            foreach (var log in _allSignIns.OrderBy(l => l.CreatedDateTime))
            {
                var location = log.Location != null
                    ? $"{log.Location.City} {log.Location.State} {log.Location.CountryOrRegion}".Trim()
                    : string.Empty;

                writer.WriteLine($"\"{log.Id}\",\"{log.CreatedDateTime:yyyy-MM-dd HH:mm:ss}\"," +
                               $"\"{Escape(log.UserPrincipalName)}\",\"{Escape(log.UserDisplayName)}\"," +
                               $"\"{log.AppId}\",\"{Escape(log.AppDisplayName)}\",\"{log.IpAddress}\"," +
                               $"\"{(log.Status?.ErrorCode == 0 ? "Success" : "Failure")}\"," +
                               $"{log.Status?.ErrorCode},\"{Escape(log.Status?.FailureReason)}\"," +
                               $"\"{log.RiskLevelAggregated}\",{log.IsInteractive}," +
                               $"\"{log.ConditionalAccessStatus}\",\"{Escape(location)}\"," +
                               $"\"{Escape(log.DeviceDetail?.OperatingSystem)}\"," +
                               $"\"{Escape(log.DeviceDetail?.Browser)}\"," +
                               $"{log.DeviceDetail?.IsCompliant},{log.DeviceDetail?.IsManaged}");
            }
#pragma warning restore SA1101
        }

        private void ExportToJson(string filename)
        {
#pragma warning disable SA1101
            var output = new
            {
                ExportDate = DateTime.UtcNow,
                DateRange = new { Start = StartDate, End = EndDate },
                TotalRecords = _allSignIns.Count,
                Statistics = _stats,
                SignInLogs = _allSignIns.OrderBy(l => l.CreatedDateTime)
            };
#pragma warning restore SA1101

            var json = JsonSerializer.Serialize(output, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            File.WriteAllText(filename, json, Encoding.UTF8);
        }

        private void ExportToJsonl(string filename)
        {
            using var writer = new StreamWriter(filename, false, Encoding.UTF8);

#pragma warning disable SA1101
            foreach (var log in _allSignIns.OrderBy(l => l.CreatedDateTime))
            {
                var json = JsonSerializer.Serialize(log, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });
                writer.WriteLine(json);
            }
#pragma warning restore SA1101
        }

        private void ExportSuspiciousActivities()
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
#pragma warning disable SA1101
            var filename = Path.Combine(OutputDir, $"SuspiciousSignIns_{_sessionId}_{timestamp}.json");
#pragma warning restore SA1101

#pragma warning disable SA1101
            var output = new
            {
                ExportDate = DateTime.UtcNow,
                TotalSuspicious = _suspiciousActivities.Count,
                Activities = _suspiciousActivities.OrderByDescending(a => a.Timestamp)
            };
#pragma warning restore SA1101

            var json = JsonSerializer.Serialize(output, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            File.WriteAllText(filename, json, Encoding.UTF8);

#pragma warning disable SA1101
            WriteHost($"Exported {_suspiciousActivities.Count} suspicious activities to: {filename}\n",
                ConsoleColor.Yellow);
#pragma warning restore SA1101
        }

        private void UpdateProgress(int pageCount, int totalRecords)
        {
#pragma warning disable SA1101
            WriteProgressSafe(
                "Retrieving Sign-In Logs",
                $"Page {pageCount} - Total records: {totalRecords:N0}",
                -1);
#pragma warning restore SA1101

#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Processed page {pageCount}: {totalRecords} total records");
#pragma warning restore SA1101
        }

        private void DisplayStatistics(TimeSpan duration)
        {
#pragma warning disable SA1101
            WriteHost("\n=== Sign-In Logs Collection Summary ===\n", ConsoleColor.Cyan);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Duration: {duration:mm\\:ss}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Total Sign-Ins: {_stats.TotalSignIns:N0}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"  - Successful: {_stats.SuccessfulSignIns:N0}\n", ConsoleColor.Green);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"  - Failed: {_stats.FailedSignIns:N0}\n", ConsoleColor.Red);
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.InteractiveSignIns > 0)
            {
#pragma warning disable SA1101
                WriteHost($"  - Interactive: {_stats.InteractiveSignIns:N0}\n");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.RiskySignIns > 0)
            {
#pragma warning disable SA1101
                WriteHost($"  - Risky: {_stats.RiskySignIns:N0}\n", ConsoleColor.Yellow);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.GuestSignIns > 0)
            {
#pragma warning disable SA1101
                WriteHost($"  - Guest Users: {_stats.GuestSignIns:N0}\n");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            WriteHost($"\nUnique Users: {_stats.UniqueUsers.Count:N0}\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"Unique Applications: {_stats.UniqueApplications.Count:N0}\n");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_stats.CountryCount.Any())
            {
#pragma warning disable SA1101
                WriteHost($"\nTop Locations:\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
                foreach (var country in _stats.CountryCount.OrderByDescending(c => c.Value).Take(5))
                {
#pragma warning disable SA1101
                    WriteHost($"  {country.Key}: {country.Value:N0}\n");
#pragma warning restore SA1101
                }
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (DetailedAnalysis)
            {
#pragma warning disable SA1101
                WriteHost($"\nPeak Hour: {_stats.PeakHour}\n");
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (_stats.TopFailureReasons?.Any() == true)
                {
#pragma warning disable SA1101
                    WriteHost($"\nTop Failure Reasons:\n", ConsoleColor.Red);
#pragma warning restore SA1101
#pragma warning disable SA1101
                    foreach (var reason in _stats.TopFailureReasons.Take(3))
                    {
#pragma warning disable SA1101
                        WriteHost($"  {reason.Key}: {reason.Value:N0}\n");
#pragma warning restore SA1101
                    }
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (_stats.TopApplications?.Any() == true)
                {
#pragma warning disable SA1101
                    WriteHost($"\nTop Applications:\n");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    foreach (var app in _stats.TopApplications.Take(5))
                    {
#pragma warning disable SA1101
                        WriteHost($"  {app.Key}: {app.Value:N0}\n");
#pragma warning restore SA1101
                    }
#pragma warning restore SA1101
                }
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (_suspiciousActivities.Any())
            {
#pragma warning disable SA1101
                WriteHost($"\n⚠ Suspicious Activities Detected: {_suspiciousActivities.Count}\n",
                    ConsoleColor.Yellow);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            var recordsPerSecond = duration.TotalSeconds > 0 ? _stats.TotalSignIns / duration.TotalSeconds : 0;
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteHost($"\nProcessing Rate: {recordsPerSecond:N0} records/second\n");
#pragma warning restore SA1101
        }

        private static string Escape(string? value)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;

            return value.Replace("\"", "\"\"");
        }

        private void WriteHost(string message, ConsoleColor? color = null)
        {
            if (color.HasValue)
            {
#pragma warning disable SA1101
                Host.UI.Write(color.Value, Host.UI.RawUI.BackgroundColor, message);
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                Host.UI.Write(message);
#pragma warning restore SA1101
            }
        }

        #region Helper Classes

        private class Statistics
        {
            public int TotalSignIns { get; set; }public int SuccessfulSignIns { get; set; }public int FailedSignIns { get; set; }public int InteractiveSignIns { get; set; }public int RiskySignIns { get; set; }public int GuestSignIns { get; set; }public HashSet<string> UniqueUsers { get; } = new();
            public HashSet<string> UniqueApplications { get; } = new();
            public Dictionary<string, int> CountryCount { get; } = new();
            public string PeakHour { get; set; } = string.Empty;
            public Dictionary<string, int>? TopFailureReasons { get; set; }
            public Dictionary<string, int>? TopApplications { get; set; }
        }

        private class SuspiciousActivity
        {
            public string? SignInId { get; set; }
            public string? UserPrincipalName { get; set; }
            public DateTimeOffset Timestamp { get; set; }public List<string> Reasons { get; set; } = new();
            public string RiskLevel { get; set; } = string.Empty;
            public string? IpAddress { get; set; }
            public string? Application { get; set; }
        }

        #endregion
    }
}
