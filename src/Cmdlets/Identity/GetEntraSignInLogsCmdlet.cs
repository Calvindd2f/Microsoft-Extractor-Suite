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

namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
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
        public DateTime? StartDate { get; set; }

        [Parameter(
            HelpMessage = "End date for sign-in logs. Default: Now")]
        public DateTime? EndDate { get; set; }

        [Parameter(
            HelpMessage = "Filter by user principal name(s)")]
        public string[]? UserPrincipalNames { get; set; }

        [Parameter(
            HelpMessage = "Filter by application ID(s)")]
        public string[]? ApplicationIds { get; set; }

        [Parameter(
            HelpMessage = "Filter by IP address")]
        public string? IPAddress { get; set; }

        [Parameter(
            HelpMessage = "Filter by sign-in status: Success, Failure, All")]
        [ValidateSet("Success", "Failure", "All")]
        public string StatusFilter { get; set; } = "All";

        [Parameter(
            HelpMessage = "Filter by risk level: None, Low, Medium, High, All")]
        [ValidateSet("None", "Low", "Medium", "High", "All")]
        public string RiskLevel { get; set; } = "All";

        [Parameter(
            HelpMessage = "Filter by conditional access status")]
        [ValidateSet("Success", "Failure", "NotApplied", "All")]
        public string ConditionalAccessStatus { get; set; } = "All";

        [Parameter(
            HelpMessage = "Include only interactive sign-ins")]
        public SwitchParameter InteractiveOnly { get; set; }

        [Parameter(
            HelpMessage = "Include only risky sign-ins")]
        public SwitchParameter RiskyOnly { get; set; }

        [Parameter(
            HelpMessage = "Include guest user sign-ins")]
        public SwitchParameter IncludeGuests { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results")]
        public string OutputDir { get; set; } = Path.Combine("Output", "EntraSignInLogs");

        [Parameter(
            HelpMessage = "Output format: CSV, JSON, JSONL")]
        [ValidateSet("CSV", "JSON", "JSONL")]
        public string OutputFormat { get; set; } = "JSONL";

        [Parameter(
            HelpMessage = "Maximum parallel requests")]
        [ValidateRange(1, 20)]
        public int MaxParallelRequests { get; set; } = 10;

        [Parameter(
            HelpMessage = "Include detailed analysis")]
        public SwitchParameter DetailedAnalysis { get; set; }

        [Parameter(
            HelpMessage = "Export suspicious activities separately")]
        public SwitchParameter ExportSuspicious { get; set; }

        #endregion

        #region Private Fields

        private GraphServiceClient? _graphClient;
        private readonly Statistics _stats = new();
        private readonly List<SignInLog> _allSignIns = new();
        private readonly List<SuspiciousActivity> _suspiciousActivities = new();
        private string _sessionId = string.Empty;
        private bool _csvHeaderWritten;

        #endregion

        protected override void BeginProcessing()
        {
            base.BeginProcessing();

            if (!RequireGraphConnection())
            {
                throw new PSInvalidOperationException(
                    "Not connected to Microsoft Graph. Please run Connect-M365 -Service Graph first.");
            }

            _graphClient = AuthManager.GraphClient;
            _sessionId = Guid.NewGuid().ToString("N").Substring(0, 8);

            // Set default dates (Graph API limitation: max 30 days for sign-in logs)
            EndDate ??= DateTime.UtcNow;
            StartDate ??= EndDate.Value.AddDays(-30);

            // Validate date range
            if ((EndDate.Value - StartDate.Value).TotalDays > 30)
            {
                WriteWarning("Sign-in logs are limited to 30 days. Adjusting start date.");
                StartDate = EndDate.Value.AddDays(-30);
            }

            // Create output directory
            if (!Directory.Exists(OutputDir))
            {
                Directory.CreateDirectory(OutputDir);
            }

            Logger?.LogInfo("=== Starting Entra Sign-In Logs Collection ===");
            Logger?.LogInfo($"Date Range: {StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}");
            Logger?.LogInfo($"Output Format: {OutputFormat}");
            Logger?.LogInfo($"Output Directory: {OutputDir}");

            if (Logger?.CurrentLevel == LogLevel.Debug)
            {
                Logger.LogDebug($"Session ID: {_sessionId}");
                Logger.LogDebug($"Status Filter: {StatusFilter}");
                Logger.LogDebug($"Risk Level: {RiskLevel}");
                Logger.LogDebug($"Interactive Only: {InteractiveOnly}");
                Logger.LogDebug($"Max Parallel Requests: {MaxParallelRequests}");
            }
        }

        protected override void ProcessRecord()
        {
            try
            {
                var startTime = DateTime.UtcNow;

                WriteHost("Retrieving Entra sign-in logs...\n", ConsoleColor.Cyan);

                // Build filter query
                var filter = BuildFilterQuery();

                // Process sign-in logs
                RunAsync(ProcessSignInLogsAsync(filter));

                var duration = DateTime.UtcNow - startTime;

                // Analyze results if requested
                if (DetailedAnalysis)
                {
                    PerformDetailedAnalysis();
                }

                // Export results
                ExportResults();

                // Export suspicious activities if requested
                if (ExportSuspicious && _suspiciousActivities.Any())
                {
                    ExportSuspiciousActivities();
                }

                // Display statistics
                DisplayStatistics(duration);
            }
            catch (Exception ex)
            {
                Logger?.WriteErrorWithTimestamp($"Error processing sign-in logs: {ex.Message}", ex);
                WriteErrorWithTimestamp($"Failed to process sign-in logs: {ex.Message}", ex);
            }
        }

        private async Task ProcessSignInLogsAsync(string filter)
        {
            if (_graphClient == null)
            {
                throw new InvalidOperationException("Graph client not initialized");
            }

            try
            {
                var request = _graphClient.AuditLogs.SignIns
                    .Request()
                    .Filter(filter)
                    .Select("id,createdDateTime,userPrincipalName,userId,userDisplayName,appId,appDisplayName," +
                           "ipAddress,clientAppUsed,correlationId,conditionalAccessStatus,isInteractive," +
                           "riskDetail,riskLevelAggregated,riskLevelDuringSignIn,riskState,riskEventTypes," +
                           "riskEventTypes_v2,status,deviceDetail,location,appliedConditionalAccessPolicies," +
                           "authenticationMethodsUsed,mfaDetail,tokenIssuerType,resourceDisplayName")
                    .OrderBy("createdDateTime desc")
                    .Top(999); // Max page size for Graph API

                var pageCount = 0;

                do
                {
                    var page = await request.GetAsync(CancellationToken);
                    pageCount++;

                    if (page?.CurrentPage != null)
                    {
                        foreach (var signIn in page.CurrentPage)
                        {
                            var log = ConvertToSignInLog(signIn);
                            ProcessSignInLog(log);
                            _allSignIns.Add(log);
                        }

                        UpdateProgress(pageCount, _allSignIns.Count);
                    }

                    request = page?.NextPageRequest;

                    // Adaptive delay to avoid throttling
                    if (request != null)
                    {
                        await Task.Delay(100, CancellationToken);
                    }

                } while (request != null && !CancellationToken.IsCancellationRequested);

                WriteProgressSafe("Processing Sign-In Logs", "Complete", 100);
            }
            catch (ServiceException ex)
            {
                Logger?.WriteErrorWithTimestamp($"Graph API error: {ex.Message}", ex);
                throw new PSInvalidOperationException($"Failed to retrieve sign-in logs: {ex.Message}", ex);
            }
        }

        private SignInLog ConvertToSignInLog(Microsoft.Graph.SignIn graphSignIn)
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
                RiskEventTypes = graphSignIn.RiskEventTypes?.ToList(),
                RiskEventTypesV2 = graphSignIn.RiskEventTypes?.ToList(), // Map to v2 as well
                Status = graphSignIn.Status != null ? new SignInStatus
                {
                    ErrorCode = graphSignIn.Status.ErrorCode ?? 0,
                    FailureReason = graphSignIn.Status.FailureReason,
                    AdditionalDetails = graphSignIn.Status.AdditionalDetails
                } : null,
                DeviceDetail = graphSignIn.DeviceDetail != null ? new DeviceDetail
                {
                    DeviceId = graphSignIn.DeviceDetail.DeviceId,
                    DisplayName = graphSignIn.DeviceDetail.DisplayName,
                    OperatingSystem = graphSignIn.DeviceDetail.OperatingSystem,
                    Browser = graphSignIn.DeviceDetail.Browser,
                    IsCompliant = graphSignIn.DeviceDetail.IsCompliant,
                    IsManaged = graphSignIn.DeviceDetail.IsManaged,
                    TrustType = graphSignIn.DeviceDetail.TrustType
                } : null,
                Location = graphSignIn.Location != null ? new SignInLocation
                {
                    City = graphSignIn.Location.City,
                    State = graphSignIn.Location.State,
                    CountryOrRegion = graphSignIn.Location.CountryOrRegion,
                    GeoCoordinates = graphSignIn.Location.GeoCoordinates != null ? new GeoCoordinates
                    {
                        Latitude = graphSignIn.Location.GeoCoordinates.Latitude,
                        Longitude = graphSignIn.Location.GeoCoordinates.Longitude
                    } : null
                } : null
            };
        }

        private void ProcessSignInLog(SignInLog log)
        {
            _stats.TotalSignIns++;

            // Count by status
            if (log.Status?.ErrorCode == 0)
            {
                _stats.SuccessfulSignIns++;
            }
            else
            {
                _stats.FailedSignIns++;
            }

            // Count interactive
            if (log.IsInteractive)
            {
                _stats.InteractiveSignIns++;
            }

            // Count risky
            if (!string.IsNullOrEmpty(log.RiskLevelAggregated) &&
                log.RiskLevelAggregated != "none" &&
                log.RiskLevelAggregated != "hidden")
            {
                _stats.RiskySignIns++;
            }

            // Count guest sign-ins
            if (log.UserType == "Guest")
            {
                _stats.GuestSignIns++;
            }

            // Check for suspicious patterns
            CheckForSuspiciousActivity(log);

            // Track unique users and applications
            if (!string.IsNullOrEmpty(log.UserPrincipalName))
            {
                _stats.UniqueUsers.Add(log.UserPrincipalName);
            }

            if (!string.IsNullOrEmpty(log.AppId))
            {
                _stats.UniqueApplications.Add(log.AppId);
            }

            // Track locations
            if (log.Location?.CountryOrRegion != null)
            {
                var currentCount = _stats.CountryCount.TryGetValue(log.Location.CountryOrRegion, out var count) ? count : 0;
                _stats.CountryCount[log.Location.CountryOrRegion] = currentCount + 1;
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
            }
        }

        private string BuildFilterQuery()
        {
            var filters = new List<string>();

            // Date filter
            filters.Add($"createdDateTime ge {StartDate:yyyy-MM-ddTHH:mm:ssZ} and createdDateTime le {EndDate:yyyy-MM-ddTHH:mm:ssZ}");

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
            WriteHost("\n=== Performing Detailed Analysis ===\n", ConsoleColor.Cyan);

            // Time-based analysis
            var hourlyDistribution = _allSignIns
                .GroupBy(s => s.CreatedDateTime.Hour)
                .OrderBy(g => g.Key)
                .ToDictionary(g => g.Key, g => g.Count());

            // Find peak hours
            var peakHour = hourlyDistribution.OrderByDescending(kvp => kvp.Value).FirstOrDefault();
            _stats.PeakHour = $"{peakHour.Key:00}:00 ({peakHour.Value} sign-ins)";

            // Failed sign-in analysis
            var failedSignIns = _allSignIns.Where(s => s.Status?.ErrorCode != 0).ToList();
            if (failedSignIns.Any())
            {
                var topFailureReasons = failedSignIns
                    .GroupBy(s => s.Status?.FailureReason ?? "Unknown")
                    .OrderByDescending(g => g.Count())
                    .Take(5)
                    .ToDictionary(g => g.Key, g => g.Count());

                _stats.TopFailureReasons = topFailureReasons;
            }

            // Application usage analysis
            var topApps = _allSignIns
                .Where(s => !string.IsNullOrEmpty(s.AppDisplayName))
                .GroupBy(s => s.AppDisplayName)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToDictionary(g => g.Key!, g => g.Count());

            _stats.TopApplications = topApps;
        }

        private void ExportResults()
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            var filename = Path.Combine(OutputDir, $"SignInLogs_{_sessionId}_{timestamp}.{OutputFormat.ToLower()}");

            switch (OutputFormat.ToUpper())
            {
                case "CSV":
                    ExportToCsv(filename);
                    break;
                case "JSON":
                    ExportToJson(filename);
                    break;
                case "JSONL":
                    ExportToJsonl(filename);
                    break;
            }

            WriteHost($"\nExported {_allSignIns.Count} sign-in logs to: {filename}\n", ConsoleColor.Green);
        }

        private void ExportToCsv(string filename)
        {
            using var writer = new StreamWriter(filename, false, Encoding.UTF8);

            // Write header
            writer.WriteLine("Id,Timestamp,UserPrincipalName,UserDisplayName,AppId,AppDisplayName,IPAddress," +
                           "Status,ErrorCode,FailureReason,RiskLevel,IsInteractive,ConditionalAccess," +
                           "Location,DeviceOS,Browser,IsCompliant,IsManaged");

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
        }

        private void ExportToJson(string filename)
        {
            var output = new
            {
                ExportDate = DateTime.UtcNow,
                DateRange = new { Start = StartDate, End = EndDate },
                TotalRecords = _allSignIns.Count,
                Statistics = _stats,
                SignInLogs = _allSignIns.OrderBy(l => l.CreatedDateTime)
            };

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

            foreach (var log in _allSignIns.OrderBy(l => l.CreatedDateTime))
            {
                var json = JsonSerializer.Serialize(log, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });
                writer.WriteLine(json);
            }
        }

        private void ExportSuspiciousActivities()
        {
            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            var filename = Path.Combine(OutputDir, $"SuspiciousSignIns_{_sessionId}_{timestamp}.json");

            var output = new
            {
                ExportDate = DateTime.UtcNow,
                TotalSuspicious = _suspiciousActivities.Count,
                Activities = _suspiciousActivities.OrderByDescending(a => a.Timestamp)
            };

            var json = JsonSerializer.Serialize(output, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            File.WriteAllText(filename, json, Encoding.UTF8);

            WriteHost($"Exported {_suspiciousActivities.Count} suspicious activities to: {filename}\n",
                ConsoleColor.Yellow);
        }

        private void UpdateProgress(int pageCount, int totalRecords)
        {
            WriteProgressSafe(
                "Retrieving Sign-In Logs",
                $"Page {pageCount} - Total records: {totalRecords:N0}",
                -1);

            WriteVerboseWithTimestamp($"Processed page {pageCount}: {totalRecords} total records");
        }

        private void DisplayStatistics(TimeSpan duration)
        {
            WriteHost("\n=== Sign-In Logs Collection Summary ===\n", ConsoleColor.Cyan);
            WriteHost($"Duration: {duration:mm\\:ss}\n");
            WriteHost($"Total Sign-Ins: {_stats.TotalSignIns:N0}\n");
            WriteHost($"  - Successful: {_stats.SuccessfulSignIns:N0}\n", ConsoleColor.Green);
            WriteHost($"  - Failed: {_stats.FailedSignIns:N0}\n", ConsoleColor.Red);

            if (_stats.InteractiveSignIns > 0)
            {
                WriteHost($"  - Interactive: {_stats.InteractiveSignIns:N0}\n");
            }

            if (_stats.RiskySignIns > 0)
            {
                WriteHost($"  - Risky: {_stats.RiskySignIns:N0}\n", ConsoleColor.Yellow);
            }

            if (_stats.GuestSignIns > 0)
            {
                WriteHost($"  - Guest Users: {_stats.GuestSignIns:N0}\n");
            }

            WriteHost($"\nUnique Users: {_stats.UniqueUsers.Count:N0}\n");
            WriteHost($"Unique Applications: {_stats.UniqueApplications.Count:N0}\n");

            if (_stats.CountryCount.Any())
            {
                WriteHost($"\nTop Locations:\n");
                foreach (var country in _stats.CountryCount.OrderByDescending(c => c.Value).Take(5))
                {
                    WriteHost($"  {country.Key}: {country.Value:N0}\n");
                }
            }

            if (DetailedAnalysis)
            {
                WriteHost($"\nPeak Hour: {_stats.PeakHour}\n");

                if (_stats.TopFailureReasons?.Any() == true)
                {
                    WriteHost($"\nTop Failure Reasons:\n", ConsoleColor.Red);
                    foreach (var reason in _stats.TopFailureReasons.Take(3))
                    {
                        WriteHost($"  {reason.Key}: {reason.Value:N0}\n");
                    }
                }

                if (_stats.TopApplications?.Any() == true)
                {
                    WriteHost($"\nTop Applications:\n");
                    foreach (var app in _stats.TopApplications.Take(5))
                    {
                        WriteHost($"  {app.Key}: {app.Value:N0}\n");
                    }
                }
            }

            if (_suspiciousActivities.Any())
            {
                WriteHost($"\n⚠ Suspicious Activities Detected: {_suspiciousActivities.Count}\n",
                    ConsoleColor.Yellow);
            }

            var recordsPerSecond = duration.TotalSeconds > 0 ? _stats.TotalSignIns / duration.TotalSeconds : 0;
            WriteHost($"\nProcessing Rate: {recordsPerSecond:N0} records/second\n");
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
                Host.UI.Write(color.Value, Host.UI.RawUI.BackgroundColor, message);
            }
            else
            {
                Host.UI.Write(message);
            }
        }

        #region Helper Classes

        private class Statistics
        {
            public int TotalSignIns { get; set; }
            public int SuccessfulSignIns { get; set; }
            public int FailedSignIns { get; set; }
            public int InteractiveSignIns { get; set; }
            public int RiskySignIns { get; set; }
            public int GuestSignIns { get; set; }
            public HashSet<string> UniqueUsers { get; } = new();
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
            public DateTimeOffset Timestamp { get; set; }
            public List<string> Reasons { get; set; } = new();
            public string RiskLevel { get; set; } = string.Empty;
            public string? IpAddress { get; set; }
            public string? Application { get; set; }
        }

        #endregion
    }
}