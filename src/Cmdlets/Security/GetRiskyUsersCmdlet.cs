namespace Microsoft.ExtractorSuite.Cmdlets.Security
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Json;
    using Microsoft.Graph;
    using Microsoft.Graph.Models;


    [Cmdlet(VerbsCommon.Get, "RiskyUsers")]
    [OutputType(typeof(RiskyUserInfo))]
#pragma warning disable SA1600
    public class GetRiskyUsersCmdlet : AsyncBaseCmdlet
#pragma warning restore SA1600
    {
        [Parameter]
#pragma warning disable SA1600
        public string[]? UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public string[]? RiskLevels { get; set; } = new[] { "low", "medium", "high" };
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public string[]? RiskStates { get; set; } = new[] { "atRisk", "confirmedCompromised" };
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeRemediated { get; set; }

        [Parameter]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "CSV";
#pragma warning restore SA1600

#pragma warning disable SA1600
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                return;
            }
#pragma warning restore SA1101

            var riskyUsers = RunAsyncOperation(GetRiskyUsersAsync, "Get Risky Users");

#pragma warning disable SA1101
            if (!Async.IsPresent && riskyUsers != null)
            {
                foreach (var user in riskyUsers)
                {
                    WriteObject(user);
                }
            }
#pragma warning restore SA1101
        }

        private async Task<List<RiskyUserInfo>> GetRiskyUsersAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var graphClient = AuthManager.BetaGraphClient ?? AuthManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");
#pragma warning restore SA1101

            var riskyUsers = new List<RiskyUserInfo>();
            var processedCount = 0;

            try
            {
                // Get risky users configuration
                string? filterExpression = null;

                // Build filter
                var filters = new List<string>();

#pragma warning disable SA1101
                if (RiskLevels != null && RiskLevels.Length > 0)
                {
#pragma warning disable SA1101
                    var riskFilter = string.Join(" or ",
                        RiskLevels.Select(r => $"riskLevel eq '{r}'"));
#pragma warning restore SA1101
                    filters.Add($"({riskFilter})");
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (RiskStates != null && RiskStates.Length > 0 && !IncludeRemediated.IsPresent)
                {
#pragma warning disable SA1101
                    var stateFilter = string.Join(" or ",
                        RiskStates.Select(s => $"riskState eq '{s}'"));
#pragma warning restore SA1101
                    filters.Add($"({stateFilter})");
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (UserIds != null && UserIds.Length > 0)
                {
#pragma warning disable SA1101
                    var userFilter = string.Join(" or ",
                        UserIds.Select(u => $"userPrincipalName eq '{u}'"));
#pragma warning restore SA1101
                    filters.Add($"({userFilter})");
                }
#pragma warning restore SA1101

                if (filters.Any())
                {
                    filterExpression = string.Join(" and ", filters);
                }

                // Get risky users
                var response = await graphClient.IdentityProtection.RiskyUsers
                    .GetAsync(requestConfiguration => {
                        requestConfiguration.QueryParameters.Top = 999;
                        if (!string.IsNullOrEmpty(filterExpression))
                        {
                            requestConfiguration.QueryParameters.Filter = filterExpression;
                        }
                    }, cancellationToken);

                if (response?.Value != null)
                {
                    foreach (var riskyUser in response.Value)
                    {
                        // Get risk history for each user
#pragma warning disable SA1101
                        var history = await GetRiskHistoryAsync(graphClient, riskyUser.Id, cancellationToken);
#pragma warning restore SA1101

                        riskyUsers.Add(new RiskyUserInfo
                        {
                            Id = riskyUser.Id,
                            UserPrincipalName = riskyUser.UserPrincipalName,
                            UserDisplayName = riskyUser.UserDisplayName,
                            RiskLevel = riskyUser.RiskLevel?.ToString(),
                            RiskState = riskyUser.RiskState?.ToString(),
                            RiskDetail = riskyUser.RiskDetail?.ToString(),
                            RiskLastUpdatedDateTime = riskyUser.RiskLastUpdatedDateTime?.DateTime,
                            IsDeleted = riskyUser.IsDeleted ?? false,
                            IsProcessing = riskyUser.IsProcessing ?? false,
                            RiskHistory = history
                        });

                        processedCount++;

                        if (processedCount % 10 == 0)
                        {
                            progress.Report(new Core.AsyncOperations.TaskProgress
                            {
                                CurrentOperation = $"Processing risky users",
                                ItemsProcessed = processedCount,
                                PercentComplete = -1
                            });
                        }
                    }
                }

                WriteVerboseWithTimestamp($"Retrieved {riskyUsers.Count} risky users");

                // Export to file if output directory specified
#pragma warning disable SA1101
                if (!string.IsNullOrEmpty(OutputDirectory))
                {
#pragma warning disable SA1101
                    await ExportRiskyUsersAsync(riskyUsers, cancellationToken);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                return riskyUsers;
            }
            catch (Microsoft.Graph.ServiceException ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Graph API error: {ex.Message}", ex);
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task<List<RiskHistoryItem>> GetRiskHistoryAsync(
            GraphServiceClient graphClient,
            string userId,
            CancellationToken cancellationToken)
        {
            var history = new List<RiskHistoryItem>();

            try
            {
                var historyResponse = await graphClient.IdentityProtection.RiskyUsers[userId].History
                    .GetAsync(requestConfiguration => {
                        requestConfiguration.QueryParameters.Top = 50;
                    }, cancellationToken);

                if (historyResponse?.Value != null)
                {
                    foreach (var item in historyResponse.Value)
                    {
                        history.Add(new RiskHistoryItem
                        {
                            RiskLevel = item.RiskLevel?.ToString(),
                            RiskState = item.RiskState?.ToString(),
                            RiskDetail = item.RiskDetail?.ToString(),
                            Activity = string.Empty, // RiskEventTypes is not available on RiskyUserHistoryItem
                            InitiatedBy = item.InitiatedBy,
                            DateTime = item.RiskLastUpdatedDateTime
                        });
                    }
                }
            }
            catch (Microsoft.Graph.ServiceException)
            {
                // History might not be available for all users
            }

            return history;
        }

        private async Task ExportRiskyUsersAsync(
            List<RiskyUserInfo> riskyUsers,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var fileName = Path.Combine(
                OutputDirectory!,
                $"RiskyUsers_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{OutputFormat.ToLower()}");
#pragma warning restore SA1101

            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

#pragma warning disable SA1101
            if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.Create(fileName);
                using var processor = new HighPerformanceJsonProcessor();
                await processor.SerializeAsync(stream, riskyUsers, true, cancellationToken);
            }
            else // CSV - flatten the data
            {
                var flattenedData = riskyUsers.Select(u => new
                {
                    u.Id,
                    u.UserPrincipalName,
                    u.UserDisplayName,
                    u.RiskLevel,
                    u.RiskState,
                    u.RiskDetail,
                    u.RiskLastUpdatedDateTime,
                    u.IsDeleted,
                    u.IsProcessing,
                    HistoryCount = u.RiskHistory.Count,
                    LastHistoryActivity = u.RiskHistory.FirstOrDefault()?.Activity
                });

                using var writer = new StreamWriter(fileName);
                using var csv = new CsvHelper.CsvWriter(writer, System.Globalization.CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(flattenedData);
            }
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Exported risky users to {fileName}");
        }
    }

#pragma warning disable SA1600
    public class RiskyUserInfo
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string? Id { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? UserPrincipalName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? UserDisplayName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? RiskLevel { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? RiskState { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? RiskDetail { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? RiskLastUpdatedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsDeleted { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsProcessing { get; set; }
        public List<RiskHistoryItem> RiskHistory { get; set; } = new();
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class RiskHistoryItem
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string? RiskLevel { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? RiskState { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? RiskDetail { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Activity { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? InitiatedBy { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTimeOffset? DateTime { get; set; }
#pragma warning restore SA1600
    }
}
