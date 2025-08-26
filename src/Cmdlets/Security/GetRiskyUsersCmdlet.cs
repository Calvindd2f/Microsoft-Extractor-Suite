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

    public class GetRiskyUsersCmdlet : AsyncBaseCmdlet

    {
        [Parameter]

        public string[]? UserIds { get; set; }


        [Parameter]

        public string[]? RiskLevels { get; set; } = new[] { "low", "medium", "high" };


        [Parameter]

        public string[]? RiskStates { get; set; } = new[] { "atRisk", "confirmedCompromised" };


        [Parameter]


        public SwitchParameter IncludeRemediated { get; set; }

        [Parameter]

        public string OutputFormat { get; set; } = "CSV";



        protected override void ProcessRecord()

        {

            if (!RequireGraphConnection())
            {
                return;
            }


            var riskyUsers = RunAsyncOperation(GetRiskyUsersAsync, "Get Risky Users");


            if (!Async.IsPresent && riskyUsers != null)
            {
                foreach (var user in riskyUsers)
                {
                    WriteObject(user);
                }
            }

        }

        private async Task<List<RiskyUserInfo>> GetRiskyUsersAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {

            var graphClient = AuthManager.BetaGraphClient ?? AuthManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");


            var riskyUsers = new List<RiskyUserInfo>();
            var processedCount = 0;

            try
            {
                // Get risky users configuration
                string? filterExpression = null;

                // Build filter
                var filters = new List<string>();


                if (RiskLevels != null && RiskLevels.Length > 0)
                {

                    var riskFilter = string.Join(" or ",
                        RiskLevels.Select(r => $"riskLevel eq '{r}'"));

                    filters.Add($"({riskFilter})");
                }



                if (RiskStates != null && RiskStates.Length > 0 && !IncludeRemediated.IsPresent)
                {

                    var stateFilter = string.Join(" or ",
                        RiskStates.Select(s => $"riskState eq '{s}'"));

                    filters.Add($"({stateFilter})");
                }



                if (UserIds != null && UserIds.Length > 0)
                {

                    var userFilter = string.Join(" or ",
                        UserIds.Select(u => $"userPrincipalName eq '{u}'"));

                    filters.Add($"({userFilter})");
                }


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

                        var history = await GetRiskHistoryAsync(graphClient, riskyUser.Id, cancellationToken);


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

                if (!string.IsNullOrEmpty(OutputDirectory))
                {

                    await ExportRiskyUsersAsync(riskyUsers, cancellationToken);

                }


                return riskyUsers;
            }
            catch (Microsoft.Graph.ServiceException ex)
            {

                WriteErrorWithTimestamp($"Graph API error: {ex.Message}", ex);

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

            var fileName = Path.Combine(
                OutputDirectory!,
                $"RiskyUsers_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{OutputFormat.ToLower()}");


            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);


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


            WriteVerboseWithTimestamp($"Exported risky users to {fileName}");
        }
    }


    public class RiskyUserInfo

    {

        public string? Id { get; set; }


        public string? UserPrincipalName { get; set; }


        public string? UserDisplayName { get; set; }


        public string? RiskLevel { get; set; }


        public string? RiskState { get; set; }


        public string? RiskDetail { get; set; }


        public DateTime? RiskLastUpdatedDateTime { get; set; }




        public bool IsDeleted { get; set; }


        public bool IsProcessing { get; set; }
        public List<RiskHistoryItem> RiskHistory { get; set; } = new();

    }


    public class RiskHistoryItem

    {

        public string? RiskLevel { get; set; }


        public string? RiskState { get; set; }


        public string? RiskDetail { get; set; }


        public string? Activity { get; set; }


        public string? InitiatedBy { get; set; }


        public DateTimeOffset? DateTime { get; set; }

    }
}
