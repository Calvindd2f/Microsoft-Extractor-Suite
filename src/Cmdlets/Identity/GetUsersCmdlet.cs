namespace Microsoft.ExtractorSuite.Cmdlets.Identity
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


    [Cmdlet(VerbsCommon.Get, "Users")]
    [OutputType(typeof(UserInfo))]
#pragma warning disable SA1600
    public class GetUsersCmdlet : AsyncBaseCmdlet
#pragma warning restore SA1600
    {
        [Parameter]
#pragma warning disable SA1600
        public string[]? UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "CSV";
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeGuests { get; set; }

        [Parameter]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public SwitchParameter IncludeDisabled { get; set; }
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                return;
            }
#pragma warning restore SA1101

            var users = RunAsyncOperation(GetUsersAsync, "Get Users");

#pragma warning disable SA1101
            if (!Async.IsPresent && users != null)
            {
                foreach (var user in users)
                {
                    WriteObject(user);
                }
            }
#pragma warning restore SA1101

            // Process any queued writes from async operations
#pragma warning disable SA1101
            ProcessQueuedWrites();
#pragma warning restore SA1101
        }

        private async Task<List<UserInfo>> GetUsersAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var graphClient = AuthManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");
#pragma warning restore SA1101

            var users = new List<UserInfo>();
            var processedCount = 0;

            try
            {
                // Build query with modern SDK patterns
                var queryOptions = new List<string>
                {
                    "$select=id,displayName,userPrincipalName,mail,createdDateTime,lastPasswordChangeDateTime,accountEnabled,userType,assignedLicenses,signInActivity",
                    "$top=999"
                };

                // Apply filters
                var filters = new List<string>();

#pragma warning disable SA1101
                if (!IncludeGuests.IsPresent)
                {
                    filters.Add("userType eq 'Member'");
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (!IncludeDisabled.IsPresent)
                {
                    filters.Add("accountEnabled eq true");
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (UserIds != null && UserIds.Length > 0)
                {
#pragma warning disable SA1101
                    var userFilter = string.Join(" or ",
                        UserIds.Select(u => $"userPrincipalName eq '{u}' or mail eq '{u}'"));
#pragma warning restore SA1101
                    filters.Add($"({userFilter})");
                }
#pragma warning restore SA1101

                if (filters.Any())
                {
                    queryOptions.Add($"$filter={string.Join(" and ", filters)}");
                }

                // Configure and get users
                var usersResponse = await graphClient.Users.GetAsync(requestConfiguration =>
                {
                    requestConfiguration.QueryParameters.Select = new string[]
                    {
                        "id", "displayName", "userPrincipalName", "mail", "createdDateTime",
                        "lastPasswordChangeDateTime", "accountEnabled", "userType",
                        "assignedLicenses", "signInActivity"
                    };
                    requestConfiguration.QueryParameters.Top = 999;

                    if (filters.Any())
                    {
                        requestConfiguration.QueryParameters.Filter = string.Join(" and ", filters);
                    }
                }, cancellationToken);

                // Process all pages using pagination
                var pageIterator = PageIterator<User, UserCollectionResponse>
                    .CreatePageIterator(
                        graphClient,
                        usersResponse,
                        (user) =>
                        {
#pragma warning disable SA1101
                            users.Add(MapToUserInfo(user));
#pragma warning restore SA1101
                            processedCount++;

                            if (processedCount % 100 == 0)
                            {
                                var count = processedCount;
                                progress.Report(new Core.AsyncOperations.TaskProgress
                                {
                                    CurrentOperation = $"Processing users",
                                    ItemsProcessed = count,
                                    PercentComplete = -1
                                });
                            }

                            return !cancellationToken.IsCancellationRequested;
                        });

                await pageIterator.IterateAsync(cancellationToken);

                var userCount = users.Count;
                QueueWrite(() => WriteVerboseWithTimestamp($"Retrieved {userCount} users"));

                // Export to file if output directory specified
#pragma warning disable SA1101
                if (!string.IsNullOrEmpty(OutputDirectory))
                {
#pragma warning disable SA1101
                    await ExportUsersAsync(users, cancellationToken);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                return users;
            }
            catch (ServiceException ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Graph API error: {ex.Message}", ex);
#pragma warning restore SA1101
                throw;
            }
        }

        private UserInfo MapToUserInfo(User user)
        {
            return new UserInfo
            {
                Id = user.Id,
                DisplayName = user.DisplayName,
                UserPrincipalName = user.UserPrincipalName,
                Mail = user.Mail,
                CreatedDateTime = user.CreatedDateTime?.DateTime,
                LastPasswordChangeDateTime = user.LastPasswordChangeDateTime?.DateTime,
                AccountEnabled = user.AccountEnabled ?? false,
                UserType = user.UserType,
                LicenseCount = user.AssignedLicenses?.Count ?? 0,
                LastSignInDateTime = user.SignInActivity?.LastSignInDateTime?.DateTime,
                DaysSincePasswordChange = user.LastPasswordChangeDateTime.HasValue
                    ? (DateTime.UtcNow - user.LastPasswordChangeDateTime.Value.DateTime).Days
                    : -1
            };
        }

        private async Task ExportUsersAsync(List<UserInfo> users, CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var fileName = Path.Combine(
                OutputDirectory!,
                $"Users_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{OutputFormat.ToLower()}");
#pragma warning restore SA1101

            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

#pragma warning disable SA1101
            if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.Create(fileName);
                using var processor = new HighPerformanceJsonProcessor();
                await processor.SerializeAsync(stream, users, true, cancellationToken);
            }
            else // CSV
            {
                using var writer = new StreamWriter(fileName);
                using var csv = new CsvHelper.CsvWriter(writer, System.Globalization.CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(users);
            }
#pragma warning restore SA1101

            QueueWrite(() => WriteVerboseWithTimestamp($"Exported users to {fileName}"));
        }
    }

#pragma warning disable SA1600
    public class UserInfo
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string? Id { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? DisplayName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? UserPrincipalName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Mail { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? CreatedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? LastPasswordChangeDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool AccountEnabled { get; set; }
        public string? UserType { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int LicenseCount { get; set; }
        public DateTime? LastSignInDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        public int DaysSincePasswordChange { get; set; }
    }
}
