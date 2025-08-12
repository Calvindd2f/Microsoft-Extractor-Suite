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

namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    [Cmdlet(VerbsCommon.Get, "Users")]
    [OutputType(typeof(UserInfo))]
    public class GetUsersCmdlet : AsyncBaseCmdlet
    {
        [Parameter]
        public string[]? UserIds { get; set; }

        [Parameter]
        public string OutputFormat { get; set; } = "CSV";

        [Parameter]
        public SwitchParameter IncludeGuests { get; set; }

        [Parameter]
        public SwitchParameter IncludeDisabled { get; set; }

        protected override void ProcessRecord()
        {
            if (!RequireGraphConnection())
            {
                return;
            }

            var users = RunAsyncOperation(GetUsersAsync, "Get Users");

            if (!Async.IsPresent && users != null)
            {
                foreach (var user in users)
                {
                    WriteObject(user);
                }
            }
        }

        private async Task<List<UserInfo>> GetUsersAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            var graphClient = AuthManager.GraphClient
                ?? throw new InvalidOperationException("Graph client not initialized");

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

                if (!IncludeGuests.IsPresent)
                {
                    filters.Add("userType eq 'Member'");
                }

                if (!IncludeDisabled.IsPresent)
                {
                    filters.Add("accountEnabled eq true");
                }

                if (UserIds != null && UserIds.Length > 0)
                {
                    var userFilter = string.Join(" or ",
                        UserIds.Select(u => $"userPrincipalName eq '{u}' or mail eq '{u}'"));
                    filters.Add($"({userFilter})");
                }

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
                            users.Add(MapToUserInfo(user));
                            processedCount++;

                            if (processedCount % 100 == 0)
                            {
                                progress.Report(new Core.AsyncOperations.TaskProgress
                                {
                                    CurrentOperation = $"Processing users",
                                    ItemsProcessed = processedCount,
                                    PercentComplete = -1
                                });
                            }

                            return !cancellationToken.IsCancellationRequested;
                        });

                await pageIterator.IterateAsync(cancellationToken);

                WriteVerboseWithTimestamp($"Retrieved {users.Count} users");

                // Export to file if output directory specified
                if (!string.IsNullOrEmpty(OutputDirectory))
                {
                    await ExportUsersAsync(users, cancellationToken);
                }

                return users;
            }
            catch (ServiceException ex)
            {
                WriteErrorWithTimestamp($"Graph API error: {ex.Message}", ex);
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
            var fileName = Path.Combine(
                OutputDirectory!,
                $"Users_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{OutputFormat.ToLower()}");

            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

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

            WriteVerboseWithTimestamp($"Exported users to {fileName}");
        }
    }

    public class UserInfo
    {
        public string? Id { get; set; }
        public string? DisplayName { get; set; }
        public string? UserPrincipalName { get; set; }
        public string? Mail { get; set; }
        public DateTime? CreatedDateTime { get; set; }
        public DateTime? LastPasswordChangeDateTime { get; set; }
        public bool AccountEnabled { get; set; }
        public string? UserType { get; set; }
        public int LicenseCount { get; set; }
        public DateTime? LastSignInDateTime { get; set; }
        public int DaysSincePasswordChange { get; set; }
    }
}