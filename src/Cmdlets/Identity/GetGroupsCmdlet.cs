namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;
    using CsvHelper;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Json;
    using Microsoft.Graph;
    using Microsoft.Graph.Models;


    /// <summary>
    /// Retrieves all groups, group members, and dynamic groups from Microsoft Entra ID.
    /// Provides comprehensive group information including basic properties, membership details, and dynamic group rules.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "Groups")]
    [OutputType(typeof(GroupInfo))]
    public class GetGroupsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "Type of group data to collect")]
        [ValidateSet("All", "Groups", "Members", "Dynamic")]
#pragma warning disable SA1600
        public string CollectionType { get; set; } = "All";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Include group membership information")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeMembers { get; set; }

        [Parameter(HelpMessage = "Include dynamic group rules and processing state")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter IncludeDynamicRules { get; set; }

        [Parameter(HelpMessage = "Output format for the results. Default: CSV")]
        [ValidateSet("CSV", "JSON")]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "CSV";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Text encoding for the output file. Default: UTF8")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

#pragma warning disable SA1600
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
            var results = RunAsyncOperation(GetGroupsAsync, "Getting Groups");

#pragma warning disable SA1101
            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
#pragma warning restore SA1101
        }

        private async Task<List<GroupInfo>> GetGroupsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Groups Collection");

#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Not connected to Microsoft Graph. Please run Connect-M365 first.");
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            var graphClient = AuthManager.GraphClient!;
#pragma warning restore SA1101

            var summary = new GroupsSummary
            {
                StartTime = DateTime.UtcNow
            };

            var results = new List<GroupInfo>();

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Retrieving groups",
                PercentComplete = 10
            });

            try
            {
                WriteVerboseWithTimestamp("Fetching all groups from Microsoft Graph...");

                // Get all groups
                var groups = await graphClient.Groups
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Top = 999;
                        requestConfiguration.QueryParameters.Select = new[]
                        {
                            "id", "displayName", "description", "mail", "mailEnabled", "mailNickname",
                            "securityEnabled", "groupTypes", "createdDateTime", "renewedDateTime",
                            "expirationDateTime", "visibility", "onPremisesSyncEnabled",
                            "onPremisesLastSyncDateTime", "securityIdentifier", "isManagementRestricted",
                            "membershipRule", "membershipRuleProcessingState", "classification",
                            "hideFromAddressLists", "hideFromOutlookClients", "isAssignableToRole",
                            "preferredDataLocation", "proxyAddresses"
                        };
                    }, cancellationToken);

                if (groups?.Value == null)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp("No groups found or insufficient permissions");
#pragma warning restore SA1101
                    return results;
                }

                WriteVerboseWithTimestamp($"Found {groups.Value.Count} groups");
                summary.TotalGroups = groups.Value.Count;

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Processing groups",
                    PercentComplete = 30
                });

                var processedCount = 0;

                // Process each group based on collection type
                foreach (var group in groups.Value)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    processedCount++;

#pragma warning disable SA1101
                    var groupInfo = await MapGroupToInfoAsync(graphClient, group, cancellationToken);
#pragma warning restore SA1101
                    results.Add(groupInfo);

                    // Update summary statistics
#pragma warning disable SA1101
                    UpdateGroupsSummary(summary, groupInfo);
#pragma warning restore SA1101

                    // Report progress
                    if (processedCount % 25 == 0 || processedCount == groups.Value.Count)
                    {
                        var progressPercent = 30 + (int)((processedCount / (double)groups.Value.Count) * 50);
                        progress.Report(new Core.AsyncOperations.TaskProgress
                        {
                            CurrentOperation = $"Processed {processedCount}/{groups.Value.Count} groups",
                            PercentComplete = progressPercent,
                            ItemsProcessed = processedCount
                        });
                    }
                }

                // Process group members if requested or if collection type is Members/All
#pragma warning disable SA1101
                if (IncludeMembers.IsPresent || CollectionType == "Members" || CollectionType == "All")
                {
                    progress.Report(new Core.AsyncOperations.TaskProgress
                    {
                        CurrentOperation = "Processing group members",
                        PercentComplete = 85
                    });

#pragma warning disable SA1101
                    await ProcessGroupMembersAsync(graphClient, results, cancellationToken);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Exporting results",
                    PercentComplete = 90
                });

                // Export results if output directory is specified
#pragma warning disable SA1101
                if (!string.IsNullOrEmpty(OutputDirectory))
                {
#pragma warning disable SA1101
                    await ExportGroupsAsync(results, summary, cancellationToken);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

                // Log summary
                WriteVerboseWithTimestamp($"Groups Collection Summary:");
                WriteVerboseWithTimestamp($"  Total Groups: {summary.TotalGroups}");
                WriteVerboseWithTimestamp($"  Security Enabled: {summary.SecurityEnabled}");
                WriteVerboseWithTimestamp($"  Mail Enabled: {summary.MailEnabled}");
                WriteVerboseWithTimestamp($"  Dynamic Groups: {summary.DynamicGroups}");
                WriteVerboseWithTimestamp($"  On-Premises Synced: {summary.OnPremisesSynced}");
                WriteVerboseWithTimestamp($"  Processing Time: {summary.ProcessingTime:mm\\:ss}");

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Collection completed",
                    PercentComplete = 100
                });
            }
            catch (ServiceException ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Microsoft Graph API error: {ex.ResponseStatusCode} - {ex.Message}", ex);
#pragma warning restore SA1101
                throw;
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Error retrieving groups: {ex.Message}", ex);
#pragma warning restore SA1101
                throw;
            }

            return results;
        }

        private async Task<GroupInfo> MapGroupToInfoAsync(
            GraphServiceClient graphClient,
            Group group,
            CancellationToken cancellationToken)
        {
            var groupInfo = new GroupInfo
            {
                GroupId = group.Id ?? "",
                DisplayName = group.DisplayName ?? "",
                Description = group.Description ?? "",
                Mail = group.Mail ?? "",
                MailEnabled = group.MailEnabled ?? false,
                MailNickname = group.MailNickname ?? "",
                SecurityEnabled = group.SecurityEnabled ?? false,
                GroupTypes = group.GroupTypes != null ? string.Join(",", group.GroupTypes) : "",
                CreatedDateTime = group.CreatedDateTime?.DateTime,
                RenewedDateTime = group.RenewedDateTime?.DateTime,
                ExpirationDateTime = group.ExpirationDateTime?.DateTime,
                Visibility = group.Visibility ?? "",
                OnPremisesSyncEnabled = group.OnPremisesSyncEnabled ?? false,
                OnPremisesLastSyncDateTime = group.OnPremisesLastSyncDateTime?.DateTime,
                SecurityIdentifier = group.SecurityIdentifier ?? "",
                IsManagementRestricted = false, // Property not available in current Graph API
                MembershipRule = group.MembershipRule ?? "",
                MembershipRuleProcessingState = group.MembershipRuleProcessingState ?? "",
                Classification = group.Classification ?? "",
                HideFromAddressLists = group.HideFromAddressLists ?? false,
                HideFromOutlookClients = group.HideFromOutlookClients ?? false,
                IsAssignableToRole = group.IsAssignableToRole ?? false,
                PreferredDataLocation = group.PreferredDataLocation ?? "",
                ProxyAddresses = group.ProxyAddresses != null ? string.Join(";", group.ProxyAddresses) : "",
                IsDynamic = !string.IsNullOrEmpty(group.MembershipRule)
            };

            return groupInfo;
        }

        private async Task ProcessGroupMembersAsync(
            GraphServiceClient graphClient,
            List<GroupInfo> groups,
            CancellationToken cancellationToken)
        {
            var memberResults = new List<GroupMemberInfo>();

            foreach (var group in groups)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                try
                {
                    WriteVerboseWithTimestamp($"Processing members for group: {group.DisplayName}");

                    var members = await graphClient.Groups[group.GroupId].Members
                        .GetAsync(requestConfiguration =>
                        {
                            requestConfiguration.QueryParameters.Select = new[]
                            {
                                "id", "displayName", "mail", "userPrincipalName"
                            };
                        }, cancellationToken);

                    if (members?.Value != null)
                    {
                        foreach (var member in members.Value)
                        {
                            var memberInfo = new GroupMemberInfo
                            {
                                GroupId = group.GroupId,
                                GroupName = group.DisplayName,
                                MemberId = member.Id ?? "",
                                DisplayName = (member as User)?.DisplayName ?? (member as Group)?.DisplayName ?? "",
                                Mail = (member as User)?.Mail ?? (member as Group)?.Mail ?? "",
                                UserPrincipalName = (member as User)?.UserPrincipalName ?? "",
                                MemberType = member.OdataType?.Contains("user") == true ? "User" :
                                           member.OdataType?.Contains("group") == true ? "Group" : "Unknown"
                            };

                            memberResults.Add(memberInfo);
                        }

                        group.MemberCount = members.Value.Count;
                    }
                }
                catch (ServiceException ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Failed to retrieve members for group {group.DisplayName}: {ex.Message}");
#pragma warning restore SA1101
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Error processing members for group {group.DisplayName}: {ex.Message}");
#pragma warning restore SA1101
                }
            }

            // Export group members separately if we have them
#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(OutputDirectory) && memberResults.Any())
            {
#pragma warning disable SA1101
                await ExportGroupMembersAsync(memberResults, cancellationToken);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        private void UpdateGroupsSummary(GroupsSummary summary, GroupInfo groupInfo)
        {
            if (groupInfo.SecurityEnabled)
                summary.SecurityEnabled++;

            if (groupInfo.MailEnabled)
                summary.MailEnabled++;

            if (groupInfo.IsDynamic)
                summary.DynamicGroups++;

            if (groupInfo.OnPremisesSyncEnabled)
                summary.OnPremisesSynced++;

            if (groupInfo.IsAssignableToRole)
                summary.RoleAssignable++;
        }

        private async Task ExportGroupsAsync(
            List<GroupInfo> groups,
            GroupsSummary summary,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            Directory.CreateDirectory(OutputDirectory!);
#pragma warning restore SA1101

            // Export main groups data
            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
#pragma warning disable SA1101
            var fileName = Path.Combine(
                OutputDirectory!,
                $"Groups_{timestamp}.{OutputFormat.ToLower()}");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.Create(fileName);
                using var processor = new HighPerformanceJsonProcessor();
                await processor.SerializeAsync(stream, groups, true, cancellationToken);
            }
            else // CSV
            {
#pragma warning disable SA1101
                using var writer = new StreamWriter(fileName, false, System.Text.Encoding.GetEncoding(Encoding));
#pragma warning restore SA1101
                using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(groups, cancellationToken);
            }
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Exported {groups.Count} groups to {fileName}");

            // Export dynamic groups separately if any exist
            var dynamicGroups = groups.Where(g => g.IsDynamic).ToList();
            if (dynamicGroups.Any())
            {
#pragma warning disable SA1101
                var dynamicFileName = Path.Combine(
                    OutputDirectory!,
                    $"DynamicGroups_{timestamp}.{OutputFormat.ToLower()}");
#pragma warning restore SA1101

#pragma warning disable SA1101
                if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
                {
                    using var stream = File.Create(dynamicFileName);
                    using var processor = new HighPerformanceJsonProcessor();
                    await processor.SerializeAsync(stream, dynamicGroups, true, cancellationToken);
                }
                else // CSV
                {
#pragma warning disable SA1101
                    using var writer = new StreamWriter(dynamicFileName, false, System.Text.Encoding.GetEncoding(Encoding));
#pragma warning restore SA1101
                    using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
                    await csv.WriteRecordsAsync(dynamicGroups, cancellationToken);
                }
#pragma warning restore SA1101

                WriteVerboseWithTimestamp($"Exported {dynamicGroups.Count} dynamic groups to {dynamicFileName}");
            }

            // Export summary
#pragma warning disable SA1101
            var summaryFileName = Path.Combine(OutputDirectory!, $"GroupsSummary_{timestamp}.json");
#pragma warning restore SA1101
            var summaryJson = System.Text.Json.JsonSerializer.Serialize(summary, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });
            using (var writer = new StreamWriter(summaryFileName)) { await writer.WriteAsync(summaryJson); }
        }

        private async Task ExportGroupMembersAsync(
            List<GroupMemberInfo> members,
            CancellationToken cancellationToken)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
#pragma warning disable SA1101
            var fileName = Path.Combine(
                OutputDirectory!,
                $"GroupMembers_{timestamp}.{OutputFormat.ToLower()}");
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.Create(fileName);
                using var processor = new HighPerformanceJsonProcessor();
                await processor.SerializeAsync(stream, members, true, cancellationToken);
            }
            else // CSV
            {
#pragma warning disable SA1101
                using var writer = new StreamWriter(fileName, false, System.Text.Encoding.GetEncoding(Encoding));
#pragma warning restore SA1101
                using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(members, cancellationToken);
            }
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Exported {members.Count} group member relationships to {fileName}");
        }
    }

#pragma warning disable SA1600
    public class GroupInfo
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string GroupId { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string DisplayName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Description { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Mail { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool MailEnabled { get; set; }
        public string MailNickname { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool SecurityEnabled { get; set; }
        public string GroupTypes { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? CreatedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? RenewedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? ExpirationDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Visibility { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool OnPremisesSyncEnabled { get; set; }
        public DateTime? OnPremisesLastSyncDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string SecurityIdentifier { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsManagementRestricted { get; set; }
        public string MembershipRule { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string MembershipRuleProcessingState { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Classification { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool HideFromAddressLists { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool HideFromOutlookClients { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsAssignableToRole { get; set; }
        public string PreferredDataLocation { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ProxyAddresses { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsDynamic { get; set; }
#pragma warning restore SA1600
        public int MemberCount { get; set; }
    }

#pragma warning disable SA1600
    public class GroupMemberInfo
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string GroupId { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string GroupName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string MemberId { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string DisplayName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Mail { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string UserPrincipalName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string MemberType { get; set; } = string.Empty; // User, Group, etc.
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class GroupsSummary
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public TimeSpan ProcessingTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalGroups { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int SecurityEnabled { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int MailEnabled { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int DynamicGroups { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int OnPremisesSynced { get; set; }
#pragma warning restore SA1600
        public int RoleAssignable { get; set; }
    }
}
