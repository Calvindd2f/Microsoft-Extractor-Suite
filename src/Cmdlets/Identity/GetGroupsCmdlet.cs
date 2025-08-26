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

        public string CollectionType { get; set; } = "All";


        [Parameter(HelpMessage = "Include group membership information")]


        public SwitchParameter IncludeMembers { get; set; }

        [Parameter(HelpMessage = "Include dynamic group rules and processing state")]


        public SwitchParameter IncludeDynamicRules { get; set; }

        [Parameter(HelpMessage = "Output format for the results. Default: CSV")]
        [ValidateSet("CSV", "JSON")]

        public string OutputFormat { get; set; } = "CSV";


        [Parameter(HelpMessage = "Text encoding for the output file. Default: UTF8")]

        public string Encoding { get; set; } = "UTF8";



        protected override void ProcessRecord()

        {
            var results = RunAsyncOperation(GetGroupsAsync, "Getting Groups");


            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }

        }

        private async Task<List<GroupInfo>> GetGroupsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Groups Collection");


            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Not connected to Microsoft Graph. Please run Connect-M365 first.");
            }



            var graphClient = AuthManager.GraphClient!;


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

                    WriteWarningWithTimestamp("No groups found or insufficient permissions");

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


                    var groupInfo = await MapGroupToInfoAsync(graphClient, group, cancellationToken);

                    results.Add(groupInfo);

                    // Update summary statistics

                    UpdateGroupsSummary(summary, groupInfo);


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

                if (IncludeMembers.IsPresent || CollectionType == "Members" || CollectionType == "All")
                {
                    progress.Report(new Core.AsyncOperations.TaskProgress
                    {
                        CurrentOperation = "Processing group members",
                        PercentComplete = 85
                    });


                    await ProcessGroupMembersAsync(graphClient, results, cancellationToken);

                }


                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Exporting results",
                    PercentComplete = 90
                });

                // Export results if output directory is specified

                if (!string.IsNullOrEmpty(OutputDirectory))
                {

                    await ExportGroupsAsync(results, summary, cancellationToken);

                }


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

                WriteErrorWithTimestamp($"Microsoft Graph API error: {ex.ResponseStatusCode} - {ex.Message}", ex);

                throw;
            }
            catch (Exception ex)
            {

                WriteErrorWithTimestamp($"Error retrieving groups: {ex.Message}", ex);

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

                    WriteWarningWithTimestamp($"Failed to retrieve members for group {group.DisplayName}: {ex.Message}");

                }
                catch (Exception ex)
                {

                    WriteWarningWithTimestamp($"Error processing members for group {group.DisplayName}: {ex.Message}");

                }
            }

            // Export group members separately if we have them

            if (!string.IsNullOrEmpty(OutputDirectory) && memberResults.Any())
            {

                await ExportGroupMembersAsync(memberResults, cancellationToken);

            }

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

            Directory.CreateDirectory(OutputDirectory!);


            // Export main groups data
            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");

            var fileName = Path.Combine(
                OutputDirectory!,
                $"Groups_{timestamp}.{OutputFormat.ToLower()}");



            if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.Create(fileName);
                using var processor = new HighPerformanceJsonProcessor();
                await processor.SerializeAsync(stream, groups, true, cancellationToken);
            }
            else // CSV
            {

                using var writer = new StreamWriter(fileName, false, System.Text.Encoding.GetEncoding(Encoding));

                using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(groups, cancellationToken);
            }


            WriteVerboseWithTimestamp($"Exported {groups.Count} groups to {fileName}");

            // Export dynamic groups separately if any exist
            var dynamicGroups = groups.Where(g => g.IsDynamic).ToList();
            if (dynamicGroups.Any())
            {

                var dynamicFileName = Path.Combine(
                    OutputDirectory!,
                    $"DynamicGroups_{timestamp}.{OutputFormat.ToLower()}");



                if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
                {
                    using var stream = File.Create(dynamicFileName);
                    using var processor = new HighPerformanceJsonProcessor();
                    await processor.SerializeAsync(stream, dynamicGroups, true, cancellationToken);
                }
                else // CSV
                {

                    using var writer = new StreamWriter(dynamicFileName, false, System.Text.Encoding.GetEncoding(Encoding));

                    using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
                    await csv.WriteRecordsAsync(dynamicGroups, cancellationToken);
                }


                WriteVerboseWithTimestamp($"Exported {dynamicGroups.Count} dynamic groups to {dynamicFileName}");
            }

            // Export summary

            var summaryFileName = Path.Combine(OutputDirectory!, $"GroupsSummary_{timestamp}.json");

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

            var fileName = Path.Combine(
                OutputDirectory!,
                $"GroupMembers_{timestamp}.{OutputFormat.ToLower()}");



            if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.Create(fileName);
                using var processor = new HighPerformanceJsonProcessor();
                await processor.SerializeAsync(stream, members, true, cancellationToken);
            }
            else // CSV
            {

                using var writer = new StreamWriter(fileName, false, System.Text.Encoding.GetEncoding(Encoding));

                using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(members, cancellationToken);
            }


            WriteVerboseWithTimestamp($"Exported {members.Count} group member relationships to {fileName}");
        }
    }


    public class GroupInfo

    {

        public string GroupId { get; set; } = string.Empty;


        public string DisplayName { get; set; } = string.Empty;


        public string Description { get; set; } = string.Empty;


        public string Mail { get; set; } = string.Empty;




        public bool MailEnabled { get; set; }
        public string MailNickname { get; set; } = string.Empty;




        public bool SecurityEnabled { get; set; }
        public string GroupTypes { get; set; } = string.Empty;


        public DateTime? CreatedDateTime { get; set; }


        public DateTime? RenewedDateTime { get; set; }


        public DateTime? ExpirationDateTime { get; set; }


        public string Visibility { get; set; } = string.Empty;




        public bool OnPremisesSyncEnabled { get; set; }
        public DateTime? OnPremisesLastSyncDateTime { get; set; }


        public string SecurityIdentifier { get; set; } = string.Empty;




        public bool IsManagementRestricted { get; set; }
        public string MembershipRule { get; set; } = string.Empty;


        public string MembershipRuleProcessingState { get; set; } = string.Empty;


        public string Classification { get; set; } = string.Empty;




        public bool HideFromAddressLists { get; set; }


        public bool HideFromOutlookClients { get; set; }


        public bool IsAssignableToRole { get; set; }
        public string PreferredDataLocation { get; set; } = string.Empty;


        public string ProxyAddresses { get; set; } = string.Empty;




        public bool IsDynamic { get; set; }

        public int MemberCount { get; set; }
    }


    public class GroupMemberInfo

    {

        public string GroupId { get; set; } = string.Empty;


        public string GroupName { get; set; } = string.Empty;


        public string MemberId { get; set; } = string.Empty;


        public string DisplayName { get; set; } = string.Empty;


        public string Mail { get; set; } = string.Empty;


        public string UserPrincipalName { get; set; } = string.Empty;


        public string MemberType { get; set; } = string.Empty; // User, Group, etc.

    }


    public class GroupsSummary

    {



        public DateTime StartTime { get; set; }


        public TimeSpan ProcessingTime { get; set; }


        public int TotalGroups { get; set; }


        public int SecurityEnabled { get; set; }


        public int MailEnabled { get; set; }


        public int DynamicGroups { get; set; }


        public int OnPremisesSynced { get; set; }

        public int RoleAssignable { get; set; }
    }
}
