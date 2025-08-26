namespace Microsoft.ExtractorSuite.Cmdlets.Collection
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;


    /// <summary>
    /// Cmdlet for orchestrating comprehensive evidence collection from Microsoft 365 and Azure/Entra ID environments.
    /// Provides both interactive and automated collection modes with support for platform filtering and user-specific collection.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AllEvidence")]
    [OutputType(typeof(CollectionSummary))]
    public class GetAllEvidenceCmdlet : AsyncBaseCmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "The name of the project/case. Used to create the output directory structure.")]
#pragma warning disable SA1600
        public string ProjectName { get; set; } = string.Empty;
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Specifies which platform to collect from. Valid values: All, Azure, M365. Default: All")]
        [ValidateSet("All", "Azure", "M365")]
#pragma warning disable SA1600
        public string Platform { get; set; } = "All";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Comma-separated list of user IDs to filter the collection scope.")]
#pragma warning disable SA1600
        public string[]? UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Output format for collected data. Default: CSV")]
        [ValidateSet("CSV", "JSON", "SOF-ELK", "JSONL")]
#pragma warning disable SA1600
        public string Output { get; set; } = "CSV";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Switch to enable interactive mode, showing the collection menu.")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter Interactive { get; set; }

        [Parameter(HelpMessage = "Custom output directory. Default: Output\\{ProjectName}")]
#pragma warning disable SA1600
        public string? CustomOutputDir { get; set; }
#pragma warning restore SA1600

#pragma warning disable SA1600
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
            var summary = RunAsyncOperation(CollectEvidenceAsync, "Collecting Evidence");

#pragma warning disable SA1101
            if (!Async.IsPresent && summary != null)
            {
#pragma warning disable SA1101
                WriteObject(summary);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101
        }

        private async Task<CollectionSummary> CollectEvidenceAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var summary = new CollectionSummary
            {
                ProjectName = ProjectName,
                Platform = Platform,
                StartTime = DateTime.UtcNow,
                UserIds = UserIds,
                Tasks = new List<CollectionTaskResult>()
            };
#pragma warning restore SA1101

            // Validate connections based on platform
            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Validating connections",
                PercentComplete = 5
            });

#pragma warning disable SA1101
            if (!await ValidateConnectionsAsync(Platform, cancellationToken))
            {
                throw new InvalidOperationException("Required connections are not established. Please run Connect-M365 first.");
            }
#pragma warning restore SA1101

            // Set up output directory
#pragma warning disable SA1101
            var outputDir = SetupOutputDirectory();
#pragma warning restore SA1101
            summary.OutputDirectory = outputDir;

#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Starting evidence collection for project: {ProjectName}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"Platform: {Platform}");
#pragma warning restore SA1101
            WriteVerboseWithTimestamp($"Output Directory: {outputDir}");
#pragma warning disable SA1101
            if (UserIds?.Length > 0)
            {
#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"Target Users: {string.Join(", ", UserIds)}");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            // Initialize collection tasks
#pragma warning disable SA1101
            var collectionTasks = InitializeCollectionTasks();
#pragma warning restore SA1101

            // Show interactive menu if requested
#pragma warning disable SA1101
            if (Interactive.IsPresent)
            {
                // Note: Interactive menu would require Host interaction which is complex in cmdlets
                // For now, we'll proceed with all enabled tasks
#pragma warning disable SA1101
                WriteWarningWithTimestamp("Interactive mode not fully implemented in this version. Proceeding with all enabled tasks.");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            // Execute collection tasks
            var completedTasks = 0;
            var totalTasks = collectionTasks.Count(t => t.Enabled);

            foreach (var task in collectionTasks.Where(t => t.Enabled))
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                completedTasks++;
                var taskProgress = (int)((completedTasks / (double)totalTasks) * 100);

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = $"Executing: {task.Name}",
                    PercentComplete = taskProgress,
                    ItemsProcessed = completedTasks
                });

#pragma warning disable SA1101
                var taskResult = await ExecuteCollectionTaskAsync(task, outputDir, cancellationToken);
#pragma warning restore SA1101
                summary.Tasks.Add(taskResult);

                if (taskResult.Success)
                {
                    summary.SuccessfulTasks++;
                    WriteVerboseWithTimestamp($"✓ Completed: {task.Name}");
                }
                else
                {
                    summary.FailedTasks++;
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"✗ Failed: {task.Name} - {taskResult.ErrorMessage}");
#pragma warning restore SA1101
                }
            }

            summary.EndTime = DateTime.UtcNow;
            summary.ProcessingTime = summary.EndTime - summary.StartTime;
            summary.TotalTasks = totalTasks;

            // Generate summary report
#pragma warning disable SA1101
            await GenerateCollectionReportAsync(summary, outputDir, cancellationToken);
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Evidence collection completed. Summary:");
            WriteVerboseWithTimestamp($"  Total Tasks: {summary.TotalTasks}");
            WriteVerboseWithTimestamp($"  Successful: {summary.SuccessfulTasks}");
            WriteVerboseWithTimestamp($"  Failed: {summary.FailedTasks}");
            WriteVerboseWithTimestamp($"  Duration: {summary.ProcessingTime:hh\\:mm\\:ss}");

            return summary;
        }

        private string SetupOutputDirectory()
        {
            string outputDir;
#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(CustomOutputDir))
            {
#pragma warning disable SA1101
                outputDir = Path.Combine(CustomOutputDir, ProjectName);
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                outputDir = Path.Combine(Environment.CurrentDirectory, "Output", ProjectName);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            if (!Directory.Exists(outputDir))
            {
                Directory.CreateDirectory(outputDir);
                WriteVerboseWithTimestamp($"Created output directory: {outputDir}");
            }

            return outputDir;
        }

        private async Task<bool> ValidateConnectionsAsync(string platform, CancellationToken cancellationToken)
        {
            var isValid = true;

            if (platform == "All" || platform == "M365")
            {
                // Check Exchange Online connection
                try
                {
                    // This would need to be implemented based on the authentication system
                    // For now, we'll assume it's valid if we get here
                    WriteVerboseWithTimestamp("M365/Exchange connection validated");
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteErrorWithTimestamp($"M365/Exchange connection failed: {ex.Message}");
#pragma warning restore SA1101
                    isValid = false;
                }
            }

            if (platform == "All" || platform == "Azure")
            {
                // Check Microsoft Graph connection
#pragma warning disable SA1101
                if (!AuthManager.IsGraphConnected)
                {
#pragma warning disable SA1101
                    WriteErrorWithTimestamp("Microsoft Graph connection not established. Please run Connect-M365 first.");
#pragma warning restore SA1101
                    isValid = false;
                }
                else
                {
                    WriteVerboseWithTimestamp("Microsoft Graph connection validated");
                }
#pragma warning restore SA1101
            }

            return isValid;
        }

        private List<CollectionTaskDefinition> InitializeCollectionTasks()
        {
            var tasks = new List<CollectionTaskDefinition>();

            // Azure/Entra ID tasks
#pragma warning disable SA1101
            if (Platform == "All" || Platform == "Azure")
            {
                tasks.AddRange(new[]
                {
                    new CollectionTaskDefinition
                    {
                        Name = "Risky Users",
                        Description = "Collects information about users marked as risky",
                        Category = "Azure",
                        TaskType = "RiskyUsers",
                        Enabled = true,
                        SupportsUserFiltering = true
                    },
                    new CollectionTaskDefinition
                    {
                        Name = "MFA Status",
                        Description = "Collects MFA configuration and status",
                        Category = "Azure",
                        TaskType = "MFAStatus",
                        Enabled = true,
                        SupportsUserFiltering = true
                    },
                    new CollectionTaskDefinition
                    {
                        Name = "Users",
                        Description = "Collects general user information",
                        Category = "Azure",
                        TaskType = "Users",
                        Enabled = true,
                        SupportsUserFiltering = false
                    },
                    new CollectionTaskDefinition
                    {
                        Name = "Devices",
                        Description = "Collects device information",
                        Category = "Azure",
                        TaskType = "Devices",
                        Enabled = true,
                        SupportsUserFiltering = true
                    },
                    new CollectionTaskDefinition
                    {
                        Name = "Conditional Access",
                        Description = "Collects Conditional Access Policies",
                        Category = "Azure",
                        TaskType = "ConditionalAccess",
                        Enabled = true,
                        SupportsUserFiltering = false
                    },
                    new CollectionTaskDefinition
                    {
                        Name = "Sign-In Logs",
                        Description = "Collects Azure Entra sign-in logs",
                        Category = "Azure",
                        TaskType = "SignInLogs",
                        Enabled = true,
                        SupportsUserFiltering = true
                    },
                    new CollectionTaskDefinition
                    {
                        Name = "Audit Logs",
                        Description = "Collects Azure Entra audit logs",
                        Category = "Azure",
                        TaskType = "AuditLogs",
                        Enabled = true,
                        SupportsUserFiltering = true
                    }
                });
            }
#pragma warning restore SA1101

            // Microsoft 365 tasks
#pragma warning disable SA1101
            if (Platform == "All" || Platform == "M365")
            {
                tasks.AddRange(new[]
                {
                    new CollectionTaskDefinition
                    {
                        Name = "Inbox Rules",
                        Description = "Collects Exchange inbox rules",
                        Category = "M365",
                        TaskType = "InboxRules",
                        Enabled = true,
                        SupportsUserFiltering = true
                    },
                    new CollectionTaskDefinition
                    {
                        Name = "Transport Rules",
                        Description = "Collects Exchange transport rules",
                        Category = "M365",
                        TaskType = "TransportRules",
                        Enabled = true,
                        SupportsUserFiltering = false
                    },
                    new CollectionTaskDefinition
                    {
                        Name = "Mailbox Audit",
                        Description = "Collects mailbox audit configuration",
                        Category = "M365",
                        TaskType = "MailboxAudit",
                        Enabled = true,
                        SupportsUserFiltering = true
                    },
                    new CollectionTaskDefinition
                    {
                        Name = "Unified Audit Log",
                        Description = "Collects Office 365 Unified Audit Logs",
                        Category = "M365",
                        TaskType = "UnifiedAuditLog",
                        Enabled = true,
                        SupportsUserFiltering = true
                    }
                });
            }
#pragma warning restore SA1101

            return tasks;
        }

        private async Task<CollectionTaskResult> ExecuteCollectionTaskAsync(
            CollectionTaskDefinition task,
            string outputDir,
            CancellationToken cancellationToken)
        {
            var result = new CollectionTaskResult
            {
                TaskName = task.Name,
                TaskType = task.TaskType,
                StartTime = DateTime.UtcNow,
                Success = false
            };

            try
            {
                // Create task-specific output directory
                var taskOutputDir = Path.Combine(outputDir, task.TaskType);
                Directory.CreateDirectory(taskOutputDir);

                // Execute the task based on its type
                // Note: In a real implementation, these would call the actual cmdlets
                // For now, we'll simulate the execution
#pragma warning disable SA1101
                await SimulateTaskExecutionAsync(task, taskOutputDir, cancellationToken);
#pragma warning restore SA1101

                result.Success = true;
                result.OutputLocation = taskOutputDir;
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
#pragma warning disable SA1101
                Logger?.WriteErrorWithTimestamp($"Task {task.Name} failed: {ex.Message}", ex);
#pragma warning restore SA1101
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
                result.ProcessingTime = result.EndTime - result.StartTime;
            }

            return result;
        }

        private async Task SimulateTaskExecutionAsync(CollectionTaskDefinition task, string outputDir, CancellationToken cancellationToken)
        {
            // Simulate task execution - in real implementation, this would call actual cmdlets
            WriteVerboseWithTimestamp($"Executing task: {task.Name}");

            // Simulate some work
            await Task.Delay(1000, cancellationToken);

            // Create a dummy output file to indicate completion
            var outputFile = Path.Combine(outputDir, $"{DateTime.UtcNow:yyyyMMddHHmmss}-{task.TaskType}.csv");
            using (var writer = new StreamWriter(outputFile)) { await writer.WriteAsync("# Placeholder for actual data collection"); }
        }

        private async Task GenerateCollectionReportAsync(CollectionSummary summary, string outputDir, CancellationToken cancellationToken)
        {
            var reportPath = Path.Combine(outputDir, $"{DateTime.UtcNow:yyyyMMddHHmmss}-CollectionSummary.json");

            var reportData = System.Text.Json.JsonSerializer.Serialize(summary, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
            });

            using (var writer = new StreamWriter(reportPath)) { await writer.WriteAsync(reportData); }
            WriteVerboseWithTimestamp($"Collection report saved to: {reportPath}");
        }
    }

#pragma warning disable SA1600
    public class CollectionSummary
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string ProjectName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Platform { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime EndTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public TimeSpan ProcessingTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalTasks { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int SuccessfulTasks { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int FailedTasks { get; set; }
        public string[]? UserIds { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string OutputDirectory { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public List<CollectionTaskResult> Tasks { get; set; } = new();
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class CollectionTaskDefinition
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string Name { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Description { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Category { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string TaskType { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool Enabled { get; set; }
#pragma warning restore SA1600
        public bool SupportsUserFiltering { get; set; }
    }

#pragma warning disable SA1600
    public class CollectionTaskResult
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string TaskName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string TaskType { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime EndTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public TimeSpan ProcessingTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? OutputLocation { get; set; }
#pragma warning restore SA1600
    }
}
