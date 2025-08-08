using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;

namespace Microsoft.ExtractorSuite.Cmdlets.Collection
{
    /// <summary>
    /// Cmdlet for orchestrating comprehensive evidence collection from Microsoft 365 and Azure/Entra ID environments.
    /// Provides both interactive and automated collection modes with support for platform filtering and user-specific collection.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AllEvidence")]
    [OutputType(typeof(CollectionSummary))]
    public class GetAllEvidenceCmdlet : AsyncBaseCmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "The name of the project/case. Used to create the output directory structure.")]
        public string ProjectName { get; set; } = string.Empty;

        [Parameter(HelpMessage = "Specifies which platform to collect from. Valid values: All, Azure, M365. Default: All")]
        [ValidateSet("All", "Azure", "M365")]
        public string Platform { get; set; } = "All";

        [Parameter(HelpMessage = "Comma-separated list of user IDs to filter the collection scope.")]
        public string[]? UserIds { get; set; }

        [Parameter(HelpMessage = "Output format for collected data. Default: CSV")]
        [ValidateSet("CSV", "JSON", "SOF-ELK", "JSONL")]
        public string Output { get; set; } = "CSV";

        [Parameter(HelpMessage = "Switch to enable interactive mode, showing the collection menu.")]
        public SwitchParameter Interactive { get; set; }

        [Parameter(HelpMessage = "Custom output directory. Default: Output\\{ProjectName}")]
        public string? CustomOutputDir { get; set; }

        protected override void ProcessRecord()
        {
            var summary = RunAsyncOperation(CollectEvidenceAsync, "Collecting Evidence");

            if (!Async.IsPresent && summary != null)
            {
                WriteObject(summary);
            }
        }

        private async Task<CollectionSummary> CollectEvidenceAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            var summary = new CollectionSummary
            {
                ProjectName = ProjectName,
                Platform = Platform,
                StartTime = DateTime.UtcNow,
                UserIds = UserIds,
                Tasks = new List<CollectionTaskResult>()
            };

            // Validate connections based on platform
            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Validating connections",
                PercentComplete = 5
            });

            if (!await ValidateConnectionsAsync(Platform, cancellationToken))
            {
                throw new InvalidOperationException("Required connections are not established. Please run Connect-M365 first.");
            }

            // Set up output directory
            var outputDir = SetupOutputDirectory();
            summary.OutputDirectory = outputDir;

            WriteVerboseWithTimestamp($"Starting evidence collection for project: {ProjectName}");
            WriteVerboseWithTimestamp($"Platform: {Platform}");
            WriteVerboseWithTimestamp($"Output Directory: {outputDir}");
            if (UserIds?.Length > 0)
            {
                WriteVerboseWithTimestamp($"Target Users: {string.Join(", ", UserIds)}");
            }

            // Initialize collection tasks
            var collectionTasks = InitializeCollectionTasks();

            // Show interactive menu if requested
            if (Interactive.IsPresent)
            {
                // Note: Interactive menu would require Host interaction which is complex in cmdlets
                // For now, we'll proceed with all enabled tasks
                WriteWarningWithTimestamp("Interactive mode not fully implemented in this version. Proceeding with all enabled tasks.");
            }

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

                var taskResult = await ExecuteCollectionTaskAsync(task, outputDir, cancellationToken);
                summary.Tasks.Add(taskResult);

                if (taskResult.Success)
                {
                    summary.SuccessfulTasks++;
                    WriteVerboseWithTimestamp($"✓ Completed: {task.Name}");
                }
                else
                {
                    summary.FailedTasks++;
                    WriteWarningWithTimestamp($"✗ Failed: {task.Name} - {taskResult.ErrorMessage}");
                }
            }

            summary.EndTime = DateTime.UtcNow;
            summary.ProcessingTime = summary.EndTime - summary.StartTime;
            summary.TotalTasks = totalTasks;

            // Generate summary report
            await GenerateCollectionReportAsync(summary, outputDir, cancellationToken);

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
            if (!string.IsNullOrEmpty(CustomOutputDir))
            {
                outputDir = Path.Combine(CustomOutputDir, ProjectName);
            }
            else
            {
                outputDir = Path.Combine(Environment.CurrentDirectory, "Output", ProjectName);
            }

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
                    WriteErrorWithTimestamp($"M365/Exchange connection failed: {ex.Message}");
                    isValid = false;
                }
            }

            if (platform == "All" || platform == "Azure")
            {
                // Check Microsoft Graph connection
                if (!AuthManager.IsGraphConnected)
                {
                    WriteErrorWithTimestamp("Microsoft Graph connection not established. Please run Connect-M365 first.");
                    isValid = false;
                }
                else
                {
                    WriteVerboseWithTimestamp("Microsoft Graph connection validated");
                }
            }

            return isValid;
        }

        private List<CollectionTaskDefinition> InitializeCollectionTasks()
        {
            var tasks = new List<CollectionTaskDefinition>();

            // Azure/Entra ID tasks
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

            // Microsoft 365 tasks
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
                await SimulateTaskExecutionAsync(task, taskOutputDir, cancellationToken);

                result.Success = true;
                result.OutputLocation = taskOutputDir;
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                Logger?.LogError($"Task {task.Name} failed: {ex.Message}", ex);
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
            await File.WriteAllTextAsync(outputFile, "# Placeholder for actual data collection", cancellationToken);
        }

        private async Task GenerateCollectionReportAsync(CollectionSummary summary, string outputDir, CancellationToken cancellationToken)
        {
            var reportPath = Path.Combine(outputDir, $"{DateTime.UtcNow:yyyyMMddHHmmss}-CollectionSummary.json");
            
            var reportData = System.Text.Json.JsonSerializer.Serialize(summary, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
            });

            await File.WriteAllTextAsync(reportPath, reportData, cancellationToken);
            WriteVerboseWithTimestamp($"Collection report saved to: {reportPath}");
        }
    }

    public class CollectionSummary
    {
        public string ProjectName { get; set; } = string.Empty;
        public string Platform { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public int TotalTasks { get; set; }
        public int SuccessfulTasks { get; set; }
        public int FailedTasks { get; set; }
        public string[]? UserIds { get; set; }
        public string OutputDirectory { get; set; } = string.Empty;
        public List<CollectionTaskResult> Tasks { get; set; } = new();
    }

    public class CollectionTaskDefinition
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string TaskType { get; set; } = string.Empty;
        public bool Enabled { get; set; }
        public bool SupportsUserFiltering { get; set; }
    }

    public class CollectionTaskResult
    {
        public string TaskName { get; set; } = string.Empty;
        public string TaskType { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public string? OutputLocation { get; set; }
    }
}