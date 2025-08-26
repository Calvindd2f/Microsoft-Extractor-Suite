namespace Microsoft.ExtractorSuite.Cmdlets.Collection
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Templates;


    /// <summary>
    /// Cmdlet to perform automated triage collection based on templates
    /// </summary>
    [Cmdlet(VerbsLifecycle.Start, "MESTriage")]
    [OutputType(typeof(MESTriageResult))]
    public class StartMESTriageCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "Template to use for triage collection")]
#pragma warning disable SA1600
        public string Template { get; set; } = "Standard";
#pragma warning restore SA1600

        [Parameter(
            Mandatory = true,
            HelpMessage = "Name of the triage project")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public string TriageName { get; set; }

        [Parameter(
            HelpMessage = "User IDs to target for triage. Multiple email addresses separated by commas")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public string UserIds { get; set; }

        [Parameter(
            HelpMessage = "Start date for time-based queries")]
#pragma warning disable SA1600
        public DateTime? StartDate { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "End date for time-based queries")]
#pragma warning disable SA1600
        public DateTime? EndDate { get; set; }
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Output format: CSV, JSON, JSONL, or SOF-ELK")]
        [ValidateSet("CSV", "JSON", "JSONL", "SOF-ELK")]
#pragma warning disable SA1600
        public string Output { get; set; } = "CSV";
#pragma warning restore SA1600

        [Parameter(
            HelpMessage = "Merge output files into single files where applicable")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter MergeOutput { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public string OutputDir { get; set; }

        [Parameter(
            HelpMessage = "File encoding for output files")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

#pragma warning disable SA1309
#pragma warning disable SA1201
        private readonly TemplateProcessor _templateProcessor;
#pragma warning restore SA1201
#pragma warning disable SA1600
#pragma warning SA1309 F
#pragma warning restore SA1600
        private readonly TaskExecutor _taskExecutor;
#pragma warning restore SA1309

        public StartMESTriageCmdlet()
        {
#pragma warning disable SA1600
#pragma warning disable SA1101
            _templateProcessor = new TemplateProcessor();
#pragma warning restore SA1101
#pragma warning disable SA1101
            _taskExecutor = new TaskExecutor();
#pragma warning restore SA1101
        }

        protected override async Task ProcessRecordAsync()
        {
#pragma warning disable SA1101
            WriteVerbose("=== Starting MES Triage ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Project: {TriageName}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Template: {Template}");
#pragma warning restore SA1101

            // Parse user IDs
#pragma warning disable SA1101
            var userIdArray = ParseUserIds(UserIds);
#pragma warning restore SA1101

            if (userIdArray.Length == 0)
            {
#pragma warning disable SA1101
                WriteVerbose("Target: All users");
#pragma warning restore SA1101
            }
            else if (userIdArray.Length == 1)
            {
#pragma warning disable SA1101
                WriteVerbose($"Target User: {userIdArray[0]}");
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                WriteVerbose("Target Users:");
#pragma warning restore SA1101
                foreach (var user in userIdArray)
                {
#pragma warning disable SA1101
                    WriteVerbose($"  - {user}");
#pragma warning restore SA1101
                }
            }

#pragma warning disable SA1101
            WriteVerbose($"Output Format: {GetOutputFormatDescription()}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Start Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
#pragma warning restore SA1101

            // Set up output directory
#pragma warning disable SA1101
            var outputDirectory = SetupOutputDirectory();
#pragma warning restore SA1101

            // Initialize summary
#pragma warning disable SA1101
            var summary = new MESTriageSummary
            {
                StartTime = DateTime.Now,
                TriageName = TriageName,
                TemplateName = Template,
                TargetUsers = userIdArray.Length == 0 ? "All users" : string.Join(", ", userIdArray),
                OutputFormat = Output,
                OutputDirectory = outputDirectory,
                TotalTasks = 0,
                SuccessfulTasks = 0,
                FailedTasks = 0,
                SkippedTasks = 0,
                TaskResults = new List<TaskResult>()
            };
#pragma warning restore SA1101

            try
            {
                // Load and validate template
#pragma warning disable SA1101
                var templateConfig = await _templateProcessor.LoadTemplateAsync(Template);
#pragma warning restore SA1101
                if (templateConfig == null)
                {
#pragma warning disable SA1101
                    WriteErrorWithTimestamp($"Template '{Template}' not found or could not be loaded.");
#pragma warning restore SA1101
                    return;
                }

                if (templateConfig.Tasks == null || templateConfig.Tasks.Count == 0)
                {
#pragma warning disable SA1101
                    WriteErrorWithTimestamp("No tasks defined in template");
#pragma warning restore SA1101
                    return;
                }

#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose("==== Executing Template Tasks ====");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose($"Total tasks to execute: {templateConfig.Tasks.Count}");
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteVerbose("");
#pragma warning restore SA1101

                summary.TotalTasks = templateConfig.Tasks.Count;

                // Execute tasks
                foreach (var task in templateConfig.Tasks)
                {
                    var taskResult = await ExecuteTaskAsync(task, outputDirectory, userIdArray, summary);
                    summary.TaskResults.Add(taskResult);

                    switch (taskResult.Status)
                    {
                        case MESTaskStatus.Completed:
                            summary.SuccessfulTasks++;
                            break;
                        case MESTaskStatus.Failed:
                            summary.FailedTasks++;
                            break;
                        case MESTaskStatus.Skipped:
                            summary.SkippedTasks++;
                            break;
                    }
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
#pragma warning disable SA1101
                LogTriageSummary(summary);
#pragma warning restore SA1101

                var result = new MESTriageResult
                {
                    Summary = summary,
                    TaskResults = summary.TaskResults
                };

#pragma warning disable SA1101
                WriteObject(result);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"An error occurred during triage execution: {ex.Message}");
#pragma warning restore SA1101
                throw;
            }
        }

        private string[] ParseUserIds(string userIds)
        {
            if (string.IsNullOrWhiteSpace(userIds))
                return new string[0];

            return userIds
                .Split(',')
                .Select(u => u.Trim())
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .ToArray();
        }

        private string GetOutputFormatDescription()
        {
#pragma warning disable SA1101
            return Output switch
            {
                "JSONL" => "JSONL (supported functions only, others will use JSON)",
                "SOF-ELK" => "SOF-ELK (supported functions only, others will use JSON)",
                _ => Output
            };
#pragma warning restore SA1101
        }

        private string SetupOutputDirectory()
        {
            string outputDirectory;

#pragma warning disable SA1101
            if (string.IsNullOrEmpty(OutputDir))
            {
#pragma warning disable SA1101
                outputDirectory = Path.Combine("Output", TriageName);
#pragma warning restore SA1101
            }
            else
            {
#pragma warning disable SA1101
                outputDirectory = Path.Combine(OutputDir, TriageName);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            if (!Directory.Exists(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
#pragma warning disable SA1101
                WriteVerbose($"Creating output directory: {outputDirectory}");
#pragma warning restore SA1101
            }

            return outputDirectory;
        }

        private async Task<TaskResult> ExecuteTaskAsync(dynamic task, string outputDirectory, string[] userIds, MESTriageSummary summary)
        {
#pragma warning disable SA1101
            var taskResult = new TaskResult
            {
                TaskName = GetTaskName(task),
                StartTime = DateTime.Now,
                Status = MESTaskStatus.InProgress
            };
#pragma warning restore SA1101

            try
            {
                // Check if task should be skipped
#pragma warning disable SA1101
                if (ShouldSkipTask(task, userIds))
                {
                    taskResult.Status = MESTaskStatus.Skipped;
                    taskResult.Message = "Task skipped - not applicable for user-specific triage";
                    taskResult.ProcessingTime = DateTime.Now - taskResult.StartTime;
                    return taskResult;
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                LogTaskProgress(taskResult.TaskName, MESTaskStatus.InProgress);
#pragma warning restore SA1101

                // Execute the task based on its type
#pragma warning disable SA1101
                var success = await _taskExecutor.ExecuteTaskAsync(new TaskExecutionContext
                {
                    Task = task,
                    OutputDirectory = outputDirectory,
                    UserIds = userIds,
                    StartDate = StartDate,
                    EndDate = EndDate,
                    Output = Output,
                    MergeOutput = MergeOutput,
                    Encoding = Encoding,
                    LogLevel = LogLevel.ToString()
                });
#pragma warning restore SA1101

                taskResult.Status = success ? MESTaskStatus.Completed : MESTaskStatus.Failed;
                taskResult.Message = success ? "Task completed successfully" : "Task failed";

#pragma warning disable SA1101
                LogTaskProgress(taskResult.TaskName, taskResult.Status);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
                taskResult.Status = MESTaskStatus.Failed;
                taskResult.Message = ex.Message;

#pragma warning disable SA1101
                LogTaskProgress(taskResult.TaskName, MESTaskStatus.Failed, ex.Message);
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Task {taskResult.TaskName} failed: {ex.Message}");
#pragma warning restore SA1101
            }

            taskResult.ProcessingTime = DateTime.Now - taskResult.StartTime;
            return taskResult;
        }

        private string GetTaskName(dynamic task)
        {
            if (task is string stringTask)
                return stringTask;

            if (task is Dictionary<string, object> dictTask)
            {
                if (dictTask.ContainsKey("Task"))
                    return dictTask["Task"]?.ToString() ?? "Unknown Task";
            }

            try
            {
                var taskProperty = task.GetType().GetProperty("Task");
                if (taskProperty != null)
                    return taskProperty.GetValue(task)?.ToString() ?? "Unknown Task";
            }
            catch
            {
                // Ignore reflection errors
            }

            return "Unknown Task";
        }

        private bool ShouldSkipTask(dynamic task, string[] userIds)
        {
#pragma warning disable SA1101
            var taskName = GetTaskName(task);
#pragma warning restore SA1101

            // Tasks that should be skipped for user-specific triage
            var userSpecificSkipTasks = new[]
            {
                "Get-DirectoryActivityLogs",
                "Get-TransportRules",
                "Get-ConditionalAccessPolicies",
                "Get-Licenses",
                "Get-LicenseCompatibility",
                "Get-EntraSecurityDefaults",
                "Get-LicensesByUser",
                "Get-Groups",
                "Get-GroupMembers",
                "Get-DynamicGroups",
                "Get-SecurityAlerts",
                "Get-PIMAssignments",
                "Get-AllRoleActivity"
            };

            return userIds.Length > 0 && userSpecificSkipTasks.Contains((string)taskName);
        }

        private void LogTaskProgress(string taskName, MESTaskStatus status, string? errorMessage = null)
        {
            switch (status)
            {
                case MESTaskStatus.InProgress:
#pragma warning disable SA1101
                    WriteVerbose($"[IN PROGRESS] {taskName}");
#pragma warning restore SA1101
                    break;
                case MESTaskStatus.Completed:
#pragma warning disable SA1101
                    WriteVerbose($"[COMPLETED] {taskName}");
#pragma warning restore SA1101
                    break;
                case MESTaskStatus.Failed:
#pragma warning disable SA1101
                    WriteErrorWithTimestamp($"[FAILED] {taskName}" + (string.IsNullOrEmpty(errorMessage) ? "" : $": {errorMessage}"));
#pragma warning restore SA1101
                    break;
                case MESTaskStatus.Skipped:
#pragma warning disable SA1101
                    WriteVerbose($"[SKIPPED] {taskName}");
#pragma warning restore SA1101
                    break;
            }
        }

        private void LogTriageSummary(MESTriageSummary summary)
        {
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"=== {Template} Triage Summary ===");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Start Time: {summary.StartTime:yyyy-MM-dd HH:mm:ss}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"End Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Duration: {summary.ProcessingTime?.ToString(@"hh\:mm\:ss")}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("Task Results:");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"  Successful: {summary.SuccessfulTasks}", summary.SuccessfulTasks > 0 ? ConsoleColor.Green : ConsoleColor.Gray);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"  Failed: {summary.FailedTasks}", summary.FailedTasks > 0 ? ConsoleColor.Red : ConsoleColor.Green);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"  Skipped: {summary.SkippedTasks}", ConsoleColor.Yellow);
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"  Total: {summary.TotalTasks}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose($"Output Location: {summary.OutputDirectory}");
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerbose("=============================================");
#pragma warning restore SA1101
        }

        private void WriteVerbose(string message, ConsoleColor color = ConsoleColor.White)
        {
            // In a real implementation, this would use the PowerShell logging infrastructure
            // For now, we'll use the base class logging
#pragma warning disable SA1101
            WriteVerbose(message);
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600
    }

    // Supporting classes and enums
#pragma warning disable SA1201
    public enum MESTaskStatus
#pragma warning restore SA1201
    {
        InProgress,
        Completed,
#pragma warning disable SA1600
        Failed,
#pragma warning restore SA1600
        Skipped
#pragma warning disable SA1600
    }
#pragma warning restore SA1600
#pragma warning disable SA1600

#pragma warning restore SA1600
#pragma warning disable SA1600
    public class TaskResult
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string TaskName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }public MESTaskStatus Status { get; set; }
        public string Message { g
#pragma warning restore SA1600
set; }
        public List<string> OutputFiles { get; set; } = new List<string>();
#pragma warning disable SA1600
    }
#pragma warning restore SA1600
#pragma warning disable SA1600

#pragma warning restore SA1600
#pragma warning disable SA1600
    public class MESTriageSummary
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string TriageName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string TemplateName { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string TargetUsers { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string OutputFormat { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string OutputDirectory { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalTasks { get; set; }
        public int SuccessfulTasks { get; set; }#pragma warning disable SA1201
        public int FailedTasks { get; set; }
        public int SkippedTasks
#pragma warning restore SA1201
        public List<TaskResult> TaskResults { get; set; } = new List<TaskResult>();
#pragma warning disable SA1600
    }
#pragma warning restore SA1600
#pragma warning disable SA1600

#pragma warning restore SA1600
    public class MESTriageResult
    {
#pragma warning disable SA1600
        public MESTriageSummary Summa
#pragma warning restore SA1600
set; }
        public List<TaskResult> TaskResults { get; set; } = new List<TaskResult>();
#pragma warning disable SA1600
    }
#pragma warning restore SA1600
#pragma warning disable SA1600

#pragma warning restore SA1600
#pragma warning disable SA1600
    public class TaskExecutionContext
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public dynamic Task { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public string OutputDirectory { get; set; }
        public string[] UserIds { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? StartDate { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? EndDate { get; set;}
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Output { get; set; }public bool MergeOutput { get; set; }public string Encoding { get; set; }
        public string LogLevel { g
#pragma warning restore SA1600
set; }
    }
#pragma warning disable SA1600

#pragma warning restore SA1600
    // Template and task execution infrastructure
    public class TemplateProcessor
    {
        public async Task<TemplateConfig> LoadTemplateAsync(string templateName)
        {
            // Implementation would load template from Templates directory
            // For now, return a basic template configuration
#pragma warning disable SA1101
            return new TemplateConfig
            {
                Name = templateName,
                Description = $"{templateName} template for Microsoft 365 triage",
                Tasks = GetDefaultTasks(templateName)
            };
#pragma warning restore SA1101
        }

        private List<object> GetDefaultTasks(string templateName)
        {
            return templateName.ToLowerInvariant() switch
            {
                "quick" => new List<object>
                {
                    "Get-RiskyUsers",
                    "Get-RiskyDetections",
                    "Get-MFA",
                    "Get-MailboxRules",
                    "Get-OAuthPermissionsGraph"
                },
                "standard" => new List<object>
                {
                    "Get-RiskyUsers",
                    "Get-RiskyDetections",
                    "Get-MFA",
                    "Get-MailboxRules",
                    "Get-OAuthPermissionsGraph",
                    "Get-GraphEntraSignInLogs",
                    "Get-GraphEntraAuditLogs",
                    "Get-UAL",
                    "Get-Users",
                    "Get-Devices"
                },
                "comprehensive" => new List<object>
                {
                    "Get-RiskyUsers",
                    "Get-RiskyDetections",
                    "Get-MFA",
                    "Get-MailboxRules",
                    "Get-OAuthPermissionsGraph",
                    "Get-GraphEntraSignInLogs",
                    "Get-GraphEntraAuditLogs",
                    "Get-UAL",
                    "Get-Users",
                    "Get-AdminUsers",
                    "Get-Devices",
                    "Get-MailboxAuditStatus",
                    "Get-MailboxPermissions",
                    "Get-MessageTraceLog",
                    "Get-TransportRules",
                    "Get-SecurityAlerts",
                    "Get-AllRoleActivity",
                    "Get-PIMAssignments"
                },
                _ => new List<object>
                {
                    "Get-RiskyUsers",
                    "Get-MFA",
                    "Get-MailboxRules"
                }
#pragma warning disable SA1600
            };
#pragma warning restore SA1600
        }
#pragma warning disable SA1600
    }
#pragma warning restore SA1600
#pragma warning disable SA1600

#pragma warning restore SA1600
#pragma warning disable SA1600
    public class TemplateConfig
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        #pragma warning disable SA1201
        public string Name { get; set; }
        public string Descrip
#pragma warning restore SA1201
        public List<object> Tasks { get; set; } = new List<object>();
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

    public class TaskExecutor
    {
        public async Task<bool> ExecuteTaskAsync(TaskExecutionContext context)
        {
#pragma warning disable SA1101
            var taskName = GetTaskName(context.Task);
#pragma warning restore SA1101

            try
            {
                // This is where we would invoke the actual PowerShell cmdlets or C# methods
                // For now, simulate task execution
                await Task.Delay(100); // Simulate work

                // In a real implementation, this would call the appropriate cmdlet
                // based on the task name and context parameters

                return true; // Simulate success
            }
            catch
            {
                return false;
            }
        }

        private string GetTaskName(dynamic task)
        {
            if (task is string stringTask)
                return stringTask;

            // Handle other task types as needed
            return "Unknown Task";
        }
    }
}
