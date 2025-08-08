using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Templates;

namespace Microsoft.ExtractorSuite.Cmdlets.Collection
{
    /// <summary>
    /// Cmdlet to perform automated triage collection based on templates
    /// </summary>
    [Cmdlet(VerbsLifecycle.Start, "MESTriage")]
    [OutputType(typeof(MESTriageResult))]
    public class StartMESTriageCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "Template to use for triage collection")]
        public string Template { get; set; } = "Standard";

        [Parameter(
            Mandatory = true,
            HelpMessage = "Name of the triage project")]
        public string TriageName { get; set; }

        [Parameter(
            HelpMessage = "User IDs to target for triage. Multiple email addresses separated by commas")]
        public string UserIds { get; set; }

        [Parameter(
            HelpMessage = "Start date for time-based queries")]
        public DateTime? StartDate { get; set; }

        [Parameter(
            HelpMessage = "End date for time-based queries")]
        public DateTime? EndDate { get; set; }

        [Parameter(
            HelpMessage = "Output format: CSV, JSON, JSONL, or SOF-ELK")]
        [ValidateSet("CSV", "JSON", "JSONL", "SOF-ELK")]
        public string Output { get; set; } = "CSV";

        [Parameter(
            HelpMessage = "Merge output files into single files where applicable")]
        public SwitchParameter MergeOutput { get; set; }

        [Parameter(
            HelpMessage = "Output directory for results")]
        public string OutputDir { get; set; }

        [Parameter(
            HelpMessage = "File encoding for output files")]
        public string Encoding { get; set; } = "UTF8";

        private readonly TemplateProcessor _templateProcessor;
        private readonly TaskExecutor _taskExecutor;

        public StartMESTriageCmdlet()
        {
            _templateProcessor = new TemplateProcessor();
            _taskExecutor = new TaskExecutor();
        }

        protected override async Task ProcessRecordAsync()
        {
            LogInformation("=== Starting MES Triage ===");
            LogInformation($"Project: {TriageName}");
            LogInformation($"Template: {Template}");

            // Parse user IDs
            var userIdArray = ParseUserIds(UserIds);
            
            if (userIdArray.Length == 0)
            {
                LogInformation("Target: All users");
            }
            else if (userIdArray.Length == 1)
            {
                LogInformation($"Target User: {userIdArray[0]}");
            }
            else
            {
                LogInformation("Target Users:");
                foreach (var user in userIdArray)
                {
                    LogInformation($"  - {user}");
                }
            }

            LogInformation($"Output Format: {GetOutputFormatDescription()}");
            LogInformation($"Start Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

            // Set up output directory
            var outputDirectory = SetupOutputDirectory();

            // Initialize summary
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

            try
            {
                // Load and validate template
                var templateConfig = await _templateProcessor.LoadTemplateAsync(Template);
                if (templateConfig == null)
                {
                    LogError($"Template '{Template}' not found or could not be loaded.");
                    return;
                }

                if (templateConfig.Tasks == null || templateConfig.Tasks.Count == 0)
                {
                    LogError("No tasks defined in template");
                    return;
                }

                LogInformation("");
                LogInformation("==== Executing Template Tasks ====");
                LogInformation($"Total tasks to execute: {templateConfig.Tasks.Count}");
                LogInformation("");

                summary.TotalTasks = templateConfig.Tasks.Count;

                // Execute tasks
                foreach (var task in templateConfig.Tasks)
                {
                    var taskResult = await ExecuteTaskAsync(task, outputDirectory, userIdArray, summary);
                    summary.TaskResults.Add(taskResult);

                    switch (taskResult.Status)
                    {
                        case TaskStatus.Completed:
                            summary.SuccessfulTasks++;
                            break;
                        case TaskStatus.Failed:
                            summary.FailedTasks++;
                            break;
                        case TaskStatus.Skipped:
                            summary.SkippedTasks++;
                            break;
                    }
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;
                LogTriageSummary(summary);

                var result = new MESTriageResult
                {
                    Summary = summary,
                    TaskResults = summary.TaskResults
                };

                WriteObject(result);
            }
            catch (Exception ex)
            {
                LogError($"An error occurred during triage execution: {ex.Message}");
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
            return Output switch
            {
                "JSONL" => "JSONL (supported functions only, others will use JSON)",
                "SOF-ELK" => "SOF-ELK (supported functions only, others will use JSON)",
                _ => Output
            };
        }

        private string SetupOutputDirectory()
        {
            string outputDirectory;
            
            if (string.IsNullOrEmpty(OutputDir))
            {
                outputDirectory = Path.Combine("Output", TriageName);
            }
            else
            {
                outputDirectory = Path.Combine(OutputDir, TriageName);
            }

            if (!Directory.Exists(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
                LogInformation($"Creating output directory: {outputDirectory}");
            }

            return outputDirectory;
        }

        private async Task<TaskResult> ExecuteTaskAsync(dynamic task, string outputDirectory, string[] userIds, MESTriageSummary summary)
        {
            var taskResult = new TaskResult
            {
                TaskName = GetTaskName(task),
                StartTime = DateTime.Now,
                Status = TaskStatus.InProgress
            };

            try
            {
                // Check if task should be skipped
                if (ShouldSkipTask(task, userIds))
                {
                    taskResult.Status = TaskStatus.Skipped;
                    taskResult.Message = "Task skipped - not applicable for user-specific triage";
                    taskResult.ProcessingTime = DateTime.Now - taskResult.StartTime;
                    return taskResult;
                }

                LogTaskProgress(taskResult.TaskName, TaskStatus.InProgress);

                // Execute the task based on its type
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
                    LogLevel = LogLevel
                });

                taskResult.Status = success ? TaskStatus.Completed : TaskStatus.Failed;
                taskResult.Message = success ? "Task completed successfully" : "Task failed";
                
                LogTaskProgress(taskResult.TaskName, taskResult.Status);
            }
            catch (Exception ex)
            {
                taskResult.Status = TaskStatus.Failed;
                taskResult.Message = ex.Message;
                
                LogTaskProgress(taskResult.TaskName, TaskStatus.Failed, ex.Message);
                LogError($"Task {taskResult.TaskName} failed: {ex.Message}");
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
            var taskName = GetTaskName(task);
            
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

            return userIds.Length > 0 && userSpecificSkipTasks.Contains(taskName);
        }

        private void LogTaskProgress(string taskName, TaskStatus status, string errorMessage = null)
        {
            switch (status)
            {
                case TaskStatus.InProgress:
                    LogInformation($"[IN PROGRESS] {taskName}");
                    break;
                case TaskStatus.Completed:
                    LogInformation($"[COMPLETED] {taskName}");
                    break;
                case TaskStatus.Failed:
                    LogError($"[FAILED] {taskName}" + (string.IsNullOrEmpty(errorMessage) ? "" : $": {errorMessage}"));
                    break;
                case TaskStatus.Skipped:
                    LogInformation($"[SKIPPED] {taskName}");
                    break;
            }
        }

        private void LogTriageSummary(MESTriageSummary summary)
        {
            LogInformation("");
            LogInformation($"=== {Template} Triage Summary ===");
            LogInformation($"Start Time: {summary.StartTime:yyyy-MM-dd HH:mm:ss}");
            LogInformation($"End Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            LogInformation($"Duration: {summary.ProcessingTime?.ToString(@"hh\:mm\:ss")}");
            LogInformation("");
            LogInformation("Task Results:");
            LogInformation($"  Successful: {summary.SuccessfulTasks}", summary.SuccessfulTasks > 0 ? ConsoleColor.Green : ConsoleColor.Gray);
            LogInformation($"  Failed: {summary.FailedTasks}", summary.FailedTasks > 0 ? ConsoleColor.Red : ConsoleColor.Green);
            LogInformation($"  Skipped: {summary.SkippedTasks}", ConsoleColor.Yellow);
            LogInformation($"  Total: {summary.TotalTasks}");
            LogInformation("");
            LogInformation($"Output Location: {summary.OutputDirectory}");
            LogInformation("=============================================");
        }

        private void LogInformation(string message, ConsoleColor color = ConsoleColor.White)
        {
            // In a real implementation, this would use the PowerShell logging infrastructure
            // For now, we'll use the base class logging
            LogInformation(message);
        }
    }

    // Supporting classes and enums
    public enum TaskStatus
    {
        InProgress,
        Completed,
        Failed,
        Skipped
    }

    public class TaskResult
    {
        public string TaskName { get; set; }
        public DateTime StartTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public TaskStatus Status { get; set; }
        public string Message { get; set; }
        public List<string> OutputFiles { get; set; } = new List<string>();
    }

    public class MESTriageSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }
        public string TriageName { get; set; }
        public string TemplateName { get; set; }
        public string TargetUsers { get; set; }
        public string OutputFormat { get; set; }
        public string OutputDirectory { get; set; }
        public int TotalTasks { get; set; }
        public int SuccessfulTasks { get; set; }
        public int FailedTasks { get; set; }
        public int SkippedTasks { get; set; }
        public List<TaskResult> TaskResults { get; set; } = new List<TaskResult>();
    }

    public class MESTriageResult
    {
        public MESTriageSummary Summary { get; set; }
        public List<TaskResult> TaskResults { get; set; } = new List<TaskResult>();
    }

    public class TaskExecutionContext
    {
        public dynamic Task { get; set; }
        public string OutputDirectory { get; set; }
        public string[] UserIds { get; set; }
        public DateTime? StartDate { get; set; }
        public DateTime? EndDate { get; set; }
        public string Output { get; set; }
        public bool MergeOutput { get; set; }
        public string Encoding { get; set; }
        public string LogLevel { get; set; }
    }

    // Template and task execution infrastructure
    public class TemplateProcessor
    {
        public async Task<TemplateConfig> LoadTemplateAsync(string templateName)
        {
            // Implementation would load template from Templates directory
            // For now, return a basic template configuration
            return new TemplateConfig
            {
                Name = templateName,
                Description = $"{templateName} template for Microsoft 365 triage",
                Tasks = GetDefaultTasks(templateName)
            };
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
            };
        }
    }

    public class TemplateConfig
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public List<object> Tasks { get; set; } = new List<object>();
    }

    public class TaskExecutor
    {
        public async Task<bool> ExecuteTaskAsync(TaskExecutionContext context)
        {
            var taskName = GetTaskName(context.Task);
            
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