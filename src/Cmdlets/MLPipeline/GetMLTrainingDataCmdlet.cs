using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Authentication;
using Microsoft.ExtractorSuite.Core.Logging;
using Microsoft.ExtractorSuite.Models.Exchange;
using Microsoft.ExtractorSuite.Models.Graph;

namespace Microsoft.ExtractorSuite.Cmdlets.MLPipeline
{
    [Cmdlet(VerbsCommon.Get, "MLTrainingData")]
    [OutputType(typeof(MLTrainingDataResult))]

    public class GetMLTrainingDataCmdlet : AsyncBaseCmdlet

    {
        [Parameter(HelpMessage = "Data sources to include in training data. Valid values: SignInLogs, AuditLogs, MailboxAudit, UAL, SecurityAlerts, RiskyUsers")]
        [ValidateSet("SignInLogs", "AuditLogs", "MailboxAudit", "UAL", "SecurityAlerts", "RiskyUsers")]

        public string[] DataSources { get; set; } = { "SignInLogs", "AuditLogs", "UAL" };


        [Parameter(HelpMessage = "Start date for data collection. Default: 30 days ago")]

        public DateTime StartDate { get; set; } = DateTime.UtcNow.AddDays(-30);


        [Parameter(HelpMessage = "End date for data collection. Default: Now")]

        public DateTime EndDate { get; set; } = DateTime.UtcNow;


        [Parameter(HelpMessage = "Comma-separated list of user IDs to filter results")]

        public string? UserIds { get; set; }


        [Parameter(HelpMessage = "Output directory for training data files")]

        public string? OutputDirectory { get; set; }


        [Parameter(HelpMessage = "Include risk simulation data in training set")]
        public SwitchParameter IncludeRiskSimulation { get; set; }

        [Parameter(HelpMessage = "Number of synthetic records to generate for risk simulation")]
        [ValidateRange(1, 10000)]

        public int SyntheticRecordCount { get; set; } = 1000;


        [Parameter(HelpMessage = "Random seed for reproducible synthetic data generation")]

        public int? RandomSeed { get; set; }


        [Parameter(HelpMessage = "Include data quality metrics and validation")]
        public SwitchParameter IncludeDataQuality { get; set; }

        [Parameter(HelpMessage = "Split data into train/validation/test sets")]
        public SwitchParameter SplitDataSets { get; set; }

        [Parameter(HelpMessage = "Training set percentage (0.0-1.0). Default: 0.7")]
        [ValidateRange(0.0, 1.0)]

        public double TrainingSetPercentage { get; set; } = 0.7;


        [Parameter(HelpMessage = "Validation set percentage (0.0-1.0). Default: 0.15")]
        [ValidateRange(0.0, 1.0)]

        public double ValidationSetPercentage { get; set; } = 0.15;




        private readonly MLDataProcessor _dataProcessor;



        private readonly RiskSimulator _riskSimulator;


        private readonly DataQualityAnalyzer _qualityAnalyzer;


        public GetMLTrainingDataCmdlet()

        {


            _dataProcessor = new MLDataProcessor();


            _riskSimulator = new RiskSimulator();


            _qualityAnalyzer = new DataQualityAnalyzer();

        }

        protected override void ProcessRecord()
        {

            WriteWarning("⚠️  IMPORTANT: This pipeline is intended for use with fine-tuned models from OpenPipe.");


            WriteWarning("⚠️  Generate your own data on a developer tenant and do not utilize customer data unlawfully.");


            WriteWarning("⚠️  This tool is for research, development, and legitimate security testing purposes only.");


            WriteWarning("⚠️  Ensure compliance with all applicable laws, regulations, and data protection requirements.");


            var result = RunAsyncOperation(
                async (progress, cancellationToken) => await GenerateMLTrainingDataAsync(progress, cancellationToken),
                "ML Training Data Generation"
            );

            WriteObject(result);
        }

        private async Task<MLTrainingDataResult> GenerateMLTrainingDataAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            var startTime = DateTime.UtcNow;

            var outputDir = GetOutputDirectory();


            var summary = new MLTrainingDataSummary
            {
                StartTime = startTime,
                DataSources = DataSources,
                DateRange = $"{StartDate:yyyy-MM-dd} to {EndDate:yyyy-MM-dd}",
                OutputDirectory = outputDir
            };


            try
            {
                // Collect real data from specified sources

                var realData = await CollectRealDataAsync(progress, cancellationToken);

                summary.RealRecordsCollected = realData.Count;

                // Generate synthetic risk simulation data if requested
                List<MLTrainingRecord> syntheticData = new();

                if (IncludeRiskSimulation)
                {

                    var seed = RandomSeed ?? Environment.TickCount;


                    syntheticData = await GenerateSyntheticRiskDataAsync(seed, cancellationToken);

                    summary.SyntheticRecordsGenerated = syntheticData.Count;
                }


                // Combine real and synthetic data
                var allData = realData.Concat(syntheticData).ToList();
                summary.TotalRecords = allData.Count;

                // Analyze data quality if requested

                if (IncludeDataQuality)
                {

                    var qualityMetrics = await _qualityAnalyzer.AnalyzeDataQualityAsync(allData, cancellationToken);

                    summary.DataQualityMetrics = qualityMetrics;
                }


                // Split data into train/validation/test sets if requested

                var dataSets = SplitDataSets
                    ? _dataProcessor.SplitDataSets(allData, TrainingSetPercentage, ValidationSetPercentage)
                    : new DataSetSplit { Training = allData, Validation = new(), Test = new() };


                // Export data in JSONL format
                var exportResults = await ExportTrainingDataAsync(dataSets, outputDir, cancellationToken);
                summary.OutputFiles = exportResults;

                // Generate metadata and documentation
                await GenerateMetadataAsync(dataSets, outputDir, cancellationToken);

                summary.ProcessingTime = DateTime.UtcNow - startTime;
                summary.Success = true;

                return new MLTrainingDataResult
                {
                    Summary = summary,
                    DataSets = dataSets,
                    QualityMetrics = summary.DataQualityMetrics
                };
            }
            catch (Exception ex)
            {
                summary.ProcessingTime = DateTime.UtcNow - startTime;
                summary.Success = false;
                summary.ErrorMessage = ex.Message;
                throw;
            }
        }

        private async Task<List<MLTrainingRecord>> CollectRealDataAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            var allRecords = new List<MLTrainingRecord>();

            var totalSources = DataSources.Length;

            var currentSource = 0;


            foreach (var dataSource in DataSources)
            {
                currentSource++;
                progress?.Report(new Core.AsyncOperations.TaskProgress
                {
                    Activity = "Collecting Training Data",
                    CurrentOperation = $"Processing {dataSource}",
                    PercentComplete = (currentSource * 100) / totalSources,
                    ItemsProcessed = currentSource,
                    TotalItems = totalSources
                });

                try
                {

                    var records = await CollectDataFromSourceAsync(dataSource, cancellationToken);

                    allRecords.AddRange(records);
                }
                catch (Exception ex)
                {

                    WriteWarning($"Failed to collect data from {dataSource}: {ex.Message}");

                }
            }


            return allRecords;
        }

        private async Task<List<MLTrainingRecord>> CollectDataFromSourceAsync(string dataSource, CancellationToken cancellationToken)
        {
            switch (dataSource.ToLower())
            {
                case "signinlogs":

                    return await CollectSignInLogsAsync(cancellationToken);

                case "auditlogs":

                    return await CollectAuditLogsAsync(cancellationToken);

                case "mailboxaudit":

                    return await CollectMailboxAuditLogsAsync(cancellationToken);

                case "ual":

                    return await CollectUALDataAsync(cancellationToken);

                case "securityalerts":

                    return await CollectSecurityAlertsAsync(cancellationToken);

                case "riskyusers":

                    return await CollectRiskyUsersAsync(cancellationToken);

                default:
                    throw new ArgumentException($"Unknown data source: {dataSource}");
            }
        }

        private async Task<List<MLTrainingRecord>> CollectSignInLogsAsync(CancellationToken cancellationToken)
        {

            if (!RequireGraphConnection()) return new List<MLTrainingRecord>();


            var records = new List<MLTrainingRecord>();

            var graphClient = AuthManager.GraphClient;

            if (graphClient == null) return records;

            try
            {

                var filter = $"createdDateTime ge {StartDate:yyyy-MM-ddTHH:mm:ssZ} and createdDateTime le {EndDate:yyyy-MM-ddTHH:mm:ssZ}";


                if (!string.IsNullOrEmpty(UserIds))
                {

                    var userIds = UserIds.Split(',').Select(u => u.Trim()).ToList();

                    var userFilter = string.Join(" or ", userIds.Select(u => $"userId eq '{u}'"));
                    filter = $"({filter}) and ({userFilter})";
                }


                var signIns = await graphClient.Identity.SignIns.GetAsync(config =>
                {
                    config.QueryParameters.Filter = filter;
                    config.QueryParameters.Top = 999;
                }, cancellationToken);

                if (signIns?.Value != null)
                {
                    foreach (var signIn in signIns.Value)
                    {
                        var record = new MLTrainingRecord
                        {
                            Id = signIn.Id ?? Guid.NewGuid().ToString(),
                            Timestamp = signIn.CreatedDateTime?.DateTime ?? DateTime.UtcNow,
                            DataSource = "SignInLogs",
                            RecordType = "SignIn",
                            Features = new Dictionary<string, object>
                            {
                                ["userId"] = signIn.UserId ?? "",
                                ["userPrincipalName"] = signIn.UserPrincipalName ?? "",
                                ["ipAddress"] = signIn.IpAddress ?? "",
                                ["location"] = signIn.Location?.City ?? "",
                                ["country"] = signIn.Location?.CountryOrRegion ?? "",
                                ["appId"] = signIn.AppId ?? "",
                                ["appDisplayName"] = signIn.AppDisplayName ?? "",
                                ["clientAppUsed"] = signIn.ClientAppUsed ?? "",
                                ["riskLevel"] = signIn.RiskLevelDuringSignIn?.ToString() ?? "",
                                ["riskState"] = signIn.RiskState?.ToString() ?? "",
                                ["conditionalAccessStatus"] = signIn.ConditionalAccessStatus?.ToString() ?? "",
                                ["isInteractive"] = signIn.IsInteractive?.ToString() ?? "",
                                ["deviceId"] = signIn.DeviceDetail?.DeviceId ?? "",
                                ["operatingSystem"] = signIn.DeviceDetail?.OperatingSystem ?? "",
                                ["browser"] = signIn.DeviceDetail?.Browser ?? "",
                                ["isCompliant"] = signIn.DeviceDetail?.IsCompliant?.ToString() ?? "",
                                ["isManaged"] = signIn.DeviceDetail?.IsManaged?.ToString() ?? "",
                                ["trustType"] = signIn.DeviceDetail?.TrustType?.ToString() ?? ""
                            },
                            Labels = new Dictionary<string, object>
                            {
                                ["riskLevel"] = signIn.RiskLevelDuringSignIn?.ToString() ?? "none",
                                ["isRisky"] = signIn.RiskLevelDuringSignIn?.ToString() != "none",
                                ["conditionalAccessBlocked"] = signIn.ConditionalAccessStatus?.ToString() == "blocked"
                            }
                        };
                        records.Add(record);
                    }
                }
            }
            catch (Exception ex)
            {

                WriteWarning($"Error collecting sign-in logs: {ex.Message}");

            }

            return records;
        }

        private async Task<List<MLTrainingRecord>> CollectAuditLogsAsync(CancellationToken cancellationToken)
        {

            if (!RequireGraphConnection()) return new List<MLTrainingRecord>();


            var records = new List<MLTrainingRecord>();

            var graphClient = AuthManager.GraphClient;

            if (graphClient == null) return records;

            try
            {

                var filter = $"activityDateTime ge {StartDate:yyyy-MM-ddTHH:mm:ssZ} and activityDateTime le {EndDate:yyyy-MM-ddTHH:mm:ssZ}";


                if (!string.IsNullOrEmpty(UserIds))
                {

                    var userIds = UserIds.Split(',').Select(u => u.Trim()).ToList();

                    var userFilter = string.Join(" or ", userIds.Select(u => $"initiatedBy.user.userPrincipalName eq '{u}'"));
                    filter = $"({filter}) and ({userFilter})";
                }


                var audits = await graphClient.AuditLogs.DirectoryAudits.GetAsync(config =>
                {
                    config.QueryParameters.Filter = filter;
                    config.QueryParameters.Top = 999;
                }, cancellationToken);

                if (audits?.Value != null)
                {
                    foreach (var audit in audits.Value)
                    {
                        var record = new MLTrainingRecord
                        {
                            Id = audit.Id ?? Guid.NewGuid().ToString(),
                            Timestamp = audit.ActivityDateTime?.DateTime ?? DateTime.UtcNow,
                            DataSource = "AuditLogs",
                            RecordType = "DirectoryAudit",
                            Features = new Dictionary<string, object>
                            {
                                ["category"] = audit.Category ?? "",
                                ["correlationId"] = audit.CorrelationId ?? "",
                                ["result"] = audit.Result?.ToString() ?? "",
                                ["resultReason"] = audit.ResultReason ?? "",
                                ["activityDisplayName"] = audit.ActivityDisplayName ?? "",
                                ["loggedByService"] = audit.LoggedByService ?? "",
                                ["operationType"] = audit.OperationType?.ToString() ?? "",
                                ["initiatedByUser"] = audit.InitiatedBy?.User?.UserPrincipalName ?? "",
                                ["initiatedByApp"] = audit.InitiatedBy?.App?.DisplayName ?? "",
                                ["targetResourceType"] = audit.TargetResources?.FirstOrDefault()?.Type ?? "",
                                ["targetResourceDisplayName"] = audit.TargetResources?.FirstOrDefault()?.DisplayName ?? "",
                                ["userAgent"] = audit.UserAgent ?? ""
                            },
                            Labels = new Dictionary<string, object>
                            {
                                ["isSuccessful"] = audit.Result?.ToString() == "success",
                                ["isUserActivity"] = !string.IsNullOrEmpty(audit.InitiatedBy?.User?.UserPrincipalName),
                                ["isAppActivity"] = !string.IsNullOrEmpty(audit.InitiatedBy?.App?.DisplayName)
                            }
                        };
                        records.Add(record);
                    }
                }
            }
            catch (Exception ex)
            {

                WriteWarning($"Error collecting audit logs: {ex.Message}");

            }

            return records;
        }

        private async Task<List<MLTrainingRecord>> CollectMailboxAuditLogsAsync(CancellationToken cancellationToken)
        {

            if (!RequireGraphConnection()) return new List<MLTrainingRecord>();


            var records = new List<MLTrainingRecord>();

            var exchangeClient = new Core.Exchange.ExchangeRestClient(AuthManager);


            try
            {
                var mailboxes = await exchangeClient.GetMailboxesAsync(cancellationToken);
                var filteredMailboxes = mailboxes;


                if (!string.IsNullOrEmpty(UserIds))
                {

                    var userIds = UserIds.Split(',').Select(u => u.Trim()).ToList();

                    filteredMailboxes = mailboxes.Where(m => userIds.Contains(m)).ToArray();
                }


                foreach (var mailbox in filteredMailboxes.Take(10)) // Limit for performance
                {
                    try
                    {

                        var auditLogs = exchangeClient.GetMailboxAuditLogAsync(
                            mailbox, StartDate, EndDate, null, cancellationToken);


                        await foreach (var auditLog in auditLogs.WithCancellation(cancellationToken))
                        {

                            var record = new MLTrainingRecord
                            {
                                Id = Guid.NewGuid().ToString(),
                                Timestamp = auditLog.LastAccessed,
                                DataSource = "MailboxAudit",
                                RecordType = "MailboxAccess",
                                Features = new Dictionary<string, object>
                                {
                                    ["mailbox"] = mailbox,
                                    ["operation"] = auditLog.Operation ?? "",
                                    ["operationResult"] = auditLog.OperationResult ?? "",
                                    ["logonType"] = auditLog.LogonType ?? "",
                                    ["logonUser"] = auditLog.LogonUserDisplayName ?? "",
                                    ["clientInfo"] = auditLog.ClientInfoString ?? "",
                                    ["clientIP"] = auditLog.ClientIPAddress ?? "",
                                    ["clientProcess"] = auditLog.ClientProcessName ?? "",
                                    ["folderPath"] = auditLog.FolderPathName ?? "",
                                    ["itemSubject"] = auditLog.ItemSubject ?? ""
                                },
                                Labels = new Dictionary<string, object>
                                {
                                    ["isSuccessful"] = auditLog.OperationResult?.ToString() == "Succeeded",
                                    ["isExternalAccess"] = !string.IsNullOrEmpty(auditLog.LogonUserDisplayName) &&
                                                          auditLog.LogonUserDisplayName != mailbox,
                                    ["isSuspiciousOperation"] = IsSuspiciousMailboxOperation(auditLog.Operation)
                                }
                            };

                            records.Add(record);
                        }
                    }
                    catch (Exception ex)
                    {

                        WriteWarning($"Error collecting mailbox audit logs for {mailbox}: {ex.Message}");

                    }
                }
            }
            catch (Exception ex)
            {

                WriteWarning($"Error collecting mailbox audit logs: {ex.Message}");

            }

            return records;
        }

        private async Task<List<MLTrainingRecord>> CollectUALDataAsync(CancellationToken cancellationToken)
        {

            if (!RequireGraphConnection()) return new List<MLTrainingRecord>();


            var records = new List<MLTrainingRecord>();

            var exchangeClient = new Core.Exchange.ExchangeRestClient(AuthManager);


            try
            {

                var ualResult = await exchangeClient.SearchUnifiedAuditLogAsync(
                    StartDate, EndDate, null, null, null,
                    !string.IsNullOrEmpty(UserIds) ? UserIds.Split(',').Select(u => u.Trim()).ToArray() : null,
                    5000, cancellationToken);


                if (ualResult?.Records != null)
                {
                    foreach (var ualRecord in ualResult.Records)
                    {
                        var record = new MLTrainingRecord
                        {
                            Id = ualRecord.Id ?? Guid.NewGuid().ToString(),
                            Timestamp = ualRecord.CreationTime,
                            DataSource = "UAL",
                            RecordType = ualRecord.RecordType ?? "Unknown",
                            Features = new Dictionary<string, object>
                            {
                                ["recordType"] = ualRecord.RecordType ?? "",
                                ["operation"] = ualRecord.Operation ?? "",
                                ["organizationId"] = ualRecord.OrganizationId ?? "",
                                ["userType"] = ualRecord.UserType ?? "",
                                ["userKey"] = ualRecord.UserKey ?? "",
                                ["workload"] = ualRecord.Workload ?? "",
                                ["resultStatus"] = ualRecord.ResultStatus ?? "",
                                ["objectId"] = ualRecord.ObjectId ?? "",
                                ["userId"] = ualRecord.UserId ?? "",
                                ["clientIP"] = ualRecord.ClientIP ?? "",
                                ["auditData"] = ualRecord.AuditData ?? ""
                            },
                            Labels = new Dictionary<string, object>
                            {
                                ["isSuccessful"] = ualRecord.ResultStatus?.ToString() == "Success",
                                ["isUserActivity"] = !string.IsNullOrEmpty(ualRecord.UserId),
                                ["isAdminActivity"] = ualRecord.UserType?.ToString() == "Admin"
                            }
                        };
                        records.Add(record);
                    }
                }
            }
            catch (Exception ex)
            {

                WriteWarning($"Error collecting UAL data: {ex.Message}");

            }

            return records;
        }

        private async Task<List<MLTrainingRecord>> CollectSecurityAlertsAsync(CancellationToken cancellationToken)
        {

            if (!RequireGraphConnection()) return new List<MLTrainingRecord>();


            var records = new List<MLTrainingRecord>();

            var graphClient = AuthManager.GraphClient;

            if (graphClient == null) return records;

            try
            {
                var alerts = await graphClient.Security.Alerts.GetAsync(config =>
                {
                    config.QueryParameters.Top = 999;
                }, cancellationToken);

                if (alerts?.Value != null)
                {
                    foreach (var alert in alerts.Value)
                    {
                        var record = new MLTrainingRecord
                        {
                            Id = alert.Id ?? Guid.NewGuid().ToString(),
                            Timestamp = alert.CreatedDateTime?.DateTime ?? DateTime.UtcNow,
                            DataSource = "SecurityAlerts",
                            RecordType = "SecurityAlert",
                            Features = new Dictionary<string, object>
                            {
                                ["title"] = alert.Title ?? "",
                                ["category"] = alert.Category ?? "",
                                ["severity"] = alert.Severity?.ToString() ?? "",
                                ["status"] = alert.Status?.ToString() ?? "",
                                ["eventDateTime"] = alert.EventDateTime?.DateTime?.ToString() ?? "",
                                ["assignedTo"] = alert.AssignedTo ?? "",
                                ["description"] = alert.Description ?? "",
                                ["detectionSource"] = alert.DetectionSource ?? "",
                                ["affectedUser"] = alert.AffectedUser ?? "",
                                ["affectedHost"] = alert.AffectedHost ?? "",
                                ["confidence"] = alert.Confidence?.ToString() ?? "",
                                ["activityGroupName"] = alert.ActivityGroupName ?? "",
                                ["vendor"] = alert.Vendor ?? "",
                                ["provider"] = alert.Provider ?? ""
                            },
                            Labels = new Dictionary<string, object>
                            {
                                ["severityLevel"] = alert.Severity?.ToString() ?? "unknown",
                                ["isHighSeverity"] = alert.Severity?.ToString() == "high",
                                ["isActive"] = alert.Status?.ToString() == "active",
                                ["hasAssignee"] = !string.IsNullOrEmpty(alert.AssignedTo)
                            }
                        };
                        records.Add(record);
                    }
                }
            }
            catch (Exception ex)
            {

                WriteWarning($"Error collecting security alerts: {ex.Message}");

            }

            return records;
        }

        private async Task<List<MLTrainingRecord>> CollectRiskyUsersAsync(CancellationToken cancellationToken)
        {

            if (!RequireGraphConnection()) return new List<MLTrainingRecord>();


            var records = new List<MLTrainingRecord>();

            var graphClient = AuthManager.GraphClient;

            if (graphClient == null) return records;

            try
            {
                var riskyUsers = await graphClient.IdentityProtection.RiskyUsers.GetAsync(config =>
                {
                    config.QueryParameters.Top = 999;
                }, cancellationToken);

                if (riskyUsers?.Value != null)
                {
                    foreach (var riskyUser in riskyUsers.Value)
                    {
                        var record = new MLTrainingRecord
                        {
                            Id = riskyUser.Id ?? Guid.NewGuid().ToString(),
                            Timestamp = riskyUser.RiskLastUpdatedDateTime?.DateTime ?? DateTime.UtcNow,
                            DataSource = "RiskyUsers",
                            RecordType = "RiskyUser",
                            Features = new Dictionary<string, object>
                            {
                                ["userId"] = riskyUser.UserId ?? "",
                                ["userPrincipalName"] = riskyUser.UserPrincipalName ?? "",
                                ["userDisplayName"] = riskyUser.UserDisplayName ?? "",
                                ["riskLevel"] = riskyUser.RiskLevel?.ToString() ?? "",
                                ["riskState"] = riskyUser.RiskState?.ToString() ?? "",
                                ["riskDetail"] = riskyUser.RiskDetail?.ToString() ?? "",
                                ["isDeleted"] = riskyUser.IsDeleted?.ToString() ?? "",
                                ["isProcessing"] = riskyUser.IsProcessing?.ToString() ?? ""
                            },
                            Labels = new Dictionary<string, object>
                            {
                                ["riskLevel"] = riskyUser.RiskLevel?.ToString() ?? "none",
                                ["isHighRisk"] = riskyUser.RiskLevel?.ToString() == "high",
                                ["isMediumRisk"] = riskyUser.RiskLevel?.ToString() == "medium",
                                ["isLowRisk"] = riskyUser.RiskLevel?.ToString() == "low",
                                ["isDeleted"] = riskyUser.IsDeleted ?? false,
                                ["isProcessing"] = riskyUser.IsProcessing ?? false
                            }
                        };
                        records.Add(record);
                    }
                }
            }
            catch (Exception ex)
            {

                WriteWarning($"Error collecting risky users: {ex.Message}");

            }

            return records;
        }

        private async Task<List<MLTrainingRecord>> GenerateSyntheticRiskDataAsync(int seed, CancellationToken cancellationToken)
        {

            return await _riskSimulator.GenerateSyntheticRiskDataAsync(
                seed, SyntheticRecordCount, StartDate, EndDate, cancellationToken);

        }

        private async Task<List<string>> ExportTrainingDataAsync(
            DataSetSplit dataSets,
            string outputDir,
            CancellationToken cancellationToken)
        {
            var outputFiles = new List<string>();

            // Export training set
            if (dataSets.Training.Any())
            {
                var trainingFile = Path.Combine(outputDir, "training_data.jsonl");

                await ExportToJsonlAsync(dataSets.Training, trainingFile, cancellationToken);

                outputFiles.Add(trainingFile);
            }

            // Export validation set
            if (dataSets.Validation.Any())
            {
                var validationFile = Path.Combine(outputDir, "validation_data.jsonl");

                await ExportToJsonlAsync(dataSets.Validation, validationFile, cancellationToken);

                outputFiles.Add(validationFile);
            }

            // Export test set
            if (dataSets.Test.Any())
            {
                var testFile = Path.Combine(outputDir, "test_data.jsonl");

                await ExportToJsonlAsync(dataSets.Test, testFile, cancellationToken);

                outputFiles.Add(testFile);
            }

            // Export combined dataset
            var allData = dataSets.Training.Concat(dataSets.Validation).Concat(dataSets.Test).ToList();
            if (allData.Any())
            {
                var combinedFile = Path.Combine(outputDir, "combined_dataset.jsonl");

                await ExportToJsonlAsync(allData, combinedFile, cancellationToken);

                outputFiles.Add(combinedFile);
            }

            return outputFiles;
        }

        private async Task ExportToJsonlAsync<T>(IEnumerable<T> data, string filePath, CancellationToken cancellationToken)
        {
            using var writer = new StreamWriter(filePath);
            foreach (var item in data)
            {
                if (cancellationToken.IsCancellationRequested) break;

                var json = JsonSerializer.Serialize(item, new JsonSerializerOptions
                {
                    WriteIndented = false,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });
                await writer.WriteLineAsync(json);
            }
        }

        private async Task GenerateMetadataAsync(DataSetSplit dataSets, string outputDir, CancellationToken cancellationToken)
        {

            var metadata = new
            {
                GeneratedAt = DateTime.UtcNow,
                DataSources = DataSources,
                DateRange = new { Start = StartDate, End = EndDate },
                UserFilter = UserIds,
                RecordCounts = new
                {
                    Training = dataSets.Training.Count,
                    Validation = dataSets.Validation.Count,
                    Test = dataSets.Test.Count,
                    Total = dataSets.Training.Count + dataSets.Validation.Count + dataSets.Test.Count
                },
                Features = GetFeatureSchema(),
                Labels = GetLabelSchema(),
                DataQuality = IncludeDataQuality,
                RiskSimulation = IncludeRiskSimulation,
                SyntheticRecords = IncludeRiskSimulation ? SyntheticRecordCount : 0,
                RandomSeed = RandomSeed,
                SplitRatios = new
                {
                    Training = TrainingSetPercentage,
                    Validation = ValidationSetPercentage,
                    Test = 1.0 - TrainingSetPercentage - ValidationSetPercentage
                }
            };


            var metadataFile = Path.Combine(outputDir, "metadata.json");
            var json = JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(metadataFile, json, cancellationToken);

            // Generate README
            var readmeFile = Path.Combine(outputDir, "README.md");

            var readme = GenerateReadmeContent(metadata);

            await File.WriteAllTextAsync(readmeFile, readme, cancellationToken);
        }

        private string GetOutputDirectory()
        {

            if (!string.IsNullOrEmpty(OutputDirectory))
            {

                return OutputDirectory;

            }


            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var defaultDir = Path.Combine("Output", "MLTrainingData", timestamp);
            Directory.CreateDirectory(defaultDir);
            return defaultDir;
        }

        private Dictionary<string, object> GetFeatureSchema()
        {
            return new Dictionary<string, object>
            {
                ["userId"] = "string",
                ["userPrincipalName"] = "string",
                ["ipAddress"] = "string",
                ["location"] = "string",
                ["country"] = "string",
                ["appId"] = "string",
                ["appDisplayName"] = "string",
                ["clientAppUsed"] = "string",
                ["riskLevel"] = "string",
                ["riskState"] = "string",
                ["conditionalAccessStatus"] = "string",
                ["isInteractive"] = "string",
                ["deviceId"] = "string",
                ["operatingSystem"] = "string",
                ["browser"] = "string",
                ["isCompliant"] = "string",
                ["isManaged"] = "string",
                ["trustType"] = "string"
            };
        }

        private Dictionary<string, object> GetLabelSchema()
        {
            return new Dictionary<string, object>
            {
                ["riskLevel"] = "string",
                ["isRisky"] = "boolean",
                ["conditionalAccessBlocked"] = "boolean",
                ["isSuccessful"] = "boolean",
                ["isUserActivity"] = "boolean",
                ["isAdminActivity"] = "boolean",
                ["isExternalAccess"] = "boolean",
                ["isSuspiciousOperation"] = "boolean",
                ["severityLevel"] = "string",
                ["isHighSeverity"] = "boolean",
                ["isActive"] = "boolean",
                ["hasAssignee"] = "boolean",
                ["isHighRisk"] = "boolean",
                ["isMediumRisk"] = "boolean",
                ["isLowRisk"] = "boolean",
                ["isDeleted"] = "boolean",
                ["isProcessing"] = "boolean"
            };
        }

        private string GenerateReadmeContent(dynamic metadata)
        {
            return $@"# ML Training Data

This directory contains machine learning training data generated for security risk detection models.

## ⚠️  IMPORTANT WARNINGS

- **This data is for research and development purposes only**
- **Generate your own data on a developer tenant**
- **Do not utilize customer data unlawfully**
- **Ensure compliance with all applicable laws and regulations**
- **This tool is intended for use with fine-tuned models from OpenPipe**

## Dataset Information

- **Generated**: {metadata.GeneratedAt:yyyy-MM-dd HH:mm:ss UTC}
- **Data Sources**: {string.Join(", ", metadata.DataSources)}
- **Date Range**: {metadata.DateRange.Start:yyyy-MM-dd} to {metadata.DateRange.End:yyyy-MM-dd}
- **User Filter**: {metadata.UserFilter ?? "All users"}
- **Total Records**: {metadata.RecordCounts.Total:N0}

## Data Split

- **Training Set**: {metadata.RecordCounts.Training:N0} records ({metadata.SplitRatios.Training:P0})
- **Validation Set**: {metadata.RecordCounts.Validation:N0} records ({metadata.SplitRatios.Validation:P0})
- **Test Set**: {metadata.RecordCounts.Test:N0} records ({metadata.SplitRatios.Test:P0})

## Features

The dataset includes the following features for each record:

{string.Join("\n", ((Dictionary<string, object>)metadata.Features).Select(kvp => $"- `{kvp.Key}`: {kvp.Value}"))}

## Labels

The dataset includes the following labels for supervised learning:

{string.Join("\n", ((Dictionary<string, object>)metadata.Labels).Select(kvp => $"- `{kvp.Key}`: {kvp.Value}"))}

## Data Quality

- **Quality Analysis**: {(bool)metadata.DataQuality ? "Enabled" : "Disabled"}
- **Risk Simulation**: {(bool)metadata.RiskSimulation ? "Enabled" : "Disabled"}
- **Synthetic Records**: {metadata.SyntheticRecords:N0}

## Usage

This data is formatted in JSONL (JSON Lines) format, with each line containing a single JSON object. Use this data to:

1. Train machine learning models for security risk detection
2. Fine-tune existing models using OpenPipe or similar platforms
3. Validate model performance on unseen data
4. Test risk detection algorithms

## File Structure

- `training_data.jsonl` - Training dataset
- `validation_data.jsonl` - Validation dataset
- `test_data.jsonl` - Test dataset
- `combined_dataset.jsonl` - Complete dataset
- `metadata.json` - Dataset metadata
- `README.md` - This file

## Compliance

Ensure your use of this data complies with:
- Microsoft 365 terms of service
- Data protection regulations (GDPR, CCPA, etc.)
- Your organization's security policies
- Ethical AI development guidelines
";
        }

        private bool IsSuspiciousMailboxOperation(string? operation)
        {
            if (string.IsNullOrEmpty(operation)) return false;

            var suspiciousOperations = new[]
            {
                "MailItemsAccessed", "SearchQueryInitiated", "MessageBind", "FolderBind",
                "SendAs", "SendOnBehalfOf", "UpdateFolderPermissions", "UpdateInboxRules"

            };



            return suspiciousOperations.Contains(operation, StringComparer.OrdinalIgnoreCase);


        }


    }


    public class MLTrainingDataResult

    {

        public MLTrainingDataSummary Summary { get; set; } = new();

        public DataSetSplit DataSets { get; set; } = new();


        public DataQualityMetrics? QualityMetrics { get; set; }


    }





    public class MLTrainingDataSummary


    {



        public DateTime StartTime { get; set; }


        public TimeSpan ProcessingTime { get; set; }

        public string[] DataSources { get; set; } = Array.Empty<string>();


        public string DateRange { get; set; } = string.Empty;


        public string OutputDirectory { get; set; } = string.Empty;



        public int RealRecordsCollected { get; set; }
        public int SyntheticRecordsGenerated { get; set; }

        public int TotalRecords { get; set; }

        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }

        public List<string> OutputFiles { get; set; } = new();


        public DataQualityMetrics? DataQualityMetrics { get; set; }


    }


    public class DataSetSplit

    {

        public List<MLTrainingRecord> Training { get; set; } = new();

        public List<MLTrainingRecord> Validation { get; set; } = new();


        public List<MLTrainingRecord> Test { get; set; } = new();


    }





    public class MLTrainingRecord


    {

        public string Id { get; set; } = string.Empty;

        public DateTime Timestamp { get; set; }
        public string DataSource { get; set; } = string.Empty;

        public string RecordType { get; set; } = string.Empty;

        public Dictionary<string, object> Features { get; set; } = new();


        public Dictionary<string, object> Labels { get; set; } = new();


    }





    public class DataQualityMetrics


    {



        public int TotalRecords { get; set; }


        public int CompleteRecords { get; set; }
        public int IncompleteRecords { get; set; }
        public double CompletenessScore { get; set; }
        public Dictionary<string, int> MissingValuesByFeature { get; set; } = new();
        public Dictionary<string, int> UniqueValuesByFeature { get; set; } = new();
        public Dictionary<string, object> DataTypesByFeature { get; set; } = new();
        public List<string> QualityIssues { get; set; } = new();
    }
}
