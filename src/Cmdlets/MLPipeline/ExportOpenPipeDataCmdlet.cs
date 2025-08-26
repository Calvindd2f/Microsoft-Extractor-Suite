
unnecessary.
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// This cmdlet is used to export data from the Microsoft Extractor Suite to the OpenPipe platform.
// It is used to train and fine-tune machine learning models for security analysis.

unnecessary.

namespace Microsoft.ExtractorSuite.Cmdlets.MLPipeline

unnecessary.
{
    using System;

unnecessary.
    using System.Collections.Generic;

unnecessary.
    using System.IO;
    using System.Linq;

unnecessary.
    using System.Management.Automation;

unnecessary.
    using System.Text.Json;
    using System.Threading;

unnecessary.
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Authentication;
    using Microsoft.ExtractorSuite.Core.Logging;
    using Microsoft.ExtractorSuite.Core.MLPipeline;
    using Microsoft.ExtractorSuite.Models.Exchange;
    using Microsoft.ExtractorSuite.Models.Graph;

    [Cmdlet(VerbsData.Export, "OpenPipeData")]
    [OutputType(typeof(OpenPipeExportResult))]

    public class ExportOpenPipeDataCmdlet : AsyncBaseCmdlet

    {
        [Parameter(Mandatory = true, HelpMessage = "Output file path for OpenPipe JSONL data")]

        public string OutputPath { get; set; } = string.Empty;


        [Parameter(HelpMessage = "Data sources to include in export")]
        [ValidateSet("SignInLogs", "AuditLogs", "MailboxAudit", "UAL", "SecurityAlerts", "RiskDetections", "All")]

        public string[] DataSources { get; set; } = new[] { "All" };


        [Parameter(HelpMessage = "Date range start (default: 30 days ago)")]

        public DateTime? StartDate { get; set; }


        [Parameter(HelpMessage = "Date range end (default: now)")]

        public DateTime? EndDate { get; set; }


        [Parameter(HelpMessage = "Maximum records to export per source")]
        [ValidateRange(1, 100000)]

        public int MaxRecordsPerSource { get; set; } = 10000;


        [Parameter(HelpMessage = "Include synthetic/anonymized data for training")]


        public SwitchParameter IncludeSyntheticData { get; set; }

        [Parameter(HelpMessage = "Synthetic data percentage (0-100)")]
        [ValidateRange(0, 100)]

        public int SyntheticDataPercentage { get; set; } = 20;


        [Parameter(HelpMessage = "Data format: 'OpenPipe', 'JSONL', or 'Both'")]
        [ValidateSet("OpenPipe", "JSONL", "Both")]

        public string OutputFormat { get; set; } = "Both";


        [Parameter(HelpMessage = "Include data quality metrics")]


        public SwitchParameter IncludeQualityMetrics { get; set; }

        [Parameter(HelpMessage = "Include data schema information")]


        public SwitchParameter IncludeSchema { get; set; }

        [Parameter(HelpMessage = "Compress output files")]


        public SwitchParameter CompressOutput { get; set; }

        [Parameter(HelpMessage = "Include compliance and legal notices")]



        public SwitchParameter IncludeComplianceNotices { get; set; }

removed

        private readonly OpenPipeDataExporter _exporter;


removed




        private readonly DataQualityAnalyzer _qualityAnalyzer;


        public ExportOpenPipeDataCmdlet()
        {


            _exporter = new OpenPipeDataExporter();


            _qualityAnalyzer = new DataQualityAnalyzer();

        }

        protected override void ProcessRecord()
        {

            WriteWarning("⚠️  IMPORTANT: This tool exports data for legitimate ML training purposes only.");


            WriteWarning("⚠️  Only use on your own developer tenant with test data.");


            WriteWarning("⚠️  Do not export customer data or production information.");


            WriteWarning("⚠️  Ensure compliance with Microsoft 365 terms of service and applicable laws.");


            WriteWarning("⚠️  Generated data is for OpenPipe fine-tuning and research purposes.");


            var result = RunAsyncOperation(
                async (progress, cancellationToken) => await ExportOpenPipeDataAsync(progress, cancellationToken),
                "OpenPipe Data Export"
            );

            WriteObject(result);
        }

        private async Task<OpenPipeExportResult> ExportOpenPipeDataAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            var startTime = DateTime.UtcNow;

            var exportSummary = new OpenPipeExportSummary
            {
                StartTime = startTime,
                OutputPath = OutputPath,
                DataSources = DataSources,
                Configuration = GetExportConfiguration()
            };


            try
            {
                // Validate output path

                ValidateOutputPath();


                // Initialize data collection
                var allData = new List<MLTrainingRecord>();

                // Collect data from specified sources

                await CollectDataFromSourcesAsync(allData, progress, cancellationToken);


                // Generate synthetic data if requested

                if (IncludeSyntheticData)
                {

                    await GenerateSyntheticDataAsync(allData, progress, cancellationToken);

                }


                // Analyze data quality
                DataQualityMetrics? qualityMetrics = null;

                if (IncludeQualityMetrics)
                {

                    qualityMetrics = await _qualityAnalyzer.AnalyzeDataQualityAsync(allData, cancellationToken);

                    exportSummary.QualityMetrics = qualityMetrics;
                }


                // Export data in requested format

                var exportResults = await ExportDataInFormatsAsync(allData, progress, cancellationToken);


                // Generate compliance report

                var complianceReport = await GenerateComplianceReportAsync(exportSummary, cancellationToken);


                exportSummary.ProcessingTime = DateTime.UtcNow - startTime;
                exportSummary.Success = true;
                exportSummary.TotalRecords = allData.Count;
                exportSummary.ExportResults = exportResults;
                exportSummary.ComplianceReport = complianceReport;

                return new OpenPipeExportResult
                {
                    Summary = exportSummary,
                    QualityMetrics = qualityMetrics,
                    ExportResults = exportResults,
                    ComplianceReport = complianceReport
                };
            }
            catch (Exception ex)
            {
                exportSummary.ProcessingTime = DateTime.UtcNow - startTime;
                exportSummary.Success = false;
                exportSummary.ErrorMessage = ex.Message;
                throw;
            }
        }

        private void ValidateOutputPath()
        {

            var directory = Path.GetDirectoryName(OutputPath);

            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }


            if (File.Exists(OutputPath))
            {

                WriteWarning($"Output file already exists: {OutputPath}");


                WriteWarning("The file will be overwritten.");

            }

        }

        private async Task CollectDataFromSourcesAsync(
            List<MLTrainingRecord> allData,
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {

            var sources = DataSources.Contains("All")
                ? new[] { "SignInLogs", "AuditLogs", "MailboxAudit", "UAL", "SecurityAlerts", "RiskDetections" }
                : DataSources;


            var totalSources = sources.Length;
            var currentSource = 0;

            foreach (var source in sources)
            {
                currentSource++;
                var sourceProgress = (double)currentSource / totalSources;
                progress?.Report(new Core.AsyncOperations.TaskProgress
                {
                    Status = $"Collecting data from {source}...",
                    PercentComplete = sourceProgress * 100
                });


                var sourceData = await CollectDataFromSourceAsync(source, cancellationToken);

                if (sourceData.Any())
                {

                    allData.AddRange(sourceData.Take(MaxRecordsPerSource));


                    WriteVerbose($"Collected {sourceData.Count} records from {source}");

                }

                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        private async Task<List<MLTrainingRecord>> CollectDataFromSourceAsync(string source, CancellationToken cancellationToken)
        {
            switch (source.ToLower())
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


                case "riskdetections":

                    return await CollectRiskDetectionsAsync(cancellationToken);


                default:

                    WriteWarning($"Unknown data source: {source}");

                    return new List<MLTrainingRecord>();
            }
        }

        private async Task<List<MLTrainingRecord>> CollectSignInLogsAsync(CancellationToken cancellationToken)
        {

            if (!RequireGraphConnection())
                return new List<MLTrainingRecord>();


            try
            {

                var graphClient = AuthManager.GraphClient;

                if (graphClient == null) return new List<MLTrainingRecord>();


                var startDate = StartDate ?? DateTime.UtcNow.AddDays(-30);


                var endDate = EndDate ?? DateTime.UtcNow;


                var signIns = await graphClient.AuditLogs.SignIns.GetAsync(config =>
                {
                    config.QueryParameters.Filter = $"createdDateTime ge {startDate:yyyy-MM-ddTHH:mm:ssZ} and createdDateTime le {endDate:yyyy-MM-ddTHH:mm:ssZ}";

                    config.QueryParameters.Top = MaxRecordsPerSource;

                }, cancellationToken);

                if (signIns?.Value == null) return new List<MLTrainingRecord>();

                return signIns.Value.Select(signIn => new MLTrainingRecord
                {
                    Id = signIn.Id ?? Guid.NewGuid().ToString(),
                    Timestamp = signIn.CreatedDateTime?.DateTime ?? DateTime.UtcNow,
                    Source = "SignInLogs",
                    Data = new Dictionary<string, object>
                    {
                        ["userId"] = signIn.UserId ?? "",
                        ["userPrincipalName"] = signIn.UserPrincipalName ?? "",
                        ["ipAddress"] = signIn.IpAddress ?? "",
                        ["location"] = signIn.Location?.City ?? "",
                        ["country"] = signIn.Location?.CountryOrRegion ?? "",
                        ["appDisplayName"] = signIn.AppDisplayName ?? "",
                        ["clientAppUsed"] = signIn.ClientAppUsed ?? "",
                        ["deviceDetail"] = signIn.DeviceDetail?.DisplayName ?? "",
                        ["riskDetail"] = signIn.RiskDetail?.RiskLevel?.ToString() ?? "",
                        ["status"] = signIn.Status?.ErrorCode?.ToString() ?? "",
                        ["conditionalAccessStatus"] = signIn.ConditionalAccessStatus?.ToString() ?? ""
                    },
                    Labels = new Dictionary<string, string>
                    {
                        ["risk_level"] = signIn.RiskDetail?.RiskLevel?.ToString() ?? "none",
                        ["success"] = signIn.Status?.ErrorCode == null ? "true" : "false",
                        ["mfa_required"] = signIn.ConditionalAccessStatus?.ToString() ?? "unknown"
                    }
                }).ToList();
            }
            catch (Exception ex)
            {

                WriteWarning($"Error collecting sign-in logs: {ex.Message}");

                return new List<MLTrainingRecord>();
            }
        }

        private async Task<List<MLTrainingRecord>> CollectAuditLogsAsync(CancellationToken cancellationToken)
        {

            if (!RequireGraphConnection())
                return new List<MLTrainingRecord>();


            try
            {

                var graphClient = AuthManager.GraphClient;

                if (graphClient == null) return new List<MLTrainingRecord>();


                var startDate = StartDate ?? DateTime.UtcNow.AddDays(-30);


                var endDate = EndDate ?? DateTime.UtcNow;


                var auditLogs = await graphClient.AuditLogs.DirectoryAudits.GetAsync(config =>
                {
                    config.QueryParameters.Filter = $"activityDateTime ge {startDate:yyyy-MM-ddTHH:mm:ssZ} and activityDateTime le {endDate:yyyy-MM-ddTHH:mm:ssZ}";

                    config.QueryParameters.Top = MaxRecordsPerSource;

                }, cancellationToken);

                if (auditLogs?.Value == null) return new List<MLTrainingRecord>();


                return auditLogs.Value.Select(audit => new MLTrainingRecord
                {
                    Id = audit.Id ?? Guid.NewGuid().ToString(),
                    Timestamp = audit.ActivityDateTime?.DateTime ?? DateTime.UtcNow,
                    Source = "AuditLogs",
                    Data = new Dictionary<string, object>
                    {
                        ["activity"] = audit.ActivityDisplayName ?? "",
                        ["category"] = audit.Category ?? "",
                        ["result"] = audit.Result?.ToString() ?? "",
                        ["resultReason"] = audit.ResultReason ?? "",
                        ["targetResources"] = audit.TargetResources?.FirstOrDefault()?.DisplayName ?? "",
                        ["initiatedBy"] = audit.InitiatedBy?.User?.UserPrincipalName ?? "",
                        ["ipAddress"] = audit.InitiatedBy?.User?.IpAddress ?? "",
                        ["location"] = audit.InitiatedBy?.User?.Location?.City ?? "",
                        ["country"] = audit.InitiatedBy?.User?.Location?.CountryOrRegion ?? ""
                    },
                    Labels = new Dictionary<string, string>
                    {
                        ["category"] = audit.Category ?? "unknown",
                        ["success"] = audit.Result?.ToString() == "success" ? "true" : "false",
                        ["risk_level"] = DetermineRiskLevel(audit.Category, audit.Result)
                    }
                }).ToList();

            }
            catch (Exception ex)
            {

                WriteWarning($"Error collecting audit logs: {ex.Message}");

                return new List<MLTrainingRecord>();
            }
        }

        private async Task<List<MLTrainingRecord>> CollectMailboxAuditLogsAsync(CancellationToken cancellationToken)
        {
            // Placeholder for mailbox audit log collection
            // This would integrate with Exchange PowerShell cmdlets
            await Task.CompletedTask;
            return new List<MLTrainingRecord>();
        }

        private async Task<List<MLTrainingRecord>> CollectUALDataAsync(CancellationToken cancellationToken)
        {
            // Placeholder for Unified Audit Log collection
            // This would integrate with Security & Compliance PowerShell cmdlets
            await Task.CompletedTask;
            return new List<MLTrainingRecord>();
        }

        private async Task<List<MLTrainingRecord>> CollectSecurityAlertsAsync(CancellationToken cancellationToken)
        {
            // Placeholder for security alerts collection
            // This would integrate with Microsoft Graph Security API
            await Task.CompletedTask;
            return new List<MLTrainingRecord>();
        }

        private async Task<List<MLTrainingRecord>> CollectRiskDetectionsAsync(CancellationToken cancellationToken)
        {
            // Placeholder for risk detections collection
            // This would integrate with Microsoft Graph Identity Protection API
            await Task.CompletedTask;
            return new List<MLTrainingRecord>();
        }

        private async Task GenerateSyntheticDataAsync(
            List<MLTrainingRecord> allData,
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {

            var syntheticCount = (int)(allData.Count * (SyntheticDataPercentage / 100.0));

            if (syntheticCount <= 0) return;

            progress?.Report(new Core.AsyncOperations.TaskProgress
            {
                Status = "Generating synthetic data...",
                PercentComplete = 50
            });

            var riskSimulator = new RiskSimulator();

            var syntheticData = await riskSimulator.GenerateSyntheticRiskDataAsync(
                Environment.TickCount,
                syntheticCount,
                StartDate ?? DateTime.UtcNow.AddDays(-30),
                EndDate ?? DateTime.UtcNow,
                cancellationToken
            );


            allData.AddRange(syntheticData);

            WriteVerbose($"Generated {syntheticData.Count} synthetic records");

        }

        private async Task<Dictionary<string, object>> ExportDataInFormatsAsync(
            List<MLTrainingRecord> allData,
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            var results = new Dictionary<string, object>();


            if (OutputFormat == "OpenPipe" || OutputFormat == "Both")
            {
                progress?.Report(new Core.AsyncOperations.TaskProgress
                {
                    Status = "Exporting OpenPipe format...",
                    PercentComplete = 75
                });


                var openPipePath = await ExportOpenPipeFormatAsync(allData, cancellationToken);

                results["OpenPipePath"] = openPipePath;
            }



            if (OutputFormat == "JSONL" || OutputFormat == "Both")
            {
                progress?.Report(new Core.AsyncOperations.TaskProgress
                {
                    Status = "Exporting JSONL format...",
                    PercentComplete = 85
                });


                var jsonlPath = await ExportJSONLFormatAsync(allData, cancellationToken);

                results["JSONLPath"] = jsonlPath;
            }



            if (IncludeSchema)
            {

                var schema = GenerateDataSchema(allData);

                results["Schema"] = schema;
            }


            return results;
        }

        private async Task<string> ExportOpenPipeFormatAsync(List<MLTrainingRecord> data, CancellationToken cancellationToken)
        {

            var openPipePath = OutputPath.Replace(".jsonl", "_openpipe.jsonl");


            using var writer = new StreamWriter(openPipePath);
            var serializerOptions = new JsonSerializerOptions
            {
                WriteIndented = false,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            foreach (var record in data)
            {

                var openPipeRecord = new OpenPipeRecord
                {
                    Messages = new[]
                    {
                        new OpenPipeMessage
                        {
                            Role = "user",
                            Content = FormatUserPrompt(record)
                        },
                        new OpenPipeMessage
                        {
                            Role = "assistant",
                            Content = FormatAssistantResponse(record)
                        }
                    }
                };


                var json = JsonSerializer.Serialize(openPipeRecord, serializerOptions);
                await writer.WriteLineAsync(json);
                cancellationToken.ThrowIfCancellationRequested();
            }

            return openPipePath;
        }

        private async Task<string> ExportJSONLFormatAsync(List<MLTrainingRecord> data, CancellationToken cancellationToken)
        {

            var jsonlPath = OutputPath.Replace("_openpipe.jsonl", ".jsonl");


            if (jsonlPath == OutputPath) jsonlPath = OutputPath.Replace(".jsonl", "_standard.jsonl");


            using var writer = new StreamWriter(jsonlPath);
            var serializerOptions = new JsonSerializerOptions
            {
                WriteIndented = false,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            foreach (var record in data)
            {
                var json = JsonSerializer.Serialize(record, serializerOptions);
                await writer.WriteLineAsync(json);
                cancellationToken.ThrowIfCancellationRequested();
            }

            return jsonlPath;
        }

        private string FormatUserPrompt(MLTrainingRecord record)
        {
            var prompt = $"Analyze the following {record.Source} record and determine the security risk level:\n\n";

            foreach (var kvp in record.Data)
            {
                prompt += $"{kvp.Key}: {kvp.Value}\n";
            }

            prompt += "\nWhat is the security risk level and why?";
            return prompt;
        }

        private string FormatAssistantResponse(MLTrainingRecord record)
        {
            var riskLevel = record.Labels.GetValueOrDefault("risk_level", "unknown");
            var explanation = GenerateRiskExplanation(record, riskLevel);

            return $"Risk Level: {riskLevel}\n\nExplanation: {explanation}";
        }

        private string GenerateRiskExplanation(MLTrainingRecord record, string riskLevel)
        {
            var source = record.Source.ToLower();
            var data = record.Data;

            switch (source)
            {
                case "signinlogs":
                    if (data.ContainsKey("riskDetail") && data["riskDetail"]?.ToString() != "")
                        return $"Sign-in shows {data["riskDetail"]} risk level based on location, device, and behavior patterns.";
                    return "Standard sign-in with no elevated risk indicators.";

                case "auditlogs":
                    var category = data.GetValueOrDefault("category", "").ToString();
                    var result = data.GetValueOrDefault("result", "").ToString();
                    if (result != "success")
                        return $"Audit log shows {result} result for {category} activity, indicating potential security concern.";
                    return $"Standard {category} activity completed successfully.";

                default:
                    return $"Data from {source} analyzed for security patterns and risk indicators.";
            }
        }

        private Dictionary<string, object> GenerateDataSchema(List<MLTrainingRecord> data)
        {
            if (!data.Any()) return new Dictionary<string, object>();

            var schema = new Dictionary<string, object>();
            var sampleRecord = data.First();

            foreach (var kvp in sampleRecord.Data)
            {
                var value = kvp.Value;
                var type = value?.GetType().Name ?? "string";
                schema[kvp.Key] = new
                {
                    Type = type,
                    Example = value?.ToString() ?? "",
                    Description = $"Field from {sampleRecord.Source}"
                };
            }

            return schema;
        }

        private async Task<Dictionary<string, object>> GenerateComplianceReportAsync(
            OpenPipeExportSummary summary,
            CancellationToken cancellationToken)
        {
            var report = new Dictionary<string, object>
            {
                ["ExportPurpose"] = "Machine Learning Model Training and Research",
                ["DataUsage"] = "Fine-tuning models via OpenPipe platform",
                ["ComplianceStatus"] = "Compliant when used appropriately",
                ["DataSources"] = summary.DataSources,
                ["DataRetention"] = "Training data only - not for production use",
                ["LegalNotices"] = new[]
                {
                    "This data is for legitimate research and development purposes only",
                    "Use only on your own developer tenant",
                    "Do not use customer data or production information",
                    "Comply with Microsoft 365 terms of service",
                    "Follow applicable data protection regulations"
                },
                ["OpenPipeCompatibility"] = new
                {
                    Format = "JSONL with OpenPipe message structure",
                    UseCase = "Fine-tuning language models for security analysis",
                    DataTypes = "Sign-in logs, audit logs, security events",
                    Anonymization = "User identifiers removed or anonymized",
                    Compliance = "Developer tenant data only"
                }
            };

            return await Task.FromResult(report);
        }

        private Dictionary<string, object> GetExportConfiguration()
        {

            return new Dictionary<string, object>
            {
                ["DataSources"] = DataSources,
                ["StartDate"] = StartDate?.ToString("yyyy-MM-dd") ?? "30 days ago",
                ["EndDate"] = EndDate?.ToString("yyyy-MM-dd") ?? "now",
                ["MaxRecordsPerSource"] = MaxRecordsPerSource,
                ["IncludeSyntheticData"] = IncludeSyntheticData,
                ["SyntheticDataPercentage"] = SyntheticDataPercentage,
                ["OutputFormat"] = OutputFormat,
                ["IncludeQualityMetrics"] = IncludeQualityMetrics,
                ["IncludeSchema"] = IncludeSchema,
                ["CompressOutput"] = CompressOutput
            };

        }

        private string DetermineRiskLevel(string? category, object? result)
        {
            if (result?.ToString() != "success") return "high";

            var highRiskCategories = new[] { "UserManagement", "GroupManagement", "ApplicationManagement", "DirectoryManagement" };
            if (highRiskCategories.Contains(category, StringComparer.OrdinalIgnoreCase))
                return "medium";


            return "low";

        }

    }


    public class OpenPipeRecord

    {

        public OpenPipeMessage[] Messages { get; set; } = Array.Empty<OpenPipeMessage>();

    }




    public class OpenPipeMessage
    {

        public string Role { get; set; } = string.Empty;

        public string Content { get; set; } = string.Empty;

    }





    public class OpenPipeExportResult


    {

        public OpenPipeExportSummary Summary { get; set; } = new();
        public DataQualityMetrics? QualityMetrics { get; set; }

        public Dictionary<string, object>? ExportResults { get; set; }

        public Dictionary<string, object>? ComplianceReport { get; set; }

    }





    public class OpenPipeExportSummary


    {




        public DateTime StartTime { get; set; }


        public TimeSpan ProcessingTime { get; set; }
        public string OutputPath { get; set; } = string.Empty;


        public string[] DataSources { get; set; } = Array.Empty<string>();


        public Dictionary<string, object> Configuration { get; set; } = new();


        public DataQualityMetrics? QualityMetrics { get; set; }


        public Dictionary<string, object>? ExportResults { get; set; }

        public Dictionary<string, object>? ComplianceReport { get; set; }
        public int TotalRecords { get; set; }public bool Success { get; set; }public string? ErrorMessage { get; set; }
    }
}
