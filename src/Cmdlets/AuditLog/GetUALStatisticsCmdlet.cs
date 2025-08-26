namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Exchange;


    /// <summary>
    /// Cmdlet to analyze unified audit log distribution across record types
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "UALStatistics")]
    [OutputType(typeof(UALStatisticsResult))]
    public class GetUALStatisticsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(
            HelpMessage = "User IDs to filter by. Use '*' for all users")]

        public string UserIds { get; set; } = "*";


        [Parameter(
            HelpMessage = "Start date for the analysis range")]

        public DateTime? StartDate { get; set; }


        [Parameter(
            HelpMessage = "End date for the analysis range")]

        public DateTime? EndDate { get; set; }


        [Parameter(
            HelpMessage = "Output directory for results",
            ValueFromPipelineByPropertyName = true)]

        public string OutputDir { get; set; } = "Output\\";




        private readonly ExchangeRestClient _exchangeClient;


        // All supported record types for UAL analysis

        private readonly string[] _recordTypes = {

            "ExchangeAdmin", "ExchangeItem", "ExchangeItemGroup", "SharePoint", "SyntheticProbe",
            "SharePointFileOperation", "OneDrive", "AzureActiveDirectory", "AzureActiveDirectoryAccountLogon",
            "DataCenterSecurityCmdlet", "ComplianceDLPSharePoint", "Sway", "ComplianceDLPExchange",
            "SharePointSharingOperation", "AzureActiveDirectoryStsLogon", "SkypeForBusinessPSTNUsage",
            "SkypeForBusinessUsersBlocked", "SecurityComplianceCenterEOPCmdlet", "ExchangeAggregatedOperation",
            "PowerBIAudit", "CRM", "Yammer", "SkypeForBusinessCmdlets", "Discovery", "MicrosoftTeams",
            "ThreatIntelligence", "MailSubmission", "MicrosoftFlow", "AeD", "MicrosoftStream",
            "ComplianceDLPSharePointClassification", "ThreatFinder", "Project", "SharePointListOperation",
            "SharePointCommentOperation", "DataGovernance", "Kaizala", "SecurityComplianceAlerts",
            "ThreatIntelligenceUrl", "SecurityComplianceInsights", "MIPLabel", "WorkplaceAnalytics",
            "PowerAppsApp", "PowerAppsPlan", "ThreatIntelligenceAtpContent", "LabelContentExplorer",
            "TeamsHealthcare", "ExchangeItemAggregated", "HygieneEvent", "DataInsightsRestApiAudit",
            "InformationBarrierPolicyApplication", "SharePointListItemOperation", "SharePointContentTypeOperation",
            "SharePointFieldOperation", "MicrosoftTeamsAdmin", "HRSignal", "MicrosoftTeamsDevice",
            "MicrosoftTeamsAnalytics", "InformationWorkerProtection", "Campaign", "DLPEndpoint",
            "AirInvestigation", "Quarantine", "MicrosoftForms", "ApplicationAudit", "ComplianceSupervisionExchange",
            "CustomerKeyServiceEncryption", "OfficeNative", "MipAutoLabelSharePointItem",
            "MipAutoLabelSharePointPolicyLocation", "MicrosoftTeamsShifts", "SecureScore",
            "MipAutoLabelExchangeItem", "CortanaBriefing", "Search", "WDATPAlerts", "PowerPlatformAdminDlp",
            "PowerPlatformAdminEnvironment", "MDATPAudit", "SensitivityLabelPolicyMatch", "SensitivityLabelAction",
            "SensitivityLabeledFileAction", "AttackSim", "AirManualInvestigation", "SecurityComplianceRBAC",
            "UserTraining", "AirAdminActionInvestigation", "MSTIC", "PhysicalBadgingSignal",
            "TeamsEasyApprovals", "AipDiscover", "AipSensitivityLabelAction", "AipProtectionAction",
            "AipFileDeleted", "AipHeartBeat", "MCASAlerts", "OnPremisesFileShareScannerDlp",
            "OnPremisesSharePointScannerDlp", "ExchangeSearch", "SharePointSearch", "PrivacyDataMinimization",
            "LabelAnalyticsAggregate", "MyAnalyticsSettings", "SecurityComplianceUserChange",
            "ComplianceDLPExchangeClassification", "ComplianceDLPEndpoint", "MipExactDataMatch",
            "MSDEResponseActions", "MSDEGeneralSettings", "MSDEIndicatorsSettings", "MS365DCustomDetection",
            "MSDERolesSettings", "MAPGAlerts", "MAPGPolicy", "MAPGRemediation", "PrivacyRemediationAction",
            "PrivacyDigestEmail", "MipAutoLabelSimulationProgress", "MipAutoLabelSimulationCompletion",
            "MipAutoLabelProgressFeedback", "DlpSensitiveInformationType", "MipAutoLabelSimulationStatistics",
            "LargeContentMetadata", "Microsoft365Group", "CDPMlInferencingResult", "FilteringMailMetadata",
            "CDPClassificationMailItem", "CDPClassificationDocument", "OfficeScriptsRunAction",
            "FilteringPostMailDeliveryAction", "CDPUnifiedFeedback", "TenantAllowBlockList", "ConsumptionResource",
            "HealthcareSignal", "DlpImportResult", "CDPCompliancePolicyExecution", "MultiStageDisposition",
            "PrivacyDataMatch", "FilteringDocMetadata", "FilteringEmailFeatures", "PowerBIDlp",
            "FilteringUrlInfo", "FilteringAttachmentInfo", "CoreReportingSettings", "ComplianceConnector",
            "PowerPlatformLockboxResourceAccessRequest", "PowerPlatformLockboxResourceCommand",
            "CDPPredictiveCodingLabel", "CDPCompliancePolicyUserFeedback", "WebpageActivityEndpoint",
            "OMEPortal", "CMImprovementActionChange", "FilteringUrlClick", "MipLabelAnalyticsAuditRecord",
            "FilteringEntityEvent", "FilteringRuleHits", "FilteringMailSubmission", "LabelExplorer",
            "MicrosoftManagedServicePlatform", "PowerPlatformServiceActivity", "ScorePlatformGenericAuditRecord",
            "FilteringTimeTravelDocMetadata", "Alert", "AlertStatus", "AlertIncident", "IncidentStatus",
            "Case", "CaseInvestigation", "RecordsManagement", "PrivacyRemediation", "DataShareOperation",
            "CdpDlpSensitive", "EHRConnector", "FilteringMailGradingResult", "PublicFolder",
            "PrivacyTenantAuditHistoryRecord", "AipScannerDiscoverEvent", "EduDataLakeDownloadOperation",
            "M365ComplianceConnector", "MicrosoftGraphDataConnectOperation", "MicrosoftPurview",
            "FilteringEmailContentFeatures", "PowerPagesSite", "PowerAppsResource", "PlannerPlan",
            "PlannerCopyPlan", "PlannerTask", "PlannerRoster", "PlannerPlanList", "PlannerTaskList",
            "PlannerTenantSettings", "ProjectForTheWebProject", "ProjectForTheWebTask", "ProjectForTheWebRoadmap",
            "ProjectForTheWebRoadmapItem", "ProjectForTheWebProjectSettings", "ProjectForTheWebRoadmapSettings",
            "QuarantineMetadata", "MicrosoftTodoAudit", "TimeTravelFilteringDocMetadata", "TeamsQuarantineMetadata",
            "SharePointAppPermissionOperation", "MicrosoftTeamsSensitivityLabelAction", "FilteringTeamsMetadata",
            "FilteringTeamsUrlInfo", "FilteringTeamsPostDeliveryAction", "MDCAssessments",
            "MDCRegulatoryComplianceStandards", "MDCRegulatoryComplianceControls", "MDCRegulatoryComplianceAssessments",
            "MDCSecurityConnectors", "MDADataSecuritySignal", "VivaGoals", "FilteringRuntimeInfo",
            "AttackSimAdmin", "MicrosoftGraphDataConnectConsent", "FilteringAtpDetonationInfo", "PrivacyPortal",
            "ManagedTenants", "UnifiedSimulationMatchedItem", "UnifiedSimulationSummary", "UpdateQuarantineMetadata",
            "MS365DSuppressionRule", "PurviewDataMapOperation", "FilteringUrlPostClickAction",
            "IrmUserDefinedDetectionSignal", "TeamsUpdates", "PlannerRosterSensitivityLabel", "MS365DIncident",
            "FilteringDelistingMetadata", "ComplianceDLPSharePointClassificationExtended",
            "MicrosoftDefenderForIdentityAudit", "SupervisoryReviewDayXInsight", "DefenderExpertsforXDRAdmin",
            "CDPEdgeBlockedMessage", "HostedRpa", "CdpContentExplorerAggregateRecord", "CDPHygieneAttachmentInfo",
            "CDPHygieneSummary", "CDPPostMailDeliveryAction", "CDPEmailFeatures", "CDPHygieneUrlInfo",
            "CDPUrlClick", "CDPPackageManagerHygieneEvent", "FilteringDocScan", "TimeTravelFilteringDocScan",
            "MAPGOnboard", "VfamCreatePolicy", "VfamUpdatePolicy", "VfamDeletePolicy", "M365DAAD",
            "CdpColdCrawlStatus", "PowerPlatformAdministratorActivity", "Windows365CustomerLockbox",
            "CdpResourceScopeChangeEvent", "ComplianceCCExchangeExecutionResult", "CdpOcrCostEstimatorRecord",
            "CopilotInteraction", "CdpOcrBillingRecord", "ComplianceDLPApplications", "UAMOperation",
            "VivaLearning", "VivaLearningAdmin", "PurviewPolicyOperation", "PurviewMetadataPolicyOperation",
            "PeopleAdminSettings", "CdpComplianceDLPExchangeClassification", "CdpComplianceDLPSharePointClassification",
            "FilteringBulkSenderInsightData", "FilteringBulkThresholdInsightData", "PrivacyOpenAccess",
            "OWAAuth", "ComplianceDLPApplicationsClassification", "SharePointESignature", "Dynamics365BusinessCentral",
            "MeshWorlds", "VivaPulseResponse", "VivaPulseOrganizer", "VivaPulseAdmin", "VivaPulseReport",
            "AIAppInteraction", "ComplianceDLMExchange", "ComplianceDLMSharePoint", "ProjectForTheWebAssignedToMeSettings",
            "CPSOperation", "ComplianceDLPExchangeDiscovery", "PurviewMCRecommendation", "ComplianceDLPEndpointDiscovery",
            "InsiderRiskScopedUserInsights", "MicrosoftTeamsRetentionLabelAction", "AadRiskDetection",
            "AuditSearch", "AuditRetentionPolicy", "AuditConfig", "Microsoft365BackupBackupPolicy",
            "Microsoft365BackupRestoreTask", "Microsoft365BackupRestoreItem", "Microsoft365BackupBackupItem",
            "URBACAssignment", "URBACRole", "URBACEnableState", "IRMSecurityAlert", "PurviewInsiderRiskCases",
            "PurviewInsiderRiskAlerts", "InsiderRiskScopedUsers", "CdpConsumptionResource", "CreateCopilotPlugin",
            "UpdateCopilotPlugin", "DeleteCopilotPlugin", "EnableCopilotPlugin", "DisableCopilotPlugin",
            "CreateCopilotWorkspace", "UpdateCopilotWorkspace", "DeleteCopilotWorkspace", "EnableCopilotWorkspace",
            "DisableCopilotWorkspace", "CreateCopilotPromptBook", "UpdateCopilotPromptBook", "DeleteCopilotPromptBook",
            "EnableCopilotPromptBook", "DisableCopilotPromptBook", "UpdateCopilotSettings", "P4AIAssessmentRecord",
            "P4AIAssessmentLocationResultRecord", "ConnectedAIAppInteraction", "PrivaPrivacyConsentOperation",
            "PrivaPrivacyAssessmentOperation", "DataCatalogAccessRequests", "ComplianceSettingsChange",
            "DataSecurityInvestigation", "TeamCopilotInteraction", "IRMActivityAuditTrail",
            "SharePointContentSecurityPolicy", "CloudUpdateProfileConfig", "CloudUpdateTenantConfig",
            "CloudUpdateDeviceConfig", "DefenderPreviewFeatures", "DeviceDiscoverySettingsExclusion",
            "DeviceDiscoverySettingsAuthenticatedScans", "CriticalAssetManagementClassification",
            "DeviceDiscoverySettings", "USXWorkspaceOnboarding", "VivaGlintAdvancedConfiguration",
            "VivaGlintPulseProgram", "VivaGlintPulseProgramRespondentRate", "VivaGlintQuestion", "VivaGlintRole",
            "VivaGlintRubicon", "VivaGlintSupportAccess",
            "VivaGlintSystem", "VivaGlintUser", "VivaGlintUserGroup",
            "VivaGlintFeedbackProgram"
        };

        public GetUALStatisticsCmdlet()

        {


            _exchangeClient = new ExchangeRestClient(AuthManager);

        }

        protected override async Task ProcessRecordAsync()
        {

            WriteVerbose("=== Analyzing audit log distribution across record types ===");


            WriteVerbose($"Started: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");


            // Check for authentication

            if (!await _exchangeClient.IsConnectedAsync())
            {

                WriteErrorWithTimestamp("Not connected to Exchange Online. Please run Connect-M365 first.");

                return;
            }


            // Set date range

            var startDate = StartDate ?? DateTime.Now.AddDays(-90);


            var endDate = EndDate ?? DateTime.Now;


            var summary = new UALStatisticsSummary
            {
                StartTime = DateTime.Now,
                SearchStartDate = startDate,
                SearchEndDate = endDate,
                TotalCount = 0,
                RecordsWithData = 0,
                RecordsWithoutData = 0,
                RecordTypeResults = new List<RecordTypeStatistic>(),
                OutputFile = string.Empty
            };

            var dateRange = $"{startDate:yyyy-MM-dd HH:mm:ss} to {endDate:yyyy-MM-dd HH:mm:ss}";

            WriteVerbose($"Analysis Period: {dateRange}");


            WriteVerbose($"Record Types to Process: {_recordTypes.Length}");


            WriteVerbose($"Output Directory: {OutputDir}");


            WriteVerbose("----------------------------------------");



            var outputDirectory = GetOutputDirectory();

            var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            var outputFile = Path.Combine(outputDirectory, $"{timestamp}-Amount_Of_Audit_Logs.csv");

            try
            {
                // Get total count first with retries

                var totalCount = await GetTotalCountWithRetriesAsync(UserIds, startDate, endDate);


                if (totalCount == 0)
                {

                    WriteWarningWithTimestamp("No Unified Audit Log entries found after multiple attempts");


                    WriteVerbose("Aborting script since there are no audit logs to analyze");

                    return;
                }

                summary.TotalCount = totalCount;

                WriteVerbose($"Found a total of {totalCount:N0} Unified Audit Log entries");


                // Process each record type

                await ProcessRecordTypesAsync(UserIds, startDate, endDate, summary);


                // Write results to file
                if (summary.RecordTypeResults.Count > 0)
                {

                    await WriteResultsToFileAsync(summary.RecordTypeResults, outputFile);

                    summary.OutputFile = outputFile;
                }

                summary.ProcessingTime = DateTime.Now - summary.StartTime;

                LogSummary(summary);


                var result = new UALStatisticsResult
                {
                    RecordTypeStatistics = summary.RecordTypeResults,
                    Summary = summary
                };


                WriteObject(result);

            }
            catch (Exception ex)
            {

                WriteErrorWithTimestamp($"An error occurred during UAL statistics analysis: {ex.Message}");


                WriteVerbose("Ensure you are connected to M365 by running the Connect-M365 command before executing this script");

                throw;
            }
        }

        private async Task<int> GetTotalCountWithRetriesAsync(string userIds, DateTime startDate, DateTime endDate)
        {
            const int maxRetries = 3;
            var retryCount = 0;
            var totalCount = 0;

            while (retryCount < maxRetries && totalCount == 0)
            {
                if (retryCount > 0)
                {

                    WriteVerbose($"No events found... retrying, attempt {retryCount + 1}/{maxRetries} after 15 second delay...");

                    await Task.Delay(15000);
                }

                try
                {
                    var userIdsArray = userIds == "*" ? null : new[] { userIds };


                    var results = await _exchangeClient.SearchUnifiedAuditLogAsync(
                        startDate,
                        endDate,
                        null, // sessionId
                        null, // operations
                        null, // recordTypes
                        userIdsArray,
                        1, // resultSize
                        CancellationToken);


                    totalCount = results?.ResultCount ?? 0;
                }
                catch (Exception ex)
                {

                    WriteWarningWithTimestamp($"Error during attempt to get the total count {retryCount + 1}: {ex.Message}");

                    totalCount = 0;
                }

                retryCount++;
            }

            return totalCount;
        }

        private async Task ProcessRecordTypesAsync(string userIds, DateTime startDate, DateTime endDate, UALStatisticsSummary summary)
        {

            WriteVerbose("Processing record types...");

            var processedCount = 0;


            foreach (var recordType in _recordTypes)
            {
                processedCount++;

                if (processedCount % 25 == 0)
                {

                    WriteVerbose($"Processed {processedCount} of {_recordTypes.Length} record types");

                }

                try
                {
                    var userIdsArray = userIds == "*" ? null : new[] { userIds };
                    var recordTypesArray = new[] { recordType };


                    var results = await _exchangeClient.SearchUnifiedAuditLogAsync(
                        startDate,
                        endDate,
                        null, // sessionId
                        null, // operations
                        recordTypesArray,
                        userIdsArray,
                        1, // resultSize
                        CancellationToken);


                    var specificResult = results?.ResultCount ?? 0;

                    if (specificResult > 0)
                    {
                        summary.RecordsWithData++;
                        var percentage = summary.TotalCount == 0 ? 0 : Math.Round((double)specificResult / summary.TotalCount * 100, 2);

                        var statistic = new RecordTypeStatistic
                        {
                            RecordType = recordType,
                            Count = specificResult,
                            Percentage = percentage
                        };

                        summary.RecordTypeResults.Add(statistic);
                    }
                    else
                    {
                        summary.RecordsWithoutData++;
                    }
                }
                catch (Exception ex)
                {

                    WriteWarningWithTimestamp($"Error processing record type {recordType}: {ex.Message}");

                    summary.RecordsWithoutData++;
                }
            }



            WriteVerbose($"Processed {processedCount} of {_recordTypes.Length} record types");

        }

        private string GetOutputDirectory()
        {

            var directory = OutputDir;


            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);

                WriteVerbose($"Created output directory: {directory}");

            }

            return directory;
        }

        private void LogSummary(UALStatisticsSummary summary)
        {
            if (summary.TotalCount > 0)
            {

                WriteVerbose("");


                WriteVerbose("=== Record Type Analysis ===");


                WriteVerbose("----------------------------------------");


                // Sort by count descending and display results
                var sortedResults = summary.RecordTypeResults.OrderByDescending(r => r.Count).ToList();

                foreach (var result in sortedResults)
                {
                    var formattedCount = $"{result.Count:N0}";
                    var formattedPercentage = $"{result.Percentage:F1}";

                    WriteVerbose($"{result.RecordType,-40} {formattedCount,15} ({formattedPercentage,4}%)");

                }


                WriteVerbose("----------------------------------------");


                WriteVerbose("");


                WriteVerbose("=== Analysis Summary ===");


                WriteVerbose($"Time Period: {summary.SearchStartDate:yyyy-MM-dd} to {summary.SearchEndDate:yyyy-MM-dd}");


                WriteVerbose($"Total Log Entries: {summary.TotalCount:N0}");


                WriteVerbose("Record Types:");


                WriteVerbose($"  With Data: {summary.RecordsWithData}");


                WriteVerbose($"  Without Data: {summary.RecordsWithoutData}");


                if (!string.IsNullOrEmpty(summary.OutputFile))
                {

                    WriteVerbose($"Output File: {summary.OutputFile}");

                }


                WriteVerbose($"Processing Time: {summary.ProcessingTime?.ToString(@"mm\:ss")}");


                WriteVerbose("===================================");

            }
            else
            {

                WriteVerbose("No records found in the Unified Audit Log.");

            }
        }

        private async Task WriteResultsToFileAsync(List<RecordTypeStatistic> results, string filePath)
        {
            try
            {
                // Sort results by count descending
                var sortedResults = results.OrderByDescending(r => r.Count).ToList();

                var csv = "RecordType,Amount,Percentage" + Environment.NewLine;

                foreach (var result in sortedResults)
                {
                    csv += $"{result.RecordType},{result.Count},{result.Percentage:F2}" + Environment.NewLine;
                }

                using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(csv); }
            }
            catch (Exception ex)
            {

                WriteErrorWithTimestamp($"Failed to write results to file {filePath}: {ex.Message}");

                throw;
            }

        }

    }




    // Supporting classes

    public class UALStatisticsResult
    {

        public List<RecordTypeStatis

List<RecordTypeStatistic>();
        public UALStatisticsSummary Summary { get; set; } = new UALStatisticsSummary();

    }





    public class RecordTypeStatistic

    {
        public string RecordType { get; set; } = string.Empty;



        public int Count { get; set; }
        public double Percentage { get; set; }
    }





    public class UALStatisticsSummary


    {




        public DateTime StartTime { get; set; }
        public TimeSpan? ProcessingTime { get; set; }




        public DateTime SearchStartDate { get; set; }


        public DateTime SearchEndDate { get; set; }

        public int TotalCount { get; set; }
        public int RecordsWithData { get; set; }public int RecordsWithoutData { get; set; }public List<RecordTypeStatistic> RecordTypeResults { get; set; } = new List<RecordTypeStatistic>();
        public string OutputFile { get; set; } = string.Empty;
    }
}
