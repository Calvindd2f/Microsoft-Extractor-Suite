using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Get-UALStatistics {
    [CmdletBinding()]
    param(
        [string]$UserIds,
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$OutputDir = "Output"
    )

    Write-logFile -Message "[INFO] Running Get-UALStatistics" -Color "Green"

    # Ensure that the output directory exists
    if (-not (Test-Path -Path $OutputDir)) {
        [void](New-Item -ItemType Directory -Force -Path $OutputDir)
    }

    $date = Get-Date -Format "yyyyMMddHHmmss"
    $outputFile = Join-Path -Path $OutputDir -ChildPath "$($date)-Amount_Of_Audit_Logs.csv"

    # Initialize StreamWriter for CSV
    $streamWriter = [System.IO.StreamWriter]::new($outputFile)
    $streamWriter.WriteLine("RecordType,Amount of log entries")

    $recordTypes = @("ExchangeAdmin", "ExchangeItem", "ExchangeItemGroup", "SharePoint", "SyntheticProbe", "SharePointFileOperation", "OneDrive", "AzureActiveDirectory", "AzureActiveDirectoryAccountLogon", "DataCenterSecurityCmdlet", "ComplianceDLPSharePoint", "Sway", "ComplianceDLPExchange", "SharePointSharingOperation", "AzureActiveDirectoryStsLogon", "SkypeForBusinessPSTNUsage", "SkypeForBusinessUsersBlocked", "SecurityComplianceCenterEOPCmdlet", "ExchangeAggregatedOperation", "PowerBIAudit", "CRM", "Yammer", "SkypeForBusinessCmdlets", "Discovery", "MicrosoftTeams", "ThreatIntelligence", "MailSubmission", "MicrosoftFlow", "AeD", "MicrosoftStream", "ComplianceDLPSharePointClassification", "ThreatFinder", "Project", "SharePointListOperation", "SharePointCommentOperation", "DataGovernance", "Kaizala", "SecurityComplianceAlerts", "ThreatIntelligenceUrl", "SecurityComplianceInsights", "MIPLabel", "WorkplaceAnalytics", "PowerAppsApp", "PowerAppsPlan", "ThreatIntelligenceAtpContent", "LabelContentExplorer", "TeamsHealthcare", "ExchangeItemAggregated", "HygieneEvent", "DataInsightsRestApiAudit", "InformationBarrierPolicyApplication", "SharePointListItemOperation", "SharePointContentTypeOperation", "SharePointFieldOperation", "MicrosoftTeamsAdmin", "HRSignal", "MicrosoftTeamsDevice", "MicrosoftTeamsAnalytics", "InformationWorkerProtection", "Campaign", "DLPEndpoint", "AirInvestigation", "Quarantine", "MicrosoftForms", "ApplicationAudit", "ComplianceSupervisionExchange", "CustomerKeyServiceEncryption", "OfficeNative", "MipAutoLabelSharePointItem", "MipAutoLabelSharePointPolicyLocation", "MicrosoftTeamsShifts", "SecureScore", "MipAutoLabelExchangeItem", "CortanaBriefing", "Search", "WDATPAlerts", "PowerPlatformAdminDlp", "PowerPlatformAdminEnvironment", "MDATPAudit", "SensitivityLabelPolicyMatch", "SensitivityLabelAction", "SensitivityLabeledFileAction", "AttackSim", "AirManualInvestigation", "SecurityComplianceRBAC", "UserTraining", "AirAdminActionInvestigation", "MSTIC", "PhysicalBadgingSignal", "TeamsEasyApprovals", "AipDiscover", "AipSensitivityLabelAction", "AipProtectionAction", "AipFileDeleted", "AipHeartBeat", "MCASAlerts", "OnPremisesFileShareScannerDlp", "OnPremisesSharePointScannerDlp", "ExchangeSearch", "SharePointSearch", "PrivacyDataMinimization", "LabelAnalyticsAggregate", "MyAnalyticsSettings", "SecurityComplianceUserChange", "ComplianceDLPExchangeClassification", "ComplianceDLPEndpoint", "MipExactDataMatch", "MSDEResponseActions", "MSDEGeneralSettings", "MSDEIndicatorsSettings", "MS365DCustomDetection", "MSDERolesSettings", "MAPGAlerts", "MAPGPolicy", "MAPGRemediation", "PrivacyRemediationAction", "PrivacyDigestEmail", "MipAutoLabelSimulationProgress", "MipAutoLabelSimulationCompletion", "MipAutoLabelProgressFeedback", "DlpSensitiveInformationType", "MipAutoLabelSimulationStatistics", "LargeContentMetadata", "Microsoft365Group", "CDPMlInferencingResult", "FilteringMailMetadata", "CDPClassificationMailItem", "CDPClassificationDocument", "OfficeScriptsRunAction", "FilteringPostMailDeliveryAction", "CDPUnifiedFeedback", "TenantAllowBlockList", "ConsumptionResource", "HealthcareSignal", "DlpImportResult", "CDPCompliancePolicyExecution", "MultiStageDisposition", "PrivacyDataMatch", "FilteringDocMetadata", "FilteringEmailFeatures", "PowerBIDlp", "FilteringUrlInfo", "FilteringAttachmentInfo", "CoreReportingSettings", "ComplianceConnector", "PowerPlatformLockboxResourceAccessRequest", "PowerPlatformLockboxResourceCommand", "CDPPredictiveCodingLabel", "CDPCompliancePolicyUserFeedback", "WebpageActivityEndpoint", "OMEPortal", "CMImprovementActionChange", "FilteringUrlClick", "MipLabelAnalyticsAuditRecord", "FilteringEntityEvent", "FilteringRuleHits", "FilteringMailSubmission", "LabelExplorer", "MicrosoftManagedServicePlatform", "PowerPlatformServiceActivity", "ScorePlatformGenericAuditRecord", "FilteringTimeTravelDocMetadata", "Alert", "AlertStatus", "AlertIncident", "IncidentStatus", "Case", "CaseInvestigation", "RecordsManagement", "PrivacyRemediation", "DataShareOperation", "CdpDlpSensitive", "EHRConnector", "FilteringMailGradingResult", "PublicFolder", "PrivacyTenantAuditHistoryRecord", "AipScannerDiscoverEvent", "EduDataLakeDownloadOperation", "M365ComplianceConnector", "MicrosoftGraphDataConnectOperation", "MicrosoftPurview", "FilteringEmailContentFeatures", "PowerPagesSite", "PowerAppsResource", "PlannerPlan", "PlannerCopyPlan", "PlannerTask", "PlannerRoster", "PlannerPlanList", "PlannerTaskList", "PlannerTenantSettings", "ProjectForTheWebProject", "ProjectForTheWebTask", "ProjectForTheWebRoadmap", "ProjectForTheWebRoadmapItem", "ProjectForTheWebProjectSettings", "ProjectForTheWebRoadmapSettings", "QuarantineMetadata", "MicrosoftTodoAudit", "TimeTravelFilteringDocMetadata", "TeamsQuarantineMetadata", "SharePointAppPermissionOperation", "MicrosoftTeamsSensitivityLabelAction", "FilteringTeamsMetadata", "FilteringTeamsUrlInfo", "FilteringTeamsPostDeliveryAction", "MDCAssessments", "MDCRegulatoryComplianceStandards", "MDCRegulatoryComplianceControls", "MDCRegulatoryComplianceAssessments", "MDCSecurityConnectors", "MDADataSecuritySignal", "VivaGoals", "FilteringRuntimeInfo", "AttackSimAdmin", "MicrosoftGraphDataConnectConsent", "FilteringAtpDetonationInfo", "PrivacyPortal", "ManagedTenants", "UnifiedSimulationMatchedItem", "UnifiedSimulationSummary", "UpdateQuarantineMetadata", "MS365DSuppressionRule", "PurviewDataMapOperation", "FilteringUrlPostClickAction", "IrmUserDefinedDetectionSignal", "TeamsUpdates", "PlannerRosterSensitivityLabel", "MS365DIncident", "FilteringDelistingMetadata", "ComplianceDLPSharePointClassificationExtended", "MicrosoftDefenderForIdentityAudit", "SupervisoryReviewDayXInsight", "DefenderExpertsforXDRAdmin", "CDPEdgeBlockedMessage", "HostedRpa")
    
    # Total count of all logs
    $totalCount = 0
    
    foreach ($recordType in $recordTypes) {
        $resultCount = 0
        try {
            $resultCount = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType $recordType -ResultSize 1).ResultCount
        } catch {
            Write-LogFile -Message "[ERROR] Unable to search logs for record type '$recordType': $_" -Color "Red"
        }

        if ($resultCount) {
            $totalCount += $resultCount
            $streamWriter.WriteLine("$recordType,$resultCount")
        }
    }
    $streamWriter.WriteLine("Total Count,$totalCount")
    $streamWriter.Close()

    # Output the total count
    Write-LogFile -Message "--------------------------------------"
    Write-LogFile -Message "Total count: $totalCount" -Color "Green"
    Write-LogFile -Message "[INFO] Count complete. File is written to $outputFile" -Color "Green"

    if (-not $totalCount) {
        Write-LogFile -Message "[INFO] No records found for $UserIds"
    }
}