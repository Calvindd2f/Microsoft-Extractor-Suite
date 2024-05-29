$AuditOperations = @(
    # Microsoft Entra ID
    "AzureActiveDirectory", "AzureActiveDirectoryAccountLogon", "AzureActiveDirectoryStsLogon",
    
    # Azure Information Protection
    "AipDiscover", "AipSensitivityLabelAction", "AipProtectionAction", "AipFileDeleted", "AipHeartBeat",
    
    # Communication compliance
    "ComplianceSupervisionExchange",
    
    # Content explorer
    "LabelContentExplorer",
    
    # Data connectors
    "ComplianceConnector",
    
    # Data loss prevention (DLP)
    "ComplianceDLPSharePoint", "ComplianceDLPExchange", "DLPEndpoint",
    
    # Dynamics 365
    "CRM",
    
    # eDiscovery (Standard + Premium)
    "Discovery", "AeD",
    
    # Encrypted message portal
    "OMEPortal",
    
    # Exact Data Match
    "MipExactDataMatch",
    
    # Exchange Online
    "ExchangeAdmin", "ExchangeItem", "ExchangeItemAggregated",
    
    # Forms
    "MicrosoftForms",
    
    # Information barriers
    "InformationBarrierPolicyApplication",
    
    # Microsoft Defender XDR
    "AirInvestigation", "AirManualInvestigation", "AirAdminActionInvestigation", "MS365DCustomDetection",
    
    # Microsoft Copilot for Microsoft 365
    "CopilotInteraction",
    
    # Microsoft Defender Experts
    "DefenderExpertsforXDRAdmin",
    
    # Microsoft Defender for Identity (MDI)
    "MicrosoftDefenderForIdentityAudit",
    
    # Microsoft Planner
    "PlannerCopyPlan", "PlannerPlan", "PlannerPlanList", "PlannerRoster", "PlannerRosterSensitivityLabel", "PlannerTask", "PlannerTaskList", "PlannerTenantSettings",
    
    # Microsoft Project for the web
    "ProjectAccessed", "ProjectCreated", "ProjectDeleted", "ProjectTenantSettingsUpdated", "ProjectUpdated",
    "RoadmapAccessed", "RoadmapCreated", "RoadmapDeleted", "RoadmapItemAccessed", "RoadmapItemCreated", 
    "RoadmapItemDeleted", "RoadmapItemUpdated", "RoadmapTenantSettingsUpdated", "RoadmapUpdated",
    "TaskAccessed", "TaskCreated", "TaskDeleted", "TaskUpdated",
    
    # Microsoft Purview Information Protection (MIP) labels
    "MIPLabel", "MipAutoLabelExchangeItem", "MipAutoLabelSharePointItem", "MipAutoLabelSharePointPolicyLocation",
    
    # Microsoft Teams
    "MicrosoftTeams",
    
    # Microsoft To Do
    "MicrosoftToDo", "MicrosoftToDoAudit",
    
    # MyAnalytics
    "MyAnalyticsSettings",
    
    # OneDrive for Business
    "OneDrive",
    
    # Power Apps
    "PowerAppsApp", "PowerAppsPlan",
    
    # Power Automate
    "MicrosoftFlow",
    
    # Power BI
    "PowerBIAudit",
    
    # Quarantine
    "Quarantine",
    
    # Sensitive information types
    "DlpSensitiveInformationType",
    
    # Sensitivity labels
    "MIPLabel", "SensitivityLabelAction", "SensitivityLabeledFileAction", "SensitivityLabelPolicyMatch",
    
    # SharePoint Online
    "SharePoint", "SharePointFileOperation", "SharePointSharingOperation", "SharePointListOperation", "SharePointCommentOperation",
    
    # Stream
    "MicrosoftStream",
    
    # SystemSync
    "DataShareCreated", "DataShareDeleted", "GenerateCopyOfLakeData", "DownloadCopyOfLakeData",
    
    # Threat Intelligence
    "ThreatIntelligence", "ThreatIntelligenceUrl", "ThreatFinder", "ThreatIntelligenceAtpContent",
    
    # Viva Goals
    "VivaGoals",
    
    # Viva Insights
    "VivaInsights",
    
    # Yammer
    "Yammer"
)

# Example of how to use this array
Write-Host "Total number of audit operations: $($AuditOperations.Count)"
$AuditOperations | ForEach-Object { Write-Host $_ }
