@{
RootModule = 'Microsoft-Extractor-Suite.psm1'

# Author of this module
Author = 'Joey Rentenaar & Korstiaan Stam'

# Company of this module
CompanyName = 'Invictus-IR'

# Version number of this module.
ModuleVersion = '1.3.4' 

# ID used to uniquely identify this module
GUID = '4376306b-0078-4b4d-b565-e22804e3be01'

# Copyright statement for this module
Copyright = 'Copyright (c) 2024 Invictus Incident Response'

# Description of the functionality provided by this module
Description = 'Microsoft-Extractor-Suite is a fully-featured, actively-maintained, Powershell tool designed to streamline the process of collecting all necessary data and information from various sources within Microsoft.'	

NestedModules = @('Scripts\Connect.ps1', 'Scripts\Get-UAL.ps1', 'Scripts\Get-UALStatistics.ps1', 'Scripts\Get-Rules.ps1', 'Scripts\Get-MailboxAuditLog.ps1', 'Scripts\Get-MessageTraceLog.ps1', 'Scripts\Get-AzureADLogs.ps1', 'Scripts\Get-OAuthPermissions.ps1', 'Scripts\Get-AdminAuditLog.ps1', 'Scripts\Get-AzureActivityLogs.ps1', 'Scripts\Get-AzureADGraphLogs.ps1', 'Scripts\Get-UsersInfo.ps1', 'Scripts\Get-MFAStatus.ps1', 'Scripts\Get-RiskyEvents.ps1', 'Scripts\Get-ConditionalAccessPolicy.ps1', 'Scripts\Get-Emails.ps1', 'Scripts\Get-MailItemsAccessed.ps1', 'Scripts\Get-UALGraph.ps1')

FunctionsToExport = @(
    'Public\Connect-M365',
    'Public\Connect-Azure',
    'Public\Connect-AzureAZ',
    'Public\Get-UALAll',
    'Public\Get-UALGroup',
    'Public\Get-UALSpecific',
    'Public\Get-UALSpecificActivity',
    'Public\Get-UALGraph',
    'Public\Get-UALStatistics',
    'Public\Show-MailboxRules',
    'Public\Get-MailboxRules',
    'Public\Get-TransportRules',
    'Public\Show-TransportRules',
    'Public\Get-MailboxAuditLog',
    'Public\Get-MessageTraceLog',
    'Public\Get-ADAuditLogs',
    'Public\Get-ADSignInLogs',
    'Public\Get-OAuthPermissions',
    'Public\Get-AdminAuditLog',
    'Public\Get-ActivityLogs',
    'Public\Get-ADSignInLogsGraph',
    'Public\Get-ADAuditLogsGraph',
    'Public\Get-Users',
    'Public\Get-AdminUsers',
    'Public\Get-MFA',
    'Public\Get-RiskyUsers',
    'Public\Get-RiskyDetections',
    'Public\Get-ConditionalAccessPolicies',
    'Public\Get-Email',
    'Public\Get-Attachment',
    'Public\Show-Email',
    'Public\Get-Sessions',
    'Public\Get-MessageIDs'
)

# Variables to export from this module
VariablesToExport = @(
    '$outputdir',
    '$curDir',
    '$logFile',
    '$retryCount'
)

# Cmdlets to export from this module, for best performance
CmdletsToExport = @()	

# Directory to store all the public functions
ScriptsPath = Join-Path -Path $PSScriptRoot -ChildPath 'Public'

# Directory to store all the help files
HelpPath = Join-Path -Path $PSScriptRoot -ChildPath 'Help'
}
