Get-AzureActivityLogs


Get-AzureActivityLogs -EndDate 2023-04-12


Get-AzureActivityLogs -StartDate 2023-04-12


Get-AzureActivityLogs -SubscriptionID "4947f939-cf12-4329-960d-4dg68a3eb66f"


<#
.SYNOPSIS
    Collect Azure Activity Logs
.DESCRIPTION
    This script collects the Azure Activity Logs for the specified time period and subscription.
.EXAMPLE
    Get-AzureActivityLogs
.EXAMPLE
    Get-AzureActivityLogs -EndDate 2023-04-12
.EXAMPLE
    Get-AzureActivityLogs -StartDate 2023-04-12
.EXAMPLE
    Get-AzureActivityLogs -SubscriptionID "4947f939-cf12-4329-960d-4dg68a3eb66f"
.PARAMETER StartDate
    The start date of the date range. Default: Today -89 days.
.PARAMETER EndDate
    The end date of the date range. Default: Now.
.PARAMETER SubscriptionID
    The subscription ID for which the collection of Activity logs is required. Default: All subscriptions.
.PARAMETER OutputDir
    The output directory. Default: Output\AzureActivityLogs.
.PARAMETER Encoding
    The encoding of the JSON output file. Default: UTF8.
.NOTES
    This functionality is currently in beta. If you encounter any issues or have suggestions for improvements, please let us know.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [DateTime]$StartDate = (Get-Date).AddDays(-89),

    [Parameter(Mandatory=$false)]
    [DateTime]$EndDate = Get-Date,

    [Parameter(Mandatory=$false)]
    [string]$SubscriptionID,

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "Output\AzureActivityLogs",

    [Parameter(Mandatory=$false)]
    [string]$Encoding = "UTF8"
    )

$OutputPath = Join-Path -Path $PSScriptRoot -ChildPath "$($OutputDir)\ActivityLogs.json"

$AzureActivityLogs = Get-AzActivityLog -StartTime $StartDate -EndTime $EndDate -Subscription $SubscriptionID

$AzureActivityLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutputPath -Encoding $Encoding

Write-Host "Activity logs saved to $OutputPath"
