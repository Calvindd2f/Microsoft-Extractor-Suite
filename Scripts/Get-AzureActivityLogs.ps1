# Load required functions
using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

# Function to get activity logs
function Get-ActivityLogs {
    <#_removed for brevity_#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$StartDate,
        [Parameter(Mandatory)]
        [string]$EndDate,
        [string]$SubscriptionID,
        [string]$OutputDir = $(Throw "OutputDir parameter is mandatory."),
        [string]$Encoding = 'utf8'
    )

    # Check if the user is connected to Azure
    $areYouConnected = Get-AzSubscription -ErrorAction Stop -WarningAction SilentlyContinue

    # Get all subscriptions or the specified subscription
    $subscriptions = if ($SubscriptionID) {
        Get-AzSubscription -SubscriptionId $SubscriptionID
    } else {
        $areYouConnected
    }

    foreach ($sub in $subscriptions) {
        Set-AzContext -Subscription $sub.Id

        try {
            $logs = Get-AzActivityLog -StartTime (Get-Date).AddDays(-89) -EndTime (Get-Date) -ErrorAction Stop -WarningAction SilentlyContinue

            if ($logs) {
                [console]::writeline("[INFO] Activity logs found in subscription: $($sub.Id)")# -ForegroundColor Green
                Export-Logs -Logs $logs -OutputDir $OutputDir -Encoding $Encoding
            } else {
                [console]::writeline("[WARNING] No Activity logs in subscription: $($sub.Id)")# -ForegroundColor Yellow
            }
        } catch {
            [console]::writeline("[WARNING] An error occurred while retrieving logs from subscription: $($sub.Id): $_")# -ForegroundColor Yellow
        }
    }
}

# Function to export logs to a file
function Export-Logs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Logs,
        [string]$OutputDir,
        [string]$Encoding = 'utf8'
    )

    $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
    $filePath = Join-Path $OutputDir "$($date)-ActivityLog.json"

    $Logs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
    Write-LogFile -Message "[INFO] Successfully retrieved and exported $($Logs.Count) Activity logs to $filePath" -Color "Green"
}

# Function to write log messages
function Write-LogFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [string]$Color = 'White'
    )

    Write-Host $Message -ForegroundColor $Color
}

# Call the Get-ActivityLogs function
Get-ActivityLogs -StartDate '2022-01-01' -EndDate '2022-02-01' -SubscriptionID 'your_subscription_id' -OutputDir 'C:\temp'
