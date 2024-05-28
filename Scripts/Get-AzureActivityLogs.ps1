# Load required functions
using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

# Function to get activity logs
function Get-ActivityLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({$_ -as [datetime]})]
        [datetime]$StartDate,

        [Parameter(Mandatory)]
        [ValidateScript({$_ -as [datetime]})]
        [datetime]$EndDate,

        [string]$SubscriptionID,

        [string]$OutputDir = (Throw "OutputDir parameter is mandatory."),

        [ValidateSet('utf8', 'ascii', 'unicode', 'bigendianunicode', 'utf7', 'utf32')]
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
            $logs = Get-AzActivityLog -StartTime $StartDate -EndTime $EndDate -ErrorAction Stop -WarningAction SilentlyContinue

            if ($logs) {
                Write-Host "Activity logs found in subscription: $($sub.Id)" -ForegroundColor Green
                Export-Logs -Logs $logs -OutputDir $OutputDir -Encoding $Encoding
            } else {
                Write-Host "No Activity logs in subscription: $($sub.Id)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "An error occurred while retrieving logs from subscription: $($sub.Id): $_" -ForegroundColor Yellow
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

        [ValidateSet('utf8', 'ascii', 'unicode', 'bigendianunicode', 'utf7', 'utf32')]
        [string]$Encoding = 'utf8'
    )

    $date = Get-Date -Format 'yyyyMMddHHmmss'
    $filePath = Join-Path -Path $OutputDir -ChildPath "$($date)-ActivityLog.json"

    $Logs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
    Write-Host "Successfully retrieved and exported $($Logs.Count) Activity logs to $filePath" -ForegroundColor Green
}

# Function to write log messages
function Write-LogFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')]
        [string]$Color = 'White'
    )

    Write-Host $Message -ForegroundColor $Color
}

# Call the Get-ActivityLogs function
Get-ActivityLogs -StartDate (Get-Date '2022-01-01') -EndDate (Get-Date '2022-02-01') -SubscriptionID 'your_subscription_id' -OutputDir 'C:\temp'
