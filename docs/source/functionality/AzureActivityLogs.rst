# Check for required modules
if (-not (Get-Module -Name Azure -ErrorAction SilentlyContinue)) {
    Write-Error "The Azure module is not installed. Please install it and try again."
    return
}

if (-not (Get-Module -Name Az -ErrorAction SilentlyContinue)) {
    Write-Error "The Az module is not installed. Please install it and try again."
    return
}

# Check for required cmdlets
if (-not (Get-Command -Name ConvertTo-Json -ErrorAction SilentlyContinue)) {
    Write-Error "The ConvertTo-Json cmdlet is not available. Please install it and try again."
    return
}

# Function to check if a directory exists and create it if it doesn't
function New-Directory ($path) {
    if (-not (Test-Path -Path $path)) {
        New-Item -ItemType Directory -Force -Path $path
    }
}

# Function to check if a file can be written
function Test-WritableFile ($path) {
    try {
        $stream = New-Object System.IO.FileStream($path, 'OpenOrCreate', 'Write', 'None')
        $stream.Close()
        return $true
    } catch {
        return $false
    }
}

# Function to get the current date and time
function Get-CurrentDateTime {
    return Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
}

# Function to retrieve the Azure subscription object
function Get-AzureSubscription {
    param (
        [string]$SubscriptionID
    )

    $subscription = Get-AzSubscription -SubscriptionId $SubscriptionID -ErrorAction SilentlyContinue

    if (-not $subscription) {
        Write-Error "The specified Azure subscription does not exist or is not accessible."
        return
    }

    return $subscription
}

# Check parameters
if ($EndDate -lt $StartDate) {
    Write-Error "The end date cannot be earlier than the start date."
    return
}

# Set output path
$outputDir = "Output\AzureActivityLogs"
New-Directory -Path $outputDir
$currentDateTime = Get-CurrentDateTime
$outputPath = Join-Path -Path $outputDir -ChildPath ("ActivityLogs_${StartDate:yyyy-MM-dd}_to_${EndDate:yyyy-MM-dd}_${SubscriptionID}_${currentDateTime}.json")

# Retrieve the Azure subscription object
$subscription = Get-AzureSubscription -SubscriptionID $SubscriptionID

# Get Azure activity logs
try {
    $azureActivityLogs = Get-AzActivityLog -StartTime $StartDate -EndTime $EndDate -SubscriptionId $SubscriptionID
} catch {
    Write-Error "Failed to retrieve Azure activity logs: $_"
    return
}

# Check if any logs were found
if ($azureActivityLogs -eq $null) {
    Write-Warning "No Azure activity logs found for the specified date range and subscription."
    return
}

# Convert logs to JSON and save to file
$json = $azureActivityLogs | ConvertTo-Json -Depth 100
if (Test-WritableFile -Path $outputPath) {
    $Encoding = [System.Text.Encoding]::UTF8
    $json | Out-File -FilePath $outputPath -Encoding $Encoding
    Write-Host "Activity logs saved to $outputPath"
} else {
    Write-Error "Cannot write to output file: $outputPath"
}

