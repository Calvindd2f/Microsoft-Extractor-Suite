# Check for required modules
if (-not (Get-Module -Name Azure -ErrorAction SilentlyContinue)) {
    Write-Error "The Azure module is not installed. Please install it and try again."
    return
}

if (-not (Get-Module -Name Az -ErrorAction SilentlyContinue)) {
    Write-Error "The Az module is not installed. Please install it and try again."
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

# Check parameters
if ($EndDate -lt $StartDate) {
    Write-Error "The end date cannot be earlier than the start date."
    return
}

# Set output path
$outputDir = "Output\AzureActivityLogs"
New-Directory -Path $outputDir
$outputPath = Join-Path -Path $outputDir -ChildPath ("ActivityLogs_${StartDate:yyyy-MM-dd}_to_${EndDate:yyyy-MM-dd}_${SubscriptionID}.json")

# Get Azure activity logs
try {
    $azureActivityLogs = Get-AzActivityLog -StartTime $StartDate -EndTime $EndDate -SubscriptionId $SubscriptionID
} catch {
    Write-Error "Failed to retrieve Azure activity logs: $_"
    return
}

# Check if any logs were found
if ($azureActivityLogs.Count -eq 0) {
    Write-Warning "No Azure activity logs found for the specified date range and subscription."
    return
}

# Convert logs to JSON and save to file
$json = $azureActivityLogs | ConvertTo-Json -Depth 100
if (Test-WritableFile -Path $outputPath) {
    $json | Out-File -FilePath $outputPath -Encoding $Encoding
    Write-Host "Activity logs saved to $outputPath"
} else {
    Write-Error "Cannot write to output file: $outputPath"
}
