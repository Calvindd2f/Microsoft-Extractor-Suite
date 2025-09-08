# Performance Comparison Script
# Compares Microsoft Graph PowerShell cmdlets vs Graph.Fast module

param(
    [string]$OutputPath = ".\performance-results.csv",
    [int]$Iterations = 3
)

# Import required modules
Import-Module Microsoft.Graph.Users -Force
Import-Module .\Graph.Fast.psm1 -Force

# Function to measure execution time
function Measure-ExecutionTime {
    param(
        [string]$TestName,
        [scriptblock]$ScriptBlock
    )

    Write-Host "Running: $TestName" -ForegroundColor Yellow

    $times = @()
    for ($i = 1; $i -le $Iterations; $i++) {
        Write-Host "  Iteration $i/$Iterations" -ForegroundColor Gray

        # Clear any cached data
        if ($TestName -like "*Graph.Fast*") {
            $script:HttpClient = $null
            $script:TokenInfo = [pscustomobject]@{ AccessToken = $null; ExpiresOn = Get-Date 0 }
        }

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            $result = & $ScriptBlock
            $stopwatch.Stop()
            $times += $stopwatch.Elapsed.TotalSeconds
            Write-Host "    Completed in $($stopwatch.Elapsed.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Green
        }
        catch {
            $stopwatch.Stop()
            Write-Host "    Failed: $($_.Exception.Message)" -ForegroundColor Red
            $times += $null
        }
    }

    return @{
        TestName = $TestName
        Times = $times
        AverageTime = if ($times -ne $null) { ($times | Where-Object { $_ -ne $null } | Measure-Object -Average).Average } else { $null }
        MinTime = if ($times -ne $null) { ($times | Where-Object { $_ -ne $null } | Measure-Object -Minimum).Minimum } else { $null }
        MaxTime = if ($times -ne $null) { ($times | Where-Object { $_ -ne $null } | Measure-Object -Maximum).Maximum } else { $null }
        SuccessCount = ($times | Where-Object { $_ -ne $null }).Count
        TotalIterations = $Iterations
    }
}

# Initialize Graph.Fast client
Write-Host "Initializing Graph.Fast client..." -ForegroundColor Cyan
try {
    Initialize-GraphFastClient -TenantId $env:TenantId -ClientId $env:ClientId -Thumbprint $env:Thumbprint -Version v1.0
    Write-Host "Graph.Fast client initialized successfully" -ForegroundColor Green
}
catch {
    Write-Host "Failed to initialize Graph.Fast client: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 1: Microsoft Graph PowerShell cmdlets
$mgTest = Measure-ExecutionTime -TestName "Microsoft Graph PowerShell" -ScriptBlock {
    $tempFile = ".\temp_mg_users.csv"
    try {
        Get-MgUser -Property id,userPrincipalName,displayName,accountEnabled |
        Select-Object id,userPrincipalName,displayName,accountEnabled |
        Export-Csv -Path $tempFile -NoTypeInformation
        $result = Get-Content $tempFile | Measure-Object -Line
        Remove-Item $tempFile -Force
        return $result.Lines - 1  # Subtract header line
    }
    catch {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
        throw
    }
}

# Test 2: Graph.Fast module
$fastTest = Measure-ExecutionTime -TestName "Graph.Fast Module" -ScriptBlock {
    $tempFile = ".\temp_fast_users.csv"
    try {
        Get-GffUsersFast -Select id,userPrincipalName,displayName,accountEnabled -ToCsv $tempFile
        $result = Get-Content $tempFile | Measure-Object -Line
        Remove-Item $tempFile -Force
        return $result.Lines - 1  # Subtract header line
    }
    catch {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
        throw
    }
}

# Display results
Write-Host "`n" + "="*80 -ForegroundColor Cyan
Write-Host "PERFORMANCE COMPARISON RESULTS" -ForegroundColor Cyan
Write-Host "="*80 -ForegroundColor Cyan

Write-Host "`nMicrosoft Graph PowerShell:" -ForegroundColor Yellow
Write-Host "  Average Time: $($mgTest.AverageTime.ToString('F2')) seconds" -ForegroundColor White
Write-Host "  Min Time:     $($mgTest.MinTime.ToString('F2')) seconds" -ForegroundColor White
Write-Host "  Max Time:     $($mgTest.MaxTime.ToString('F2')) seconds" -ForegroundColor White
Write-Host "  Success Rate: $($mgTest.SuccessCount)/$($mgTest.TotalIterations)" -ForegroundColor White

Write-Host "`nGraph.Fast Module:" -ForegroundColor Yellow
Write-Host "  Average Time: $($fastTest.AverageTime.ToString('F2')) seconds" -ForegroundColor White
Write-Host "  Min Time:     $($fastTest.MinTime.ToString('F2')) seconds" -ForegroundColor White
Write-Host "  Max Time:     $($fastTest.MaxTime.ToString('F2')) seconds" -ForegroundColor White
Write-Host "  Success Rate: $($fastTest.SuccessCount)/$($fastTest.TotalIterations)" -ForegroundColor White

# Calculate performance improvement
if ($mgTest.AverageTime -and $fastTest.AverageTime) {
    $improvement = (($mgTest.AverageTime - $fastTest.AverageTime) / $mgTest.AverageTime) * 100
    $speedup = $mgTest.AverageTime / $fastTest.AverageTime

    Write-Host "`nPerformance Improvement:" -ForegroundColor Green
    Write-Host "  Time Reduction: $($improvement.ToString('F1'))%" -ForegroundColor White
    Write-Host "  Speedup Factor: $($speedup.ToString('F2'))x faster" -ForegroundColor White

    if ($improvement -gt 0) {
        Write-Host "  Graph.Fast is $($speedup.ToString('F2'))x faster than Microsoft Graph PowerShell!" -ForegroundColor Green
    } else {
        Write-Host "  Microsoft Graph PowerShell is $((1/$speedup).ToString('F2'))x faster than Graph.Fast" -ForegroundColor Yellow
    }
}

# Export detailed results to CSV
$results = @()
for ($i = 0; $i -lt $Iterations; $i++) {
    $results += [PSCustomObject]@{
        TestName = "Microsoft Graph PowerShell"
        Iteration = $i + 1
        ExecutionTime = if ($mgTest.Times[$i]) { $mgTest.Times[$i] } else { $null }
        Success = $mgTest.Times[$i] -ne $null
    }
    $results += [PSCustomObject]@{
        TestName = "Graph.Fast Module"
        Iteration = $i + 1
        ExecutionTime = if ($fastTest.Times[$i]) { $fastTest.Times[$i] } else { $null }
        Success = $fastTest.Times[$i] -ne $null
    }
}

$results | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "`nDetailed results exported to: $OutputPath" -ForegroundColor Cyan

# Summary statistics
$summary = [PSCustomObject]@{
    TestName = @("Microsoft Graph PowerShell", "Graph.Fast Module")
    AverageTime = @($mgTest.AverageTime, $fastTest.AverageTime)
    MinTime = @($mgTest.MinTime, $fastTest.MinTime)
    MaxTime = @($mgTest.MaxTime, $fastTest.MaxTime)
    SuccessRate = @("$($mgTest.SuccessCount)/$($mgTest.TotalIterations)", "$($fastTest.SuccessCount)/$($fastTest.TotalIterations)")
}

$summaryPath = $OutputPath -replace '\.csv$', '_summary.csv'
$summary | Export-Csv -Path $summaryPath -NoTypeInformation
Write-Host "Summary statistics exported to: $summaryPath" -ForegroundColor Cyan
