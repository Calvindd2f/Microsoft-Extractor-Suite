# Quick Performance Comparison
# Single-run comparison between Microsoft Graph PowerShell and Graph.Fast

# Import modules
Import-Module Microsoft.Graph.Users -Force
Import-Module .\Graph.Fast.psm1 -Force

Write-Host "Initializing Graph.Fast client..." -ForegroundColor Cyan
Initialize-GraphFastClient -TenantId $env:TenantId -ClientId $env:ClientId -Thumbprint $env:Thumbprint -Version v1.0

Write-Host "`nStarting performance comparison..." -ForegroundColor Yellow
Write-Host "="*60 -ForegroundColor Cyan

# Test Microsoft Graph PowerShell
Write-Host "`nTesting Microsoft Graph PowerShell..." -ForegroundColor Yellow
$mgStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $mgUsers = Get-MgUser -Property id,userPrincipalName,displayName,accountEnabled |
               Select-Object id,userPrincipalName,displayName,accountEnabled
    $mgStopwatch.Stop()
    $mgTime = $mgStopwatch.Elapsed.TotalSeconds
    $mgCount = $mgUsers.Count
    Write-Host "✓ Completed in $($mgTime.ToString('F2')) seconds - Retrieved $mgCount users" -ForegroundColor Green
}
catch {
    $mgStopwatch.Stop()
    Write-Host "✗ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $mgTime = $null
    $mgCount = 0
}

# Test Graph.Fast
Write-Host "`nTesting Graph.Fast Module..." -ForegroundColor Yellow
$fastStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $fastUsers = Get-GffUsersFast -Select id,userPrincipalName,displayName,accountEnabled
    $fastStopwatch.Stop()
    $fastTime = $fastStopwatch.Elapsed.TotalSeconds
    $fastCount = $fastUsers.Count
    Write-Host "✓ Completed in $($fastTime.ToString('F2')) seconds - Retrieved $fastCount users" -ForegroundColor Green
}
catch {
    $fastStopwatch.Stop()
    Write-Host "✗ Failed: $($_.Exception.Message)" -ForegroundColor Red
    $fastTime = $null
    $fastCount = 0
}

# Display comparison
Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "RESULTS COMPARISON" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan

Write-Host "`nMicrosoft Graph PowerShell:" -ForegroundColor Yellow
Write-Host "  Time: $($mgTime.ToString('F2')) seconds" -ForegroundColor White
Write-Host "  Users: $mgCount" -ForegroundColor White

Write-Host "`nGraph.Fast Module:" -ForegroundColor Yellow
Write-Host "  Time: $($fastTime.ToString('F2')) seconds" -ForegroundColor White
Write-Host "  Users: $fastCount" -ForegroundColor White

if ($mgTime -and $fastTime) {
    $improvement = (($mgTime - $fastTime) / $mgTime) * 100
    $speedup = $mgTime / $fastTime

    Write-Host "`nPerformance:" -ForegroundColor Green
    Write-Host "  Time Reduction: $($improvement.ToString('F1'))%" -ForegroundColor White
    Write-Host "  Speedup: $($speedup.ToString('F2'))x" -ForegroundColor White

    if ($improvement -gt 0) {
        Write-Host "  🚀 Graph.Fast is $($speedup.ToString('F2'))x faster!" -ForegroundColor Green
    } else {
        Write-Host "  📊 Microsoft Graph PowerShell is $((1/$speedup).ToString('F2'))x faster" -ForegroundColor Yellow
    }
}

Write-Host "`nTest completed!" -ForegroundColor Cyan
