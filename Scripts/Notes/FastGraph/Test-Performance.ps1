#Requires -Version 5.1
#Requires -Modules Microsoft-Extractor-Suite

<#
.SYNOPSIS
    Performance testing script for Microsoft Extractor Suite - C# vs PowerShell modules

.DESCRIPTION
    This script performs performance testing between C# binary modules and PowerShell script modules
    to compare execution times and success rates. It logs detailed results including timing,
    success/failure status, and performance metrics.

.PARAMETER TestType
    Type of test to run: "CSharp", "PowerShell", or "Both" (default)

.PARAMETER TestFunctions
    Array of function names to test. If not specified, tests all available functions.

.PARAMETER Iterations
    Number of iterations to run for each test (default: 3)

.PARAMETER OutputPath
    Path to save the performance results (default: "Performance-Test-Results.csv")

.PARAMETER LogLevel
    Logging level: "Minimal", "Detailed", or "Verbose" (default: "Detailed")

.PARAMETER WarmupRuns
    Number of warmup runs before actual testing (default: 1)

.PARAMETER TestParameters
    Hashtable of parameters to pass to test functions

.EXAMPLE
    .\Test-Performance.ps1 -TestType Both -Iterations 5

.EXAMPLE
    .\Test-Performance.ps1 -TestFunctions @("Get-Users", "Get-Groups") -TestType CSharp

.EXAMPLE
    .\Test-Performance.ps1 -TestType PowerShell -LogLevel Verbose -WarmupRuns 2
#>

param(
    [Parameter()]
    [ValidateSet("CSharp", "PowerShell", "Both")]
    [string]$TestType = "Both",

    [Parameter()]
    [string[]]$TestFunctions = @(),

    [Parameter()]
    [int]$Iterations = 3,

    [Parameter()]
    [string]$OutputPath = "Performance-Test-Results.csv",

    [Parameter()]
    [ValidateSet("Minimal", "Detailed", "Verbose")]
    [string]$LogLevel = "Detailed",

    [Parameter()]
    [int]$WarmupRuns = 1,

    [Parameter()]
    [hashtable]$TestParameters = @{}
)

# Initialize performance test class
class PerformanceTest {
    [string]$TestName
    [string]$ModuleType
    [string]$FunctionName
    [datetime]$StartTime
    [datetime]$EndTime
    [timespan]$Duration
    [bool]$Success
    [string]$ErrorMessage
    [int]$Iteration
    [hashtable]$Parameters
    [long]$MemoryUsageMB
    [int]$CPUUsagePercent

    PerformanceTest([string]$name, [string]$type, [string]$function, [int]$iter, [hashtable]$params) {
        $this.TestName = $name
        $this.ModuleType = $type
        $this.FunctionName = $function
        $this.Iteration = $iter
        $this.Parameters = $params
        $this.StartTime = [datetime]::Now
    }

    [void]Complete([bool]$success, [string]$errorMsg) {
        $this.EndTime = [datetime]::Now
        $this.Duration = $this.EndTime - $this.StartTime
        $this.Success = $success
        $this.ErrorMessage = $errorMsg
    }
}

# Performance test runner class
class PerformanceTestRunner {
    [System.Collections.Generic.List[PerformanceTest]]$TestResults
    [hashtable]$TestFunctions
    [string]$LogLevel
    [int]$WarmupRuns

    PerformanceTestRunner([string]$logLevel, [int]$warmupRuns) {
        $this.TestResults = [System.Collections.Generic.List[PerformanceTest]]::new()
        $this.LogLevel = $logLevel
        $this.WarmupRuns = $warmupRuns
        $this.InitializeTestFunctions()
    }

    [void]InitializeTestFunctions() {
        # Define test functions with their parameters
        $this.TestFunctions = @{
            # Identity functions
            "Get-Users" = @{
                CSharp = "Get-Users"
                PowerShell = "Get-Users"
                Parameters = @{}
            }
            "Get-Groups" = @{
                CSharp = "Get-Groups"
                PowerShell = "Get-Groups"
                Parameters = @{}
            }
            "Get-Devices" = @{
                CSharp = "Get-Devices"
                PowerShell = "Get-Devices"
                Parameters = @{}
            }
            "Get-MFA" = @{
                CSharp = "Get-MFA"
                PowerShell = "Get-MFA"
                Parameters = @{}
            }

            # Audit functions
            "Get-UAL" = @{
                CSharp = "Get-UAL"
                PowerShell = "Get-UAL"
                Parameters = @{
                    StartDate = (Get-Date).AddDays(-7)
                    EndDate = Get-Date
                    OutputFormat = "CSV"
                }
            }
            "Get-UALStatistics" = @{
                CSharp = "Get-UALStatistics"
                PowerShell = "Get-UALStatistics"
                Parameters = @{
                    StartDate = (Get-Date).AddDays(-7)
                    EndDate = Get-Date
                }
            }
            "Get-AdminAuditLog" = @{
                CSharp = "Get-AdminAuditLog"
                PowerShell = "Get-AdminAuditLog"
                Parameters = @{
                    StartDate = (Get-Date).AddDays(-7)
                    EndDate = Get-Date
                }
            }

            # Mail functions
            "Get-MailboxPermissions" = @{
                CSharp = "Get-MailboxPermissions"
                PowerShell = "Get-MailboxPermissions"
                Parameters = @{}
            }
            "Get-MailboxRules" = @{
                CSharp = "Get-MailboxRules"
                PowerShell = "Get-MailboxRules"
                Parameters = @{}
            }

            # Security functions
            "Get-SecurityAlerts" = @{
                CSharp = "Get-SecurityAlerts"
                PowerShell = "Get-SecurityAlerts"
                Parameters = @{}
            }
            "Get-RiskyUsers" = @{
                CSharp = "Get-RiskyUsers"
                PowerShell = "Get-RiskyUsers"
                Parameters = @{}
            }

            # Azure functions
            "Get-ActivityLogs" = @{
                CSharp = "Get-AzureActivityLogs"
                PowerShell = "Get-ActivityLogs"
                Parameters = @{
                    StartDate = (Get-Date).AddDays(-7)
                    EndDate = Get-Date
                }
            }
        }
    }

    [void]WriteLog([string]$message, [string]$level = "Info") {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $color = switch ($level) {
            "Error" { "Red" }
            "Warning" { "Yellow" }
            "Success" { "Green" }
            default { "White" }
        }

        if ($this.LogLevel -eq "Verbose" -or
            ($this.LogLevel -eq "Detailed" -and $level -ne "Info") -or
            $level -eq "Error" -or $level -eq "Warning") {
            Write-Host "[$timestamp] [$level] $message" -ForegroundColor $color
        }
    }

    [void]RunWarmup([string]$functionName, [string]$moduleType) {
        $this.WriteLog("Running $WarmupRuns warmup run(s) for $functionName ($moduleType)...", "Info")

        for ($i = 1; $i -le $this.WarmupRuns; $i++) {
            try {
                $test = [PerformanceTest]::new("Warmup-$i", $moduleType, $functionName, $i, @{})
                $this.ExecuteTest($test)
                $this.WriteLog("Warmup run $i completed in $($test.Duration.TotalSeconds.ToString('F2'))s", "Info")
            }
            catch {
                $this.WriteLog("Warmup run $i failed: $($_.Exception.Message)", "Warning")
            }
        }
    }

    [void]ExecuteTest([PerformanceTest]$test) {
        $startMemory = [System.GC]::GetTotalMemory($false)
        $startCPU = (Get-Counter "\Processor(_Total)\% Processor Time").CounterSamples[0].CookedValue

        try {
            # Execute the function based on module type
            $functionName = $test.FunctionName
            $params = $test.Parameters.Clone()

            # Add common parameters
            if (-not $params.ContainsKey("OutputFormat")) {
                $params["OutputFormat"] = "CSV"
            }
            if (-not $params.ContainsKey("LogLevel")) {
                $params["LogLevel"] = "Minimal"
            }

            # Execute the function
            $result = & $functionName @params

            $test.Complete($true, "")
        }
        catch {
            $test.Complete($false, $_.Exception.Message)
            throw
        }
        finally {
            $endMemory = [System.GC]::GetTotalMemory($false)
            $endCPU = (Get-Counter "\Processor(_Total)\% Processor Time").CounterSamples[0].CookedValue

            $test.MemoryUsageMB = [math]::Round(($endMemory - $startMemory) / 1MB, 2)
            $test.CPUUsagePercent = [math]::Round($endCPU - $startCPU, 2)
        }
    }

    [void]RunTests([string]$testType, [string[]]$functions, [int]$iterations) {
        $this.WriteLog("Starting performance tests for $testType module...", "Info")

        $testFunctions = if ($functions.Count -gt 0) { $functions } else { $this.TestFunctions.Keys }

        foreach ($functionName in $testFunctions) {
            if (-not $this.TestFunctions.ContainsKey($functionName)) {
                $this.WriteLog("Function $functionName not found in test configuration", "Warning")
                continue
            }

            $functionConfig = $this.TestFunctions[$functionName]
            $moduleFunction = if ($testType -eq "CSharp") { $functionConfig.CSharp } else { $functionConfig.PowerShell }

            $this.WriteLog("Testing function: $functionName ($moduleFunction)", "Info")

            # Run warmup
            $this.RunWarmup($moduleFunction, $testType)

            # Run actual tests
            for ($i = 1; $i -le $iterations; $i++) {
                $this.WriteLog("Running iteration $i/$iterations for $functionName", "Info")

                $test = [PerformanceTest]::new("$functionName-$i", $testType, $moduleFunction, $i, $functionConfig.Parameters)

                try {
                    $this.ExecuteTest($test)
                    $this.TestResults.Add($test)
                    $this.WriteLog("Iteration $i completed successfully in $($test.Duration.TotalSeconds.ToString('F2'))s", "Success")
                }
                catch {
                    $this.WriteLog("Iteration $i failed: $($_.Exception.Message)", "Error")
                    $this.TestResults.Add($test)
                }
            }
        }
    }

    [void]ExportResults([string]$outputPath) {
        $this.WriteLog("Exporting results to $outputPath", "Info")

        $results = @()
        foreach ($test in $this.TestResults) {
            $results += [PSCustomObject]@{
                TestName = $test.TestName
                ModuleType = $test.ModuleType
                FunctionName = $test.FunctionName
                Iteration = $test.Iteration
                StartTime = $test.StartTime
                EndTime = $test.EndTime
                DurationSeconds = $test.Duration.TotalSeconds
                DurationMilliseconds = $test.Duration.TotalMilliseconds
                Success = $test.Success
                ErrorMessage = $test.ErrorMessage
                MemoryUsageMB = $test.MemoryUsageMB
                CPUUsagePercent = $test.CPUUsagePercent
                Parameters = ($test.Parameters | ConvertTo-Json -Compress)
            }
        }

        $results | Export-Csv -Path $outputPath -NoTypeInformation
        $this.WriteLog("Results exported successfully", "Success")
    }

    [void]GenerateSummary() {
        $this.WriteLog("Generating performance summary...", "Info")

        $summary = @{}

        foreach ($test in $this.TestResults) {
            $key = "$($test.ModuleType)_$($test.FunctionName)"

            if (-not $summary.ContainsKey($key)) {
                $summary[$key] = @{
                    ModuleType = $test.ModuleType
                    FunctionName = $test.FunctionName
                    TotalRuns = 0
                    SuccessfulRuns = 0
                    FailedRuns = 0
                    TotalDuration = [timespan]::Zero
                    AverageDuration = [timespan]::Zero
                    MinDuration = [timespan]::MaxValue
                    MaxDuration = [timespan]::Zero
                    TotalMemoryMB = 0
                    AverageMemoryMB = 0
                    TotalCPUPercent = 0
                    AverageCPUPercent = 0
                }
            }

            $stats = $summary[$key]
            $stats.TotalRuns++
            $stats.TotalDuration += $test.Duration
            $stats.TotalMemoryMB += $test.MemoryUsageMB
            $stats.TotalCPUPercent += $test.CPUUsagePercent

            if ($test.Success) {
                $stats.SuccessfulRuns++
            } else {
                $stats.FailedRuns++
            }

            if ($test.Duration -lt $stats.MinDuration) {
                $stats.MinDuration = $test.Duration
            }
            if ($test.Duration -gt $stats.MaxDuration) {
                $stats.MaxDuration = $test.Duration
            }
        }

        # Calculate averages
        foreach ($key in $summary.Keys) {
            $stats = $summary[$key]
            if ($stats.TotalRuns -gt 0) {
                $stats.AverageDuration = [timespan]::FromMilliseconds($stats.TotalDuration.TotalMilliseconds / $stats.TotalRuns)
                $stats.AverageMemoryMB = [math]::Round($stats.TotalMemoryMB / $stats.TotalRuns, 2)
                $stats.AverageCPUPercent = [math]::Round($stats.TotalCPUPercent / $stats.TotalRuns, 2)
            }
        }

        # Display summary
        $this.WriteLog("`n=== PERFORMANCE TEST SUMMARY ===", "Info")
        $this.WriteLog("Total tests executed: $($this.TestResults.Count)", "Info")

        foreach ($key in $summary.Keys | Sort-Object) {
            $stats = $summary[$key]
            $this.WriteLog("`n$($stats.ModuleType) - $($stats.FunctionName):", "Info")
            $this.WriteLog("  Runs: $($stats.SuccessfulRuns)/$($stats.TotalRuns) successful", "Info")
            $this.WriteLog("  Duration: Avg=$($stats.AverageDuration.TotalSeconds.ToString('F2'))s, Min=$($stats.MinDuration.TotalSeconds.ToString('F2'))s, Max=$($stats.MaxDuration.TotalSeconds.ToString('F2'))s", "Info")
            $this.WriteLog("  Memory: Avg=$($stats.AverageMemoryMB)MB", "Info")
            $this.WriteLog("  CPU: Avg=$($stats.AverageCPUPercent)%", "Info")
        }

        # Compare C# vs PowerShell
        $this.WriteLog("`n=== C# vs PowerShell Comparison ===", "Info")
        $csharpResults = $summary.Keys | Where-Object { $_ -like "CSharp_*" }
        $psResults = $summary.Keys | Where-Object { $_ -like "PowerShell_*" }

        foreach ($csharpKey in $csharpResults) {
            $functionName = $csharpKey.Replace("CSharp_", "")
            $psKey = "PowerShell_$functionName"

            if ($summary.ContainsKey($psKey)) {
                $csharp = $summary[$csharpKey]
                $ps = $summary[$psKey]

                $speedup = if ($csharp.AverageDuration.TotalMilliseconds -gt 0) {
                    $ps.AverageDuration.TotalMilliseconds / $csharp.AverageDuration.TotalMilliseconds
                } else { 0 }

                $this.WriteLog("$functionName:", "Info")
                $this.WriteLog("  C#: $($csharp.AverageDuration.TotalSeconds.ToString('F2'))s", "Info")
                $this.WriteLog("  PS: $($ps.AverageDuration.TotalSeconds.ToString('F2'))s", "Info")
                $this.WriteLog("  Speedup: ${speedup}x", if ($speedup -gt 1) { "Success" } else { "Warning" })
            }
        }
    }
}

# Main execution
try {
    Write-Host "Microsoft Extractor Suite - Performance Testing Tool" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan

    # Initialize test runner
    $runner = [PerformanceTestRunner]::new($LogLevel, $WarmupRuns)

    # Check if module is loaded
    if (-not (Get-Module -Name "Microsoft-Extractor-Suite")) {
        Write-Host "Loading Microsoft-Extractor-Suite module..." -ForegroundColor Yellow
        Import-Module "$PSScriptRoot\Microsoft-Extractor-Suite.psm1" -Force
    }

    # Run tests based on test type
    switch ($TestType) {
        "CSharp" {
            $runner.RunTests("CSharp", $TestFunctions, $Iterations)
        }
        "PowerShell" {
            $runner.RunTests("PowerShell", $TestFunctions, $Iterations)
        }
        "Both" {
            $runner.RunTests("CSharp", $TestFunctions, $Iterations)
            $runner.RunTests("PowerShell", $TestFunctions, $Iterations)
        }
    }

    # Export results
    $runner.ExportResults($OutputPath)

    # Generate summary
    $runner.GenerateSummary()

    Write-Host "`nPerformance testing completed successfully!" -ForegroundColor Green
    Write-Host "Results saved to: $OutputPath" -ForegroundColor Green
}
catch {
    Write-Host "Performance testing failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
