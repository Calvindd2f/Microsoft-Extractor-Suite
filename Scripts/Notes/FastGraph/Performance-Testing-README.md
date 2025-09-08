# Microsoft Extractor Suite - Performance Testing

This directory contains scripts for performance testing between C# binary modules and PowerShell script modules in the Microsoft Extractor Suite.

## Overview

The performance testing tools help you compare execution times, success rates, and resource usage between:
- **C# Binary Modules**: Compiled .NET cmdlets with optimized performance
- **PowerShell Script Modules**: Pure PowerShell implementations

## Available Scripts

### 1. Quick-Performance-Test.ps1
A simple, focused performance testing script for quick comparisons.

**Features:**
- Single function testing
- Configurable iterations
- Memory and timing measurements
- Success/failure tracking
- CSV output

**Usage:**
```powershell
# Test Get-Users function with 5 iterations
.\Quick-Performance-Test.ps1 -FunctionName "Get-Users" -Iterations 5

# Test Get-Groups with custom output file
.\Quick-Performance-Test.ps1 -FunctionName "Get-Groups" -OutputFile "groups-test.csv"

# Test only C# version
.\Quick-Performance-Test.ps1 -FunctionName "Get-UAL" -TestBoth $false
```

### 2. Test-Performance.ps1
A comprehensive performance testing framework with advanced features.

**Features:**
- Multiple function testing
- Warmup runs
- Detailed logging levels
- Advanced metrics
- Comprehensive reporting

**Usage:**
```powershell
# Test all functions with both C# and PowerShell
.\Test-Performance.ps1 -TestType Both -Iterations 3

# Test specific functions with C# only
.\Test-Performance.ps1 -TestType CSharp -TestFunctions @("Get-Users", "Get-Groups")

# Verbose logging with 5 iterations
.\Test-Performance.ps1 -TestType Both -Iterations 5 -LogLevel Verbose
```

### 3. Run-Performance-Tests.bat
A Windows batch script for easy command-line testing.

**Usage:**
```cmd
# Basic test
Run-Performance-Tests.bat

# Test specific function
Run-Performance-Tests.bat --function Get-Groups --iterations 10

# C# only test
Run-Performance-Tests.bat --function Get-UAL --csharp-only

# Custom output file
Run-Performance-Tests.bat --function Get-Users --output my-results.csv
```

## Supported Functions

The following functions can be tested:

### Identity Functions
- `Get-Users` - Retrieve user information
- `Get-Groups` - Retrieve group information
- `Get-Devices` - Retrieve device information
- `Get-MFA` - Retrieve MFA status

### Audit Functions
- `Get-UAL` - Unified Audit Log retrieval
- `Get-UALStatistics` - UAL statistics
- `Get-AdminAuditLog` - Admin audit log

### Mail Functions
- `Get-MailboxPermissions` - Mailbox permissions
- `Get-MailboxRules` - Mailbox rules

### Security Functions
- `Get-SecurityAlerts` - Security alerts
- `Get-RiskyUsers` - Risky users

### Azure Functions
- `Get-ActivityLogs` - Azure activity logs

## Output Format

All scripts generate CSV files with the following columns:

| Column | Description |
|--------|-------------|
| FunctionName | Name of the tested function |
| ModuleType | CSharp, PowerShell, or Current |
| StartTime | Test start timestamp |
| EndTime | Test end timestamp |
| DurationSeconds | Execution time in seconds |
| DurationMilliseconds | Execution time in milliseconds |
| Success | True/False indicating success |
| ErrorMessage | Error message if failed |
| MemoryUsageMB | Memory usage in MB |
| CPUUsagePercent | CPU usage percentage |

## Performance Metrics

The scripts measure:

1. **Execution Time**: Total time to complete the function
2. **Success Rate**: Percentage of successful executions
3. **Memory Usage**: Memory consumption during execution
4. **CPU Usage**: CPU utilization during execution
5. **Error Tracking**: Detailed error messages for failed tests

## Best Practices

### 1. Environment Setup
- Ensure you have proper authentication configured
- Use a consistent environment for fair comparisons
- Close unnecessary applications to reduce interference

### 2. Test Configuration
- Use multiple iterations (3-10) for reliable results
- Include warmup runs to account for JIT compilation
- Test during off-peak hours for consistent network performance

### 3. Result Analysis
- Focus on average execution times rather than single runs
- Consider success rates alongside performance
- Account for network latency in cloud-based functions

### 4. Interpreting Results

**C# vs PowerShell Comparison:**
- C# modules typically show 2-10x performance improvement
- PowerShell modules may be more flexible for customization
- Memory usage is usually lower with C# modules

**Success Rate Analysis:**
- 100% success rate indicates stable implementation
- Lower success rates may indicate authentication or permission issues
- Consistent errors suggest configuration problems

## Example Results

```
=== PERFORMANCE SUMMARY ===
ModuleType    TotalRuns  SuccessfulRuns  FailedRuns  SuccessRate  AverageDuration  MinDuration  MaxDuration  AverageMemoryMB
----------    ---------  --------------  ----------  -----------  ----------------  -----------  -----------  ----------------
CSharp        5          5               0           100.0        2.34              2.12         2.67         45.2
PowerShell    5          5               0           100.0        8.91              8.45         9.23         78.6

=== C# vs PowerShell Comparison ===
Get-Users:
  C#: 2.34s
  PowerShell: 8.91s
  Speedup: 3.8x
```

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Ensure proper connection to Microsoft 365/Azure
   - Check required permissions and scopes
   - Verify certificate/app registration

2. **Module Loading Issues**
   - Ensure Microsoft-Extractor-Suite module is available
   - Check PowerShell execution policy
   - Verify module dependencies

3. **Performance Variations**
   - Network latency affects cloud-based functions
   - System load impacts results
   - JIT compilation affects first runs

### Error Messages

- **"Function not found"**: Check function name spelling
- **"Module not loaded"**: Import Microsoft-Extractor-Suite module
- **"Authentication failed"**: Reconnect to Microsoft services
- **"Permission denied"**: Check required scopes and permissions

## Advanced Usage

### Custom Test Parameters

You can modify the test parameters in the scripts:

```powershell
# Custom parameters for UAL testing
$testParams = @{
    StartDate = (Get-Date).AddDays(-30)
    EndDate = Get-Date
    OutputFormat = "JSON"
    LogLevel = "Minimal"
}
```

### Batch Testing

Create a batch file to test multiple functions:

```cmd
@echo off
for %%f in (Get-Users Get-Groups Get-Devices) do (
    echo Testing %%f...
    Run-Performance-Tests.bat --function %%f --iterations 3 --output %%f-results.csv
)
```

### Automated Reporting

Use PowerShell to generate automated reports:

```powershell
$results = Import-Csv "performance-results.csv"
$summary = $results | Group-Object ModuleType | ForEach-Object {
    # Generate summary statistics
}
$summary | Export-Csv "performance-summary.csv"
```

## Support

For issues with the performance testing scripts:
1. Check the troubleshooting section above
2. Review error messages in the output
3. Verify your Microsoft Extractor Suite installation
4. Ensure proper authentication and permissions

## Contributing

To add new functions to the performance testing framework:
1. Update the `InitializeTestFunctions()` method in `Test-Performance.ps1`
2. Add appropriate test parameters
3. Update this README with new function documentation
4. Test the new function thoroughly before committing
