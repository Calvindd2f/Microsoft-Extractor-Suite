# Microsoft Extractor Suite - ML Pipeline Examples
# This script demonstrates how to use the ML pipeline cmdlets for data collection and risk simulation

# ⚠️ IMPORTANT: This script is for legitimate security testing and research purposes only
# ⚠️ ONLY use on your own developer tenant with test data
# ⚠️ DO NOT use customer data or production environments

Write-Host "Microsoft Extractor Suite - ML Pipeline Examples" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host ""

# Example 1: Basic Training Data Generation
Write-Host "Example 1: Basic Training Data Generation" -ForegroundColor Yellow
Write-Host "-------------------------------------------" -ForegroundColor Yellow

try {
    # Generate training data from sign-in logs and audit logs for the last 30 days
    $outputPath = "C:\MLData\basic_training.jsonl"

    Write-Host "Generating basic training data..." -ForegroundColor Cyan
    $result = Get-MLTrainingData -OutputPath $outputPath -DataSources "SignInLogs", "AuditLogs" -MaxRecordsPerSource 5000

    Write-Host "Training data generated successfully!" -ForegroundColor Green
    Write-Host "Output file: $outputPath" -ForegroundColor White
    Write-Host "Total records: $($result.Summary.TotalRecords)" -ForegroundColor White
    Write-Host ""
}
catch {
    Write-Host "Error generating training data: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# Example 2: Comprehensive Training Data with Synthetic Data
Write-Host "Example 2: Comprehensive Training Data with Synthetic Data" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------" -ForegroundColor Yellow

try {
    # Generate comprehensive training data with synthetic data for better model training
    $outputPath = "C:\MLData\comprehensive_training.jsonl"

    Write-Host "Generating comprehensive training data with synthetic data..." -ForegroundColor Cyan
    $result = Get-MLTrainingData -OutputPath $outputPath -DataSources "All" -StartDate (Get-Date).AddDays(-60) -EndDate (Get-Date) -IncludeSyntheticData -SyntheticDataPercentage 25 -OutputFormat "Both" -IncludeQualityMetrics -IncludeSchema

    Write-Host "Comprehensive training data generated successfully!" -ForegroundColor Green
    Write-Host "Output file: $outputPath" -ForegroundColor White
    Write-Host "Total records: $($result.Summary.TotalRecords)" -ForegroundColor White
    Write-Host "Quality metrics included: $($result.QualityMetrics -ne $null)" -ForegroundColor White
    Write-Host ""
}
catch {
    Write-Host "Error generating comprehensive training data: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# Example 3: Risk Simulation - Anonymous IP
Write-Host "Example 3: Risk Simulation - Anonymous IP" -ForegroundColor Yellow
Write-Host "-------------------------------------------" -ForegroundColor Yellow

try {
    # Simulate anonymous IP address detection
    Write-Host "Starting Anonymous IP risk simulation..." -ForegroundColor Cyan
    $simulationResult = Start-RiskSimulation -RiskType "AnonymousIP" -TestAccount "test@yourtenant.onmicrosoft.com" -UseTorBrowser -SimulationAttempts 3 -DelayBetweenAttempts 60

    Write-Host "Anonymous IP simulation completed!" -ForegroundColor Green
    Write-Host "Risk Type: $($simulationResult.SimulationResult.RiskType)" -ForegroundColor White
    Write-Host "Expected Outcome: $($simulationResult.SimulationResult.ExpectedOutcome)" -ForegroundColor White
    Write-Host "Expected Detection Time: $($simulationResult.SimulationResult.ExpectedDetectionTime)" -ForegroundColor White
    Write-Host ""

    # Display simulation steps
    Write-Host "Simulation Steps:" -ForegroundColor Cyan
    foreach ($step in $simulationResult.SimulationResult.Steps) {
        Write-Host "  $step" -ForegroundColor White
    }
    Write-Host ""
}
catch {
    Write-Host "Error during Anonymous IP simulation: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# Example 4: Risk Simulation - Unfamiliar Sign-In
Write-Host "Example 4: Risk Simulation - Unfamiliar Sign-In" -ForegroundColor Yellow
Write-Host "------------------------------------------------" -ForegroundColor Yellow

try {
    # Simulate unfamiliar sign-in properties
    Write-Host "Starting Unfamiliar Sign-In risk simulation..." -ForegroundColor Cyan
    $simulationResult = Start-RiskSimulation -RiskType "UnfamiliarSignIn" -TestAccount "admin@yourtenant.onmicrosoft.com" -UseVPN -SimulationAttempts 2 -DelayBetweenAttempts 120

    Write-Host "Unfamiliar Sign-In simulation completed!" -ForegroundColor Green
    Write-Host "Risk Type: $($simulationResult.SimulationResult.RiskType)" -ForegroundColor White
    Write-Host "Expected Outcome: $($simulationResult.SimulationResult.ExpectedOutcome)" -ForegroundColor White
    Write-Host "Expected Detection Time: $($simulationResult.SimulationResult.ExpectedDetectionTime)" -ForegroundColor White
    Write-Host ""

    # Display prerequisites
    Write-Host "Prerequisites:" -ForegroundColor Cyan
    foreach ($prereq in $simulationResult.SimulationResult.Prerequisites) {
        Write-Host "  - $prereq" -ForegroundColor White
    }
    Write-Host ""
}
catch {
    Write-Host "Error during Unfamiliar Sign-In simulation: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# Example 5: OpenPipe Data Export
Write-Host "Example 5: OpenPipe Data Export" -ForegroundColor Yellow
Write-Host "--------------------------------" -ForegroundColor Yellow

try {
    # Export data in OpenPipe format for fine-tuning
    $outputPath = "C:\MLData\openpipe_export.jsonl"

    Write-Host "Exporting data in OpenPipe format..." -ForegroundColor Cyan
    $exportResult = Export-OpenPipeData -OutputPath $outputPath -DataSources "SignInLogs", "AuditLogs" -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -IncludeSyntheticData -SyntheticDataPercentage 20 -OutputFormat "OpenPipe" -IncludeQualityMetrics -IncludeSchema

    Write-Host "OpenPipe export completed successfully!" -ForegroundColor Green
    Write-Host "Output files:" -ForegroundColor White
    foreach ($file in $exportResult.ExportResults.Values) {
        Write-Host "  $file" -ForegroundColor White
    }
    Write-Host "Total records: $($exportResult.Summary.TotalRecords)" -ForegroundColor White
    Write-Host ""
}
catch {
    Write-Host "Error during OpenPipe export: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# Example 6: Data Quality Analysis
Write-Host "Example 6: Data Quality Analysis" -ForegroundColor Yellow
Write-Host "--------------------------------" -ForegroundColor Yellow

try {
    # Generate training data with quality metrics
    $outputPath = "C:\MLData\quality_analysis.jsonl"

    Write-Host "Generating training data with quality analysis..." -ForegroundColor Cyan
    $result = Get-MLTrainingData -OutputPath $outputPath -DataSources "All" -MaxRecordsPerSource 2000 -IncludeQualityMetrics -IncludeSchema

    if ($result.QualityMetrics -ne $null) {
        Write-Host "Data quality analysis completed!" -ForegroundColor Green
        Write-Host "Total Records: $($result.QualityMetrics.TotalRecords)" -ForegroundColor White
        Write-Host "Missing Values: $($result.QualityMetrics.MissingValuesPercentage)%" -ForegroundColor White
        Write-Host "Data Sources: $($result.QualityMetrics.DataSourcesCount)" -ForegroundColor White
        Write-Host "Date Range: $($result.QualityMetrics.DateRangeStart) to $($result.QualityMetrics.DateRangeEnd)" -ForegroundColor White
        Write-Host ""

        # Display missing values by feature
        if ($result.QualityMetrics.MissingValuesByFeature -and $result.QualityMetrics.MissingValuesByFeature.Count -gt 0) {
            Write-Host "Missing Values by Feature:" -ForegroundColor Cyan
            foreach ($feature in $result.QualityMetrics.MissingValuesByFeature.Keys) {
                $count = $result.QualityMetrics.MissingValuesByFeature[$feature]
                Write-Host "  $feature`: $count" -ForegroundColor White
            }
            Write-Host ""
        }
    }
}
catch {
    Write-Host "Error during data quality analysis: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# Example 7: Custom Date Range Collection
Write-Host "Example 7: Custom Date Range Collection" -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Yellow

try {
    # Collect data for a specific date range
    $startDate = Get-Date "2024-01-01"
    $endDate = Get-Date "2024-01-31"
    $outputPath = "C:\MLData\january_2024.jsonl"

    Write-Host "Collecting data for January 2024..." -ForegroundColor Cyan
    $result = Get-MLTrainingData -OutputPath $outputPath -DataSources "SignInLogs", "AuditLogs" -StartDate $startDate -EndDate $endDate -MaxRecordsPerSource 10000

    Write-Host "January 2024 data collection completed!" -ForegroundColor Green
    Write-Host "Output file: $outputPath" -ForegroundColor White
    Write-Host "Date range: $startDate to $endDate" -ForegroundColor White
    Write-Host "Total records: $($result.Summary.TotalRecords)" -ForegroundColor White
    Write-Host ""
}
catch {
    Write-Host "Error during custom date range collection: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# Example 8: Compliance Report Generation
Write-Host "Example 8: Compliance Report Generation" -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Yellow

try {
    # Export data with compliance notices
    $outputPath = "C:\MLData\compliance_export.jsonl"

    Write-Host "Generating compliance export..." -ForegroundColor Cyan
    $exportResult = Export-OpenPipeData -OutputPath $outputPath -DataSources "All" -MaxRecordsPerSource 5000 -IncludeComplianceNotices -OutputFormat "Both"

    Write-Host "Compliance export completed!" -ForegroundColor Green
    Write-Host "Output files:" -ForegroundColor White
    foreach ($file in $exportResult.ExportResults.Values) {
        Write-Host "  $file" -ForegroundColor White
    }

    # Display compliance information
    if ($exportResult.ComplianceReport -ne $null) {
        Write-Host "Compliance Information:" -ForegroundColor Cyan
        Write-Host "  Purpose: $($exportResult.ComplianceReport.ExportPurpose)" -ForegroundColor White
        Write-Host "  Usage: $($exportResult.ComplianceReport.DataUsage)" -ForegroundColor White
        Write-Host "  Status: $($exportResult.ComplianceReport.ComplianceStatus)" -ForegroundColor White
        Write-Host ""
    }
}
catch {
    Write-Host "Error during compliance export: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# Summary
Write-Host "ML Pipeline Examples Summary" -ForegroundColor Green
Write-Host "============================" -ForegroundColor Green
Write-Host ""

Write-Host "Examples demonstrated:" -ForegroundColor Cyan
Write-Host "1. Basic training data generation" -ForegroundColor White
Write-Host "2. Comprehensive training data with synthetic data" -ForegroundColor White
Write-Host "3. Anonymous IP risk simulation" -ForegroundColor White
Write-Host "4. Unfamiliar sign-in risk simulation" -ForegroundColor White
Write-Host "5. OpenPipe format export" -ForegroundColor White
Write-Host "6. Data quality analysis" -ForegroundColor White
Write-Host "7. Custom date range collection" -ForegroundColor White
Write-Host "8. Compliance report generation" -ForegroundColor White
Write-Host ""

Write-Host "Output files created in: C:\MLData\" -ForegroundColor Yellow
Write-Host ""

Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Review the generated data files" -ForegroundColor White
Write-Host "2. Upload OpenPipe format files to OpenPipe platform" -ForegroundColor White
Write-Host "3. Use standard JSONL files for other ML frameworks" -ForegroundColor White
Write-Host "4. Monitor your tenant for risk detections from simulations" -ForegroundColor White
Write-Host "5. Review compliance reports for legal documentation" -ForegroundColor White
Write-Host ""

Write-Host "⚠️  REMEMBER: This tool is for legitimate security testing and research purposes only!" -ForegroundColor Red
Write-Host "⚠️  Only use on your own developer tenant with test data!" -ForegroundColor Red
Write-Host "⚠️  Do not use customer data or production environments!" -ForegroundColor Red
Write-Host ""

Write-Host "ML Pipeline examples completed successfully!" -ForegroundColor Green
