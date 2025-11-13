# Microsoft-Extractor-Suite Test Suite

This directory contains Pester tests for the Microsoft-Extractor-Suite module.

## Prerequisites

Install Pester module:
```powershell
Install-Module -Name Pester -Force -SkipPublisherCheck
```

## Running Tests

Run all tests:
```powershell
Invoke-Pester -Path .\tests\
```

Run specific test file:
```powershell
Invoke-Pester -Path .\tests\Merge-OutputFiles.Tests.ps1
```

Run with code coverage:
```powershell
Invoke-Pester -Path .\tests\ -CodeCoverage ..\Microsoft-Extractor-Suite.psm1
```

## Test Coverage

### Merge-OutputFiles.Tests.ps1
- CSV format merging (basic, edge cases, error handling)
- JSONL format merging
- TSV format merging
- Performance tests

### Update-Mechanism.Tests.ps1
- Backup creation
- Update verification
- Rollback mechanism

### StreamReader.Tests.ps1
- Resource management
- Null safety
- Error handling

## Test Data

Tests use Pester's `$TestDrive` for temporary file creation. All test data is automatically cleaned up after tests complete.

## Contributing

When adding new functionality, please add corresponding tests:
1. Test happy path scenarios
2. Test edge cases (empty files, invalid data, etc.)
3. Test error handling
4. Test performance for large datasets

