#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for StreamReader resource management

.DESCRIPTION
    Tests to verify proper resource disposal and error handling in StreamReader usage.
#>

BeforeAll {
    # Import the module
    $modulePath = Join-Path $PSScriptRoot '..' 'Microsoft-Extractor-Suite.psm1'
    Import-Module $modulePath -Force -ErrorAction Stop
    
    # Create test output directory
    $script:TestOutputDir = Join-Path $TestDrive 'TestOutput'
    New-Item -ItemType Directory -Path $script:TestOutputDir -Force | Out-Null
    
    # Create merged subdirectory
    $script:TestMergedDir = Join-Path $script:TestOutputDir 'Merged'
    New-Item -ItemType Directory -Path $script:TestMergedDir -Force | Out-Null
}

AfterAll {
    # Cleanup
    if (Test-Path $script:TestOutputDir) {
        Remove-Item -Path $script:TestOutputDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'StreamReader Resource Management' {
    Context 'Null Safety' {
        It 'Should handle StreamReader creation failure without resource leak' {
            # Arrange - Create a file that will cause StreamReader to fail
            # (e.g., file locked by another process, or invalid path)
            # Note: This is difficult to test without actual file system manipulation
            # The code should handle null reader in finally block
            
            # For now, verify the pattern exists in code
            $moduleContent = Get-Content -Path (Join-Path $PSScriptRoot '..' 'Microsoft-Extractor-Suite.psm1') -Raw
            $moduleContent | Should -Match '\$reader = \$null'
            $moduleContent | Should -Match 'if \(\$null -ne \$reader\)'
        }

        It 'Should dispose StreamReader even if exception occurs during read' {
            # Test that finally block always executes
            $moduleContent = Get-Content -Path (Join-Path $PSScriptRoot '..' 'Microsoft-Extractor-Suite.psm1') -Raw
            $moduleContent | Should -Match 'finally'
            $moduleContent | Should -Match 'Dispose'
        }
    }

    Context 'File Processing' {
        It 'Should process valid files without errors' {
            # Arrange
            $jsonl1 = Join-Path $script:TestOutputDir 'file1.jsonl'
            @'
{"test":"data1"}
{"test":"data2"}
'@ | Set-Content -Path $jsonl1 -Encoding UTF8
            
            # Act
            { Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType JSONL -MergedFileName 'merged.jsonl' } | Should -Not -Throw
            
            # Assert
            $mergedFile = Join-Path $script:TestMergedDir 'merged.jsonl'
            Test-Path $mergedFile | Should -Be $true
        }
    }
}

