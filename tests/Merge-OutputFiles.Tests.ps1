#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for Merge-OutputFiles function

.DESCRIPTION
    Comprehensive test suite covering edge cases, error handling, and performance scenarios
    for the Merge-OutputFiles function in Microsoft-Extractor-Suite module.
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

Describe 'Merge-OutputFiles - CSV Format' {
    BeforeEach {
        # Clean merged directory before each test
        Get-ChildItem -Path $script:TestMergedDir -ErrorAction SilentlyContinue | Remove-Item -Force
    }

    Context 'Basic CSV Merging' {
        It 'Should merge multiple CSV files with data' {
            # Arrange
            $csv1 = Join-Path $script:TestOutputDir 'file1.csv'
            $csv2 = Join-Path $script:TestOutputDir 'file2.csv'

            @'
Name,Value
Item1,100
Item2,200
'@ | Set-Content -Path $csv1 -Encoding UTF8

            @'
Name,Value
Item3,300
Item4,400
'@ | Set-Content -Path $csv2 -Encoding UTF8

            $mergedFile = Join-Path $script:TestMergedDir 'merged.csv'

            # Act
            Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType CSV -MergedFileName 'merged.csv'

            # Assert
            $result = Import-Csv -Path $mergedFile
            $result.Count | Should -Be 4
            $result[0].Name | Should -Be 'Item1'
            $result[3].Name | Should -Be 'Item4'
        }

        It 'Should handle CSV files with different column orders' {
            # Arrange
            $csv1 = Join-Path $script:TestOutputDir 'file1.csv'
            $csv2 = Join-Path $script:TestOutputDir 'file2.csv'

            @'
Name,Value,Category
Item1,100,TypeA
'@ | Set-Content -Path $csv1 -Encoding UTF8

            @'
Value,Category,Name
200,TypeB,Item2
'@ | Set-Content -Path $csv2 -Encoding UTF8

            # Act
            Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType CSV -MergedFileName 'merged.csv'

            # Assert
            $mergedFile = Join-Path $script:TestMergedDir 'merged.csv'
            $result = Import-Csv -Path $mergedFile
            $result.Count | Should -Be 2
            # Columns should be reordered to match first file
            $result[0].PSObject.Properties.Name | Should -Contain 'Name'
            $result[0].PSObject.Properties.Name | Should -Contain 'Value'
        }
    }

    Context 'Edge Cases - Empty Files' {
        It 'Should skip empty CSV files' {
            # Arrange
            $csv1 = Join-Path $script:TestOutputDir 'file1.csv'
            $csv2 = Join-Path $script:TestOutputDir 'file2.csv'
            $csv3 = Join-Path $script:TestOutputDir 'empty.csv'

            @'
Name,Value
Item1,100
'@ | Set-Content -Path $csv1 -Encoding UTF8

            @'
Name,Value
Item2,200
'@ | Set-Content -Path $csv2 -Encoding UTF8

            # Create empty file
            '' | Set-Content -Path $csv3 -Encoding UTF8

            # Act
            Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType CSV -MergedFileName 'merged.csv'

            # Assert
            $mergedFile = Join-Path $script:TestMergedDir 'merged.csv'
            if (Test-Path $mergedFile) {
                $result = Import-Csv -Path $mergedFile
                $result.Count | Should -Be 2
            }
        }

        It 'Should handle CSV file with only header row' {
            # Arrange
            $csv1 = Join-Path $script:TestOutputDir 'header_only.csv'

            @'
Name,Value
'@ | Set-Content -Path $csv1 -Encoding UTF8

            # Act
            Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType CSV -MergedFileName 'merged.csv'

            # Assert
            $mergedFile = Join-Path $script:TestMergedDir 'merged.csv'
            if (Test-Path $mergedFile) {
                $result = Import-Csv -Path $mergedFile
                $result.Count | Should -Be 0
            }
        }

        It 'Should handle no CSV files found' {
            # Arrange - empty directory
            Get-ChildItem -Path $script:TestOutputDir -Filter *.csv | Remove-Item -Force

            # Act
            { Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType CSV -MergedFileName 'merged.csv' } | Should -Not -Throw

            # Assert
            $mergedFile = Join-Path $script:TestMergedDir 'merged.csv'
            Test-Path $mergedFile | Should -Be $false
        }
    }

    Context 'Error Handling' {
        It 'Should handle corrupted CSV files gracefully' {
            # Arrange
            $csv1 = Join-Path $script:TestOutputDir 'file1.csv'
            $csv2 = Join-Path $script:TestOutputDir 'corrupted.csv'

            @'
Name,Value
Item1,100
'@ | Set-Content -Path $csv1 -Encoding UTF8

            # Create corrupted CSV
            @'
Name,Value
Invalid,Data,Too,Many,Columns
'@ | Set-Content -Path $csv2 -Encoding UTF8

            # Act
            { Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType CSV -MergedFileName 'merged.csv' } | Should -Not -Throw

            # Assert - should process valid file
            $mergedFile = Join-Path $script:TestMergedDir 'merged.csv'
            if (Test-Path $mergedFile) {
                $result = Import-Csv -Path $mergedFile
                $result.Count | Should -BeGreaterOrEqual 1
            }
        }
    }
}

Describe 'Merge-OutputFiles - JSONL Format' {
    BeforeEach {
        Get-ChildItem -Path $script:TestMergedDir -ErrorAction SilentlyContinue | Remove-Item -Force
    }

    Context 'Basic JSONL Merging' {
        It 'Should merge multiple JSONL files' {
            # Arrange
            $jsonl1 = Join-Path $script:TestOutputDir 'file1.jsonl'
            $jsonl2 = Join-Path $script:TestOutputDir 'file2.jsonl'

            @'
{"name":"Item1","value":100}
{"name":"Item2","value":200}
'@ | Set-Content -Path $jsonl1 -Encoding UTF8

            @'
{"name":"Item3","value":300}
{"name":"Item4","value":400}
'@ | Set-Content -Path $jsonl2 -Encoding UTF8

            # Act
            Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType JSONL -MergedFileName 'merged.jsonl'

            # Assert
            $mergedFile = Join-Path $script:TestMergedDir 'merged.jsonl'
            $result = Get-Content -Path $mergedFile
            $result.Count | Should -Be 4
            $result[0] | Should -Match 'Item1'
            $result[3] | Should -Match 'Item4'
        }

        It 'Should handle empty JSONL files' {
            # Arrange
            $jsonl1 = Join-Path $script:TestOutputDir 'file1.jsonl'
            $jsonl2 = Join-Path $script:TestOutputDir 'empty.jsonl'

            @'
{"name":"Item1","value":100}
'@ | Set-Content -Path $jsonl1 -Encoding UTF8

            '' | Set-Content -Path $jsonl2 -Encoding UTF8

            # Act
            Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType JSONL -MergedFileName 'merged.jsonl'

            # Assert
            $mergedFile = Join-Path $script:TestMergedDir 'merged.jsonl'
            $result = Get-Content -Path $mergedFile
            $result.Count | Should -Be 1
        }

        It 'Should skip blank lines in JSONL files' {
            # Arrange
            $jsonl1 = Join-Path $script:TestOutputDir 'file1.jsonl'

            @'
{"name":"Item1","value":100}

{"name":"Item2","value":200}
'@ | Set-Content -Path $jsonl1 -Encoding UTF8

            # Act
            Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType JSONL -MergedFileName 'merged.jsonl'

            # Assert
            $mergedFile = Join-Path $script:TestMergedDir 'merged.jsonl'
            $result = Get-Content -Path $mergedFile
            $result.Count | Should -Be 2
        }
    }

    Context 'Error Handling' {
        It 'Should handle no JSONL files found' {
            # Arrange
            Get-ChildItem -Path $script:TestOutputDir -Filter *.jsonl | Remove-Item -Force

            # Act
            { Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType JSONL -MergedFileName 'merged.jsonl' } | Should -Not -Throw

            # Assert - should not create merged file
            $mergedFile = Join-Path $script:TestMergedDir 'merged.jsonl'
            if (Test-Path $mergedFile) {
                $content = Get-Content -Path $mergedFile
                $content.Count | Should -Be 0
            }
        }
    }
}

Describe 'Merge-OutputFiles - TSV Format' {
    BeforeEach {
        Get-ChildItem -Path $script:TestMergedDir -ErrorAction SilentlyContinue | Remove-Item -Force
    }

    Context 'Basic TSV Merging' {
        It 'Should merge multiple TSV files with header deduplication' {
            # Arrange
            $tsv1 = Join-Path $script:TestOutputDir 'file1.tsv'
            $tsv2 = Join-Path $script:TestOutputDir 'file2.tsv'

            @'
Name	Value
Item1	100
Item2	200
'@ | Set-Content -Path $tsv1 -Encoding UTF8

            @'
Name	Value
Item3	300
Item4	400
'@ | Set-Content -Path $tsv2 -Encoding UTF8

            # Act
            Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType TSV -MergedFileName 'merged.tsv'

            # Assert
            $mergedFile = Join-Path $script:TestMergedDir 'merged.tsv'
            $result = Get-Content -Path $mergedFile
            $result.Count | Should -Be 5  # 1 header + 4 data rows
            $result[0] | Should -Match 'Name'
            $result[1] | Should -Match 'Item1'
            $result[4] | Should -Match 'Item4'
        }
    }
}

Describe 'Merge-OutputFiles - Performance Considerations' {
    It 'Should handle large number of files efficiently' {
        # Arrange - Create 10 CSV files
        for ($i = 1; $i -le 10; $i++) {
            $csvFile = Join-Path $script:TestOutputDir "file$i.csv"
            @"
Name,Value
Item$i,$($i * 100)
"@ | Set-Content -Path $csvFile -Encoding UTF8
        }

        # Act
        $startTime = Get-Date
        Merge-OutputFiles -OutputDir $script:TestOutputDir -OutputType CSV -MergedFileName 'merged.csv'
        $duration = (Get-Date) - $startTime

        # Assert
        $mergedFile = Join-Path $script:TestMergedDir 'merged.csv'
        $result = Import-Csv -Path $mergedFile
        $result.Count | Should -Be 10
        $duration.TotalSeconds | Should -BeLessThan 30  # Should complete in reasonable time
    }
}

