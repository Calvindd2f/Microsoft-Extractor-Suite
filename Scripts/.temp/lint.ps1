function Test-ScriptOptimization {
    param (
        [string]$ScriptContent
    )

    $patterns = @{
        'Pipe to Out-Null'                                    = '(\| *Out-Null)'
        'Operator to Array += '                               = '\+= *\@'
        'Operator to String += '                              = '\+= *"'
        'Get-Content, Set-Content, Add-Content'               = '\b(Get-Content|Set-Content|Add-Content)\b'
        'Write-Host'                                          = '\bWrite-Host\b'
        'Looking up entries by property in large collections' = '\$[a-zA-Z0-9]+ \| ForEach-Object -Process *{ *\$[a-zA-Z0-9]+ = \$_ *\$[a-zA-Z0-9]+ = \$[a-zA-Z0-9]+ \| Where-Object -FilterScript *{ *\$_\.Name -eq \$[a-zA-Z0-9]+\.Name *}'
        'Avoid repeated calls to a function'                  = '\b([a-zA-Z0-9_]+\(\))'
        'OrderedDictionary'                                   = '\[ordered\].*\[pscustomobject\]|Add-Member|PSObject\.Properties\.Add'
    }

    $recommendations = @{
        'Pipe to Out-Null'                                    = 'Avoid using | Out-Null. Instead, assign the output to $null.'
        'Operator to Array += '                               = 'Avoid using += for arrays. Use array lists (e.g., [System.Collections.ArrayList]) for better performance.'
        'Operator to String += '                              = 'Avoid using += for strings. Use the [System.Text.StringBuilder] class for better performance.'
        'Get-Content, Set-Content, Add-Content'               = 'Consider using other cmdlets such as Import-Csv, Export-Csv, or Out-File for handling file content more efficiently.'
        'Write-Host'                                          = 'Avoid using Write-Host. Use Write-Output or other Write-* cmdlets instead.'
        'Looking up entries by property in large collections' = 'Use a hash table for lookups instead of iterating over collections repeatedly.'
        'Avoid repeated calls to a function'                  = 'Avoid calling functions repeatedly within loops. Store the result in a variable outside the loop if possible.'
        'OrderedDictionary'                                   = 'Use [ordered] hashtable to [pscustomobject] cast, Add-Member, or PSObject.Properties.Add for dynamically creating new objects.'
    }

    $issuesFound = @()

    foreach ($pattern in $patterns.GetEnumerator()) {
        if ($ScriptContent -match $pattern.Value) {
            $issuesFound += [PSCustomObject]@{
                Pattern     = $pattern.Key
                Recommendation = $recommendations[$pattern.Key]
            }
        }
    }

    if ($issuesFound.Count -eq 0) {
        Write-Output "No issues found in the script."
    } else {
        Write-Output "Issues found in the script:"

        $issuesFound | ForEach-Object {
            Write-Output " - $($_.Pattern): $($_.Recommendation)"
        }
    }
}

$scripts = Get-ChildItem -Path .\scripts -Filter *.ps1 -Recurse

$runningJobs = @()

foreach ($script in $scripts) {
    $runningJob = Start-Job -ScriptBlock {
        param (
            [string]$scriptPath
        )

        $scriptContent = Get-Content -Path $scriptPath
        Test-ScriptOptimization -ScriptContent $scriptContent
    } -ArgumentList $script.FullName

    $runningJobs += $runningJob
}

Wait-Job -Job $runningJobs

$results = Receive-Job -Job $runningJobs

Write-Output "Optimization results:"
$results
