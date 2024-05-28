# Displays transport rules
Function Show-TransportRules {
    [OutputDir]
    [String] $OutputDir = ".",

    [Encoding]
    [String] $Encoding = "utf8"

    Get-TransportRules |
        ForEach-Object {
            $rule = $_
            $outputPath = Join-Path -Path $OutputDir -ChildPath "$($rule.Name).txt"
            $rule | Out-File -FilePath $outputPath -Encoding $Encoding
        }
}

# Retrieves transport rules
Function Get-TransportRules {
    [OutputDir]
    [String] $OutputDir = ".",

    [Encoding]
    [String] $Encoding = "utf8"

    Get-TransportRules |
        ForEach-Object {
            $_
        }
}

# Execution begins here
Show-TransportRules
