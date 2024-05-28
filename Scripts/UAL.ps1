# Check if the file exists before loading the module
if (Test-Path -Path "$PSScriptRoot\Microsoft-Extractor-Suite.psm1") {
    # Load the module using the fully qualified path
    Import-Module -Name "$PSScriptRoot\Microsoft-Extractor-Suite.psm1"
} else {
    # Handle the error, e.g. by throwing an exception
    Write-Error "The module 'Microsoft-Extractor-Suite.psm1' could not be found in the path '$PSScriptRoot'."
    exit 1
}

