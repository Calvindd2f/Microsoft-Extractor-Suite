param(
    [string]$header = "Default Header"
)

Import-Module "${PSScriptRoot}/bin/Debug/net7.0/PowerShellSample.dll" -Verbose

try {
    Write-Report -h $header
}
catch {
    Write-Error "Error. Exception: $_"
}

write-host "Script Complete"
