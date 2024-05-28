# Set supported TLS methods
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
#Enable TLS, TLS1.1, TLS1.2, TLS1.3 in this session if they are available
IF([Net.SecurityProtocolType]::Tls) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls}
IF([Net.SecurityProtocolType]::Tls11) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls11}
IF([Net.SecurityProtocolType]::Tls12) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12}
IF([Net.SecurityProtocolType]::Tls13) {[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13}

Function Write-Log([string]$log,[switch]$show){
    [string]$logtime = $((Get-Date -Format "[dd/MM/yyyy HH:mm:ss zz] |").ToString())
    foreach($line in $($log -split "`n")){
        if($VerbosePreference -eq 'Continue' -or $show -eq $true){[console]::WriteLine( "$logtime $line"}
      if(-not (Test-Path "Log.log")){New-Item -ItemType File -Path "Log.log"}
      Add-Content -Path "Log.log" -Value "$logtime $line" -ErrorAction Stop
    }
}

$manifest = Import-PowerShellDataFile "$PSScriptRoot\Microsoft-Extractor-Suite.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle = "Microsoft-Extractor-Suite $version"

$logo = @'
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+
 |M|i|c|r|o|s|o|f|t| |E|x|t|r|a|c|t|o|r| |S|u|i|t|e|
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+
Copyright (c) 2024 Invictus Incident Response
Created by Joey Rentenaar & Korstiaan Stam
'@

[console]::ForegroundColor = 'Yellow'
[console]::WriteLine("$logo")
[console]::ForegroundColor = 'White'

$Parameters = @{
	OutputDir = $global:OutputDir
}
Assert-GlobalVariables @Parameters

$Global:retryCount = 0

Function StartDate
{
    if ([string]::IsNullOrWhiteSpace($startDate))
    {
        $daysToAdd = -90
        $message = "[INFO] No start date provided by user setting the start date to: {0}" -f ([datetime]::Now.ToUniversalTime().AddDays($daysToAdd).ToString('yyyy-MM-ddTHH:mm:ssK'))
        $color = 'Yellow'
    }
    else
    {
        $daysToAdd = -30
        $message = "[INFO] No start date provided by user setting the start date to: {0}" -f ($startDate -as [datetime]).ToString('yyyy-MM-ddTHH:mm:ssK')
        $color = 'Yellow'
    }
    
    $Global:StartDate = [datetime]::Now.ToUniversalTime().AddDays($daysToAdd)
    
    Write-Log -log $message -show
    return @(($
