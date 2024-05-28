# Set supported TLS methods
Add-Type -TypeDefinition @"
    using System.Net;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(ServicePoint sPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

# Enable TLS, TLS1.1, TLS1.2, TLS1.3 in this session if they are available
$tlsProtocols = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13
foreach ($protocol in $tlsProtocols) {
    if ($protocol -in [Net.ServicePointManager]::SecurityProtocol) {
        continue
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $protocol
}

function Write-Log([string]$log, [switch]$show) {
    [string]$logtime = $((Get-Date -Format "[dd/MM/yyyy HH:mm:ss zz] |").ToString())
    foreach ($line in $($log -split "`n")) {
        if ($VerbosePreference -eq 'Continue' -or $show -eq $true) {
            [console]::WriteLine("$logtime $line")
        }
        if (-not (Test-Path "Log.log")) {
            New-Item -ItemType File -Path "Log.log"
        }
        try {
            Add-Content -Path "Log.log" -Value "$logtime $line" -ErrorAction Stop
        } catch {
            Write-Error "Failed to write to log file: $_"
        }
    }
}

$manifestPath = Join-Path $PSScriptRoot "Microsoft-Extractor-Suite.psd1"
if (-not (Test-Path $manifestPath)) {
    Write-Error "PowerShell data file not found: $manifestPath"
    return
}

$manifest = Import-PowerShellDataFile $manifestPath
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle = "Microsoft-Extractor-Suite $version"

$logoPath = Join-Path $PSScriptRoot "logo.txt"
if (-not (Test-Path $logoPath)) {
    Write-Error "Logo file not found: $logoPath"
    return
}

$logo = Get-Content $logoPath
[console]::ForegroundColor = 'Yellow'
[console]::WriteLine("$logo")
[console]::ForegroundColor = 'White'

$Parameters = @{
    OutputDir = $global:OutputDir
}

if (-not $Parameters.OutputDir) {
    $Parameters.OutputDir = Get-Item -Path $PSScriptRoot
}

if (-not (Test-Path $Parameters.OutputDir)) {
    Write-Error "Output directory not found: $($Parameters.OutputDir)"
    return
}

Assert-GlobalVariables @Parameters

$Global:retryCount = 0

function StartDate() {
    if ([string]::IsNullOrWhiteSpace($startDate)) {
        $daysToAdd = -90
        $message = "[INFO] No start date provided by user setting the start date to: {0}" -f ([datetime]::Now.ToUniversalTime().AddDays($daysToAdd).ToString('yyyy-MM-ddTHH:mm:ssK'))
        $color = 'Yellow'
    } else {
        $daysToAdd = -30
        $message = "[INFO] No start date provided by user setting the start date to: {0}" -f ($startDate -as [datetime]).ToString('yyyy-MM-ddTHH:mm:ssK')
        $color = 'Yellow'
    }

    $Global:StartDate = [datetime]::Now.ToUniversalTime().AddDays($daysToAdd)

    Write-Log -log $message -show
    return @(($Global:StartDate)
