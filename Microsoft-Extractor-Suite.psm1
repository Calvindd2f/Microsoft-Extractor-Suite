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

Function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'Log entry')]
        [ValidateNotNullOrEmpty()]
        [string]$Entry,

        [Parameter(Position = 1, HelpMessage = 'Log file to write into')]
        [ValidateNotNullOrEmpty()]
        [Alias('LogFile')]
        [string]$LogFile = 'Output\Log.txt',

        [Parameter(Position = 2, HelpMessage = 'Level')]
        [ValidateSet('Info', 'Error', 'Process', 'Note', 'Warning')]
        [string]$Level = 'Info'
    )

    $Indicator = switch ($Level) {
        'Warning' { 'Warning' }
        'Error'   { 'Error' }
        'Process' { 'Process' }
        'Note'    { 'Note' }
        default   { 'Info' }
    }

    $foregroundColor = switch ($Level) {
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Note'    { 'White' }
        'Process' { 'Green' }
        default   { 'White' }
    }

    $message = "$Indicator : $Entry"
    [console]::ForegroundColor = $foregroundColor
    [console]::WriteLine($message)
    [console]::ForegroundColor = 'White'

    if (-not $global:NoLog) {
        try {
            [System.IO.File]::AppendAllText($Log, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') + ' ' + $message + [Environment]::NewLine)
        } catch {
            # Handle exception
        }
    }
}

# ... (rest of the functions)

# Invoke functions and other code here

Export-ModuleMember -Function * -Alias * -Variable * -Cmdlet *
