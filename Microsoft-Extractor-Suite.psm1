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
      Add-Content -Path "Log.log" -Value "$logtime $line"
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
    
    write-LogFilew -Message $message -Color $color
    return @(($Global:StartDate).ToString('yyyy-MM-ddTHH:mm:ssK'),)
}
function EndDate
{
    if ([string]::IsNullOrWhiteSpace($endDate))
    {
        $script:EndDate = [datetime]::UtcNow
        $message = "[INFO] No end date provided by user; setting the end date to: $($script:EndDate.ToString('yyyy-MM-ddTHH:mm:ssK'))"
        $color = 'Yellow'
    }
    else
    {
        if (-not ($endDate -as [datetime]))
        {
            $message = '[WARNING] Not a valid end date and time; make sure to use YYYY-MM-DD'
            $color = 'Red'
        }
        else
        {
            $script:EndDate = $endDate
            return
        }
    }
    write-LogFile -Message $message -Color $color
    $Global:EndDate = $endDate
    return $Global:EndDate;
}
Function logtime
{
        [string]$logtime = $((Get-Date -Format '[yyyy-MM-dd HH:mm:ssK] |').ToString())
    #yyyy-MM-ddTHH:mm:ssK
    #(get-date).GetDateTimeFormats()
    #2022-07-14T12:30:00Z should be used for filter queries.
    # $logtime should be used for messages
}

function Write-LogFile([string]$message, [string]$severity, [string]$logFile = 'Output\LogFile.txt') {
        $logEntry = [string]$logtime + $severity.ToUpper() + ' ' + $message
    try {
        [System.IO.File]::AppendAllText($logFile, $logEntry + [Environment]::NewLine)
    } catch {
        # exception
    }
    
    $foregroundColor = switch ($severity) {
        'WARNING'  { 'Yellow' }
        'W'        { 'Yellow' }
        '?'        { 'Yellow' }
        'ERROR'    { 'Red' }
        'E'        { 'Red' }
        '!'        { 'Red' }
        'SUCCESS'  { 'Green' }
        'S'        { 'Green' }
        '+'        { 'Green' }
        Default    { 'White' }
    }

    [console]::ForegroundColor = $foregroundColor
    [console]::WriteLine($logEntry)
    [console]::ResetColor()
}
function Write-Log {
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'Log entry')]
        [ValidateNotNullOrEmpty()]
        [string]$Entry,

        [Parameter(Position = 1, HelpMessage = 'Log file to write into')]
        [ValidateNotNullOrEmpty()]
        [Alias('LogFile')]
        [string]$Logs = 'Output\Log.txt',

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
            [System.IO.File]::AppendAllText($Log, (Get-Date -Format 'Export-ModuleMember -Function StartDate, EndDate') + ' ' + $message + [Environment]::NewLine)
        } catch {
            # Handle exception
        }
    }
}

function Get-ModuleVersion
{
	# Return the already computed version info if available.
	if (![string]::IsNullOrWhiteSpace($script:ModuleVersion))
	{
		Write-Verbose "Returning precomputed version info: $script:ModuleVersion"
		return $script:ModuleVersion
	}

	$extModule = Get-Module Microsoft-Extractor-Suite

	# Check for ExchangeOnlineManagementBeta in case the psm1 is loaded directly
	if ($null -eq $extModule)
	{
		$extModule = (Get-Command -Name Microsoft-Extractor-Suite).Module
	}

	# Get the module version from the loaded module info.
	$script:ModuleVersion = $extModule.Version.ToString()

	# Look for prerelease information from the corresponding module manifest.
	$extModuleRoot = (Get-Item $extModule.Path).Directory.Parent.FullName

	$extModuleManifestPath = Join-Path -Path $extModuleRoot -ChildPath Microsoft-Extractor-Suite.psd1
	$isextModuleManifestPathValid = Test-Path -Path $extModuleManifestPath
	if ($isextModuleManifestPathValid -ne $true)
	{
		# Could be a local debug build import for testing. Skip extracting prerelease info for those.
		Write-Verbose "Module manifest path invalid, path: $extModuleManifestPath, skipping extracting prerelease info"
		return $script:ModuleVersion
	}

	$extModuleManifestContent = Get-Content -Path $extModuleManifestPath
	$preReleaseInfo = $extModuleManifestContent -match "Prerelease = '(.*)'"
	if ($null -ne $preReleaseInfo)
	{
		$script:ModuleVersion = '{0}-{1}' -f $extModule.Version.ToString(), $preReleaseInfo[0].Split('=')[1].Trim().Trim("'")
	}

	Write-Verbose "Computed version info: $script:ModuleVersion"
	return $script:ModuleVersion
}
Get-ModuleVersion

function Set-OutputEncoding 
{
    if ($PSVersionTable.PSVersion.Major -lt 6) 
    {
        # For PowerShell versions less than 6, set to UTF8
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    } 
    else 
    {
        # For PowerShell 6 and above, set to UTF8 without BOM
        [System.Text.Encoding]::UTF8NoBOM = New-Object System.Text.UTF8Encoding($false)
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8NoBOM
    }
}
function Merge-OutputFiles
{
    param(
        [string]$OutputDir,
        [string]$Encoding,
        [string]$mergedFile
    )
    
    $mergedFilePath = Join-Path -Path $OutputDir -ChildPath $mergedFile
    
    $allLogs = Get-ChildItem -Path $OutputDir -Filter '*.json' | ForEach-Object {
        $content = [System.IO.File]::ReadAllText($_.FullName)
        [System.Text.Json.JsonSerializer]::Deserialize($content, [object].GetType())
    }
    
    $jsonOutput = [System.Text.Json.JsonSerializer]::Serialize($allLogs, [object].GetType(), [System.Text.Json.JsonSerializer]::GetOptions())
    [System.IO.File]::WriteAllText($mergedFilePath, $jsonOutput, [System.Text.Encoding]::$Encoding)
    
    [console]::WriteLine("[INFO] All logs merged into $mergedFilePath")
}
Function Set-OutputFormat([alias]$format)
{
    'JSON'
    'HASHTABLE'
    ;

        => $PSBoundParameters['format']
}
##########################################################################

function Assert-GlobalVariables {
    param (
        [string]$OutputDir,
        [string]$FileEncoding,
        [int[]]$UserIds
    )

    if (-not [System.IO.Directory]::Exists($OutputDir)) {
        [console]::WriteLine( "Output directory does not exist, creating: $OutputDir")>>null
        [void](New-Item -ItemType Directory -Path $OutputDir -Force >>null)
    } else {
        [void]([console]::WriteLine( "Output directory already exists: $OutputDir")  >>null)
    }

    if ($null -eq $FileEncoding -or $FileEncoding.Trim() -eq '') {
        Set-OutputEncoding >> null
    }

    if ($null -eq $UserIds -or $UserIds.Count -eq 0) {
        $UserIds >>null
    }

    # Additional checks can be added here if needed
}






Export-ModuleMember -Function * -Alias * -Variable * -Cmdlet *
