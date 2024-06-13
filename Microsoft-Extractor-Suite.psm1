# Set supported TLS methods
[Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls13"

$manifest = Import-PowerShellDataFile "$PSScriptRoot\Microsoft-Extractor-Suite.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle="Microsoft-Extractor-Suite $version"

$logo=@"

 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+
 |M|i|c|r|o|s|o|f|t| |E|x|t|r|a|c|t|o|r| |S|u|i|t|e|
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+                                                                                                                                                                     
Copyright (c) 2024 Invictus Incident Response
Created by Joey Rentenaar & Korstiaan Stam
"@

Write-Host $logo -ForegroundColor Yellow

$outputDir = "Output"
if (!(test-path $outputDir)) {
	New-Item -ItemType Directory -Force -Name $Outputdir | Out-Null
}

$retryCount = 0 
	
Function StartDate
{
	if (($startDate -eq "") -Or ($null -eq $startDate)) {
		$script:StartDate = [datetime]::Now.ToUniversalTime().AddDays(-90)
		write-LogFile -Message "[INFO] No start date provived by user setting the start date to: $($script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
	}
	else
	{
		$script:startDate = $startDate -as [datetime]
		if (!$script:startDate ) { 
			write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"
		} 
	}
}

Function StartDateAz
{
	if (($startDate -eq "") -Or ($null -eq $startDate)) {
		$script:StartDate = [datetime]::Now.ToUniversalTime().AddDays(-30)
		write-LogFile -Message "[INFO] No start date provived by user setting the start date to: $($script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
	}
	else
	{
		$script:startDate = $startDate -as [datetime]
		if (!$script:startDate ) { 
			write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"
		} 
	}
}

function EndDate
{
	if (($endDate -eq "") -Or ($null -eq $endDate)) {
		$script:EndDate = [datetime]::Now.ToUniversalTime()
		write-LogFile -Message "[INFO] No end date provived by user setting the end date to: $($script:EndDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
	}

	else {
		$script:endDate = $endDate -as [datetime]
		if (!$endDate) { 
			write-LogFile -Message "[WARNING] Not A valid end date and time, make sure to use YYYY-MM-DD" -Color "Red"
		} 
	}
}

$logFile = "Output\LogFile.txt"
function Write-LogFile([String]$message,$color)
{
	$outputDir = "Output"
	if (!(test-path $outputDir)) {
		New-Item -ItemType Directory -Force -Name $Outputdir | Out-Null
	}
	if ($color -eq "Yellow")
	{
		Write-host $message -ForegroundColor Yellow
	}
	elseif ($color -eq "Red")
	{
		Write-host $message -ForegroundColor Red
	}
	elseif ($color -eq "Green")
	{
		Write-host $message -ForegroundColor Green
	}
	else {
		Write-host $message
	}
	
	$logToWrite = [DateTime]::Now.ToString() + ": " + $message
	$logToWrite | Out-File $LogFile -Append
}

function versionCheck{
	$moduleName = "Microsoft-Extractor-Suite"
	$currentVersionString  = $version

	$currentVersion = [Version]$currentVersionString
    $latestVersionString = (Find-Module -Name $moduleName).Version.ToString()
    $latestVersion = [Version]$latestVersionString


	$latestVersion = (Find-Module -Name $moduleName).Version.ToString()

	if ($currentVersion -lt $latestVersion) {
		write-LogFile -Message "`n[INFO] You are running an outdated version ($currentVersion) of $moduleName. The latest version is ($latestVersion), please update to the latest version." -Color "Yellow"
	}
}

versionCheck
###########################################################################################

$EXORunspace=[PSCustomObject]@{
    EXOSession = $null
    Runspace = $null
    RunspaceName = $null
    RunspaceID = $null
    RunspaceParams = [PSCustomObject]@{
        #set the default connection limit
        [System.Net.ServicePointManager]::DefaultConnectionLimit = 1024;
        [System.Net.ServicePointManager]::MaxServicePoints       = 1000;
        #Set the maximum memory for the runspace
        MaxMemoryPerShellMB                                      = 1024;
        #Set the maximum number of objects for the runspace
        MaximumReceivedObjects                                   = 10000;
        #Set the maximum number of commands for the runspace
        MaximumReceivedCommand                                   = 1000;
        # Set the timeout for the runspace
        OpenTimeout = (New-TimeSpan -Minutes 10);
         # Set the timeout for the runspace
        CancellationTimeout                                      = (New-TimeSpan -Minutes 10);
        #Add Expiration time
        [NoteProperty]$ExpiresOn_ = ([System.DateTimeOffset]::Now.AddMinutes(60))
        #Add renewable option
        [NoteProperty]$renewable                                 = $true 
        #Add function to check for near expiration
        [ScriptMethod]$IsNearExpiry                              = { return (($this.ExpiresOn_.UtcDateTime.AddMinutes( - 5)) -le ((Get-Date).ToUniversalTime())) }
        #Add function to disable token renewal
        [ScriptMethod]$DisableRenew = { $this.renewable = $false }
}}
$EXOSession = $null

###########################################################################################
# This part is for managing importing all the functions during execution / passing functions and variables.

#$internal_modules=@();
#$internal_modules.ForEach({ Import-Module ("{0}{1}{2}" -f $PSScriptRoot, [System.IO.Path]::DirectorySeparatorChar, $_.ToString()) -Force })
#$msal_modules=@();
#$msal_modules.ForEach({ Import-Module ("{0}{1}{2}" -f $PSScriptRoot, [System.IO.Path]::DirectorySeparatorChar, $_.ToString()) -Scope Global -Force })
New-Variable -Name ScriptPath -Value $PSScriptRoot -Scope Script -Force

$cmds=[System.IO.Directory]::EnumerateFiles(("{0}/scripts/" -f $PSScriptRoot), "*.ps1", "AllDirectories")
$p=@{
    ImportModules   = ("{0}/scripts/" -f $PSScriptRoot);
    ImportCommands  = $cmds;
    ImportVariables = @{"ScriptPath" = $PSScriptRoot };
}

$internal_functions = @();
$all_files=$internal_functions.ForEach({
        if ([System.IO.Directory]::Exists(("{0}{1}" -f $PSScriptRoot, $_)))
        {
            [System.IO.Directory]::EnumerateFiles(("{0}{1}" -f $PSScriptRoot, $_), "*.ps1", [System.IO.SearchOption]::AllDirectories)
        }
    })
$all_files = $all_files.Where({ $_.EndsWith('ps1') })
$all_files.ForEach({ . $_ })
