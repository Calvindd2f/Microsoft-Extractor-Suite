#read_only
#####################################################
##########  INPUT
#####################################################

$my_input = "";

#####################################################
##########  OUTPUT ##################################

$variableProps = @{my_output = $null;}

$outputProps = @{out = $(New-Object psobject - Property $variableProps);success = $false;}

$activityOutput = New-Object psobject -Property $outputProps;

#/read_only

# Set supported TLS methods
[Net.ServicePointManager]::SecurityProtocol = 'Tls12, Tls13'

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

$outputDir = 'Output'
if (!(Test-Path $outputDir))
{
	New-Item -ItemType Directory -Force -Name $Outputdir >$Null
}

$Global:retryCount = 0

Function StartDate
{
	if ([string]::IsNullOrWhiteSpace($startDate))
 {
		#Commit 1. The compairson was driving me nuts when there is method for the check
		$script:StartDate = [datetime]::Now.ToUniversalTime().AddDays(-90)
		write-LogFile -Message "[INFO] No start date provived by user setting the start date to: $($script:StartDate.ToString('yyyy-MM-ddTHH:mm:ssK'))" -Color 'Yellow'
	}
	else
	{
		$script:startDate = $startDate -as [datetime]
		if (!$script:startDate )
		{
			write-LogFile -Message '[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD' -Color 'Red'
		}
	}
}
Function StartDateAz
{
	if ([string]::IsNullOrWhiteSpace($startDate))
 {
		#Commit 1. The compairson was driving me nuts when there is method for the check
		$script:StartDate = [datetime]::Now.ToUniversalTime().AddDays(-30)
		write-LogFile -Message "[INFO] No start date provived by user setting the start date to: $($script:StartDate.ToString('yyyy-MM-ddTHH:mm:ssK'))" -Color 'Yellow'
	}
	else
	{
		$script:startDate = $startDate -as [datetime]
		if (!$script:startDate )
		{
			write-LogFile -Message '[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD' -Color 'Red'
		}
	}
}
function EndDate
{
	if ([string]::IsNullOrWhiteSpace($endDate))
 {
		#Commit 1. The compairson was driving me nuts when there is method for the check
		$script:EndDate = [datetime]::Now.ToUniversalTime()
		write-LogFile -Message "[INFO] No end date provived by user setting the end date to: $($script:EndDate.ToString('yyyy-MM-ddTHH:mm:ssK'))" -Color 'Yellow'
	}

	else
	{
		$script:endDate = $endDate -as [datetime]
		if (!$endDate)
		{
			write-LogFile -Message '[WARNING] Not A valid end date and time, make sure to use YYYY-MM-DD' -Color 'Red'
		}
	}
}
function EndDateAz
{
	if ([string]::IsNullOrWhiteSpace($endDate))
 {
		#Commit 1. The compairson was driving me nuts when there is method for the check
		$script:EndDate = [datetime]::Now.ToUniversalTime()
		write-LogFile -Message "[INFO] No end date provived by user setting the end date to: $($script:EndDate.ToString('yyyy-MM-ddTHH:mm:ssK'))" -Color 'Yellow'
	}

	else
	{
		$script:endDate = $endDate -as [datetime]
		if (!$endDate)
		{
			write-LogFile -Message '[WARNING] Not A valid end date and time, make sure to use YYYY-MM-DD' -Color 'Red'
		}
	}
}


function Write-LogFile([string]$message, [string]$color, [string]$logFile = 'Output\LogFile.txt')
{
	switch ($color)
	{
		'Yellow'
		{
			[console]::ForegroundColor = 'Yellow' 	# Warning / Verbose / Debug
			[console]::writefile("[WARNING] $message")
			[console]::ForegroundColor = 'White'
		}
		'Red'
		{
			[console]::ForegroundColor = 'Red' 		# Error
			[console]::writefile("[ERR] $message")
			[console]::ForegroundColor = 'White'
		}
		'Green'
		{
			[console]::ForegroundColor = 'Green' 	# Success
			[console]::writefile("[SUCCESS] $message")
			[console]::ForegroundColor = 'White'
		}
		default
		{
			[console]::writefile("[INFO] $message")
		} 											# Generic Output
	}

	try
	{
		$logToWrite = [DateTime]::Now.ToString() + ': ' + $message
		[System.IO.StreamWriter]::Synchronized([System.IO.File]::AppendText($logFile)).WriteLine($logToWrite)
	}
	catch
	{
		# Handle exception
	}
}

function Write-Log
{
	param (
		[Parameter(Mandatory = $True, Position = 0, HelpMessage = 'Log entry')]
		[ValidateNotNullOrEmpty()]
		[String]$Entry,

		[Parameter(Position = 1, HelpMessage = 'Log file to write into')]
		[ValidateNotNullOrEmpty()]
		[Alias('SS')]
		[IO.FileInfo]$LogFile = 'Output\LogFile.txt',

		[Parameter(Position = 3, HelpMessage = 'Level')]
		[ValidateNotNullOrEmpty()]
		[String]$Level = ('Info', 'Error', 'Process', 'Note', 'Warning')
	)

	# Indicator
	$Indicator = '[+]'
	if ( $Level -eq 'Warning' -or '[WARNING]' )
	{
		$Indicator = '[!]'
	}
 elseif ( $Level -eq 'Error' -or '[ERR]' )
	{
		$Indicator = '[E]'
	}
 elseif ( $Level -eq 'Process' -or '[SUCCESS]' )
	{
		$Indicator = '[.]'
	}
 elseif ($Level -eq 'Note' -or 'Info' )
	{
		$Indicator = '[i]'
	}

	# Output Pipe
	if ( $Level -eq 'Warning' -or '[WARNING]')
	{
		[console]::ForegroundColor = 'Yellow'
		[console]::writefile("$($Indicator) $($Entry)")
	}
 elseif ( $Level -eq 'Error' -or '[ERR]'  )
	{
		[console]::ForegroundColor = 'Red'
		[console]::writefile("$($Indicator) $($Entry)")
	}
 elseif ( $Level -eq 'Note' -or 'Info' )
	{
		[console]::ForegroundColor = 'White'
		[console]::writefile("$($Indicator) $($Entry)")
	}
 elseif ( $Level -eq '[SUCCESS]')
	{
		[console]::ForegroundColor = 'Green'
		[console]::writefile("$($Indicator) $($Entry)")
	}
 else
	{
		[console]::ForegroundColor = 'White'
		[console]::writefile("$($Indicator) $($Entry)")
	}

	# Log File
	if ( $global:NoLog -eq $False )
	{
		"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') : $Entry" | Out-File -FilePath $LogFile -Append
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

##########################################################################
# PR Functions

Filter Assert-FileEncoding
{
	<#
    .Description
    This function returns encoding type for setting content.
    .Functionality
    Internal
    #>
	$PSVersion = $PSVersionTable.PSVersion

	$Encoding = 'utf8'

	if ($PSVersion -ge '6.0')
	{
		$Encoding = 'utf8NoBom'
	}

	return $Encoding
}
Filter Assert-UserIds ([Parameter(Mandatory, ValueFromPipeline)][string]$UserIds)
{
	if ([string]::IsNullOrEmpty($UserIds))
 {
		$UserIds = '*'
	}
	return $UserIds
}
Filter Assert-OutputDir ([Parameter(Mandatory, ValueFromPipeline)][string]$OutputDir = 'Output', [string]$fileName)
{
	$outputDir = if ([string]::IsNullOrEmpty($OutputDir)) { $OutputDir = 'Output' }
	if (!(Test-Path $outputDir))
	{
		New-Item -ItemType Directory -Force -Name $outputDir > $null
	}
	if (![string]::IsNullOrEmpty($fileName))
	{
		if (!(Test-Path $outputDir\$fileName))
		{
			New-Item -ItemType File -Force -Name "$outputDir\$fileName" > $null
		}
		$output = "$outputDir\$fileName"
	}
	return $output
}
# Main assertion function
function Assertion
{
	param (
		[bool]$Output,
		[bool]$Encoding,
		[bool]$UserIds,
		[bool]$Interval,
		[string]$OutputFileName
	)

	if ($Output)
	{
		$outputDir = Assert-OutputDir -fileName $OutputFileName
	}

	if ($Encoding)
	{
		$encoding = Assert-Encoding -Encoding $Encoding
	}

	if ($UserIds)
	{
		$userIds = Assert-UserIds -UserIds $UserIds
	}

}
# Example in each .ps1 file instead of the manual isnullorempty / isnullorwhitespace assertions
Assertion -Output $true -Encoding $true -UserIds $true -Interval $true -OutputFileName 'OutputFileName.txt'





##########################################################################
# PR Assertions
# Filters to assert and set default values for various parameters

function Assertion
{
	param (
		[Parameter(Mandatory = $false)] [bool] $Output = $false,
		[Parameter(Mandatory = $false)] [bool] $Encoding = $false,
		[Parameter(Mandatory = $false)] [bool] $UserIds = $false,
		[Parameter(Mandatory = $false)] [bool] $Interval = $false,
		[Parameter(Mandatory = $false)] [string] $OutputFileName = '',
		[Parameter(Mandatory = $false)] [string] $Command = ''
	)

	if ($Output)
	{
		$OutputDir = Assert-OutputDir -fileName $OutputFileName
	}

	if ($Encoding)
	{
		$Encoding = Assert-Encoding
	}

	if ($UserIds)
	{
		$UserIds = Assert-UserIds
	}

	if ($Interval)
	{
		$Interval = Assert-Interval
	}

	if ($Command)
	{
		Assert-Connection -Cmdlet $Command
	}
}
Assertion -Output $true -Encoding $true -UserIds $true -Interval $true -OutputFileName 'OutputFileName.txt'

function Set-OutputEncoding {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        # For PowerShell versions less than 6, set to UTF8
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    } else {
        # For PowerShell 6 and above, set to UTF8 without BOM
        [System.Text.Encoding]::UTF8NoBOM = New-Object System.Text.UTF8Encoding($false)
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8NoBOM
    }
}

Export-ModuleMember -Function * -Alias * -Variable * -Cmdlet *
