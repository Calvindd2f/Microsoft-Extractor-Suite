# Set supported TLS methods
[Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls13"

$manifest = Import-PowerShellDataFile "$PSScriptRoot\Microsoft-Extractor-Suite.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle = "Microsoft-Extractor-Suite $version"

$logo=@"
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+
 |M|i|c|r|o|s|o|f|t| |E|x|t|r|a|c|t|o|r| |S|u|i|t|e|
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+
Copyright 2024 Invictus Incident Response
Created by Joey Rentenaar & Korstiaan Stam
"@

Write-Host $logo -ForegroundColor Yellow

$outputDir = "Output"
if (!(test-path $outputDir)) {
	New-Item -ItemType Directory -Force -Name $Outputdir > $null
}

$retryCount = 0

Function StartDate
{
	if ([string]::IsNullOrEmpty($startDate)) {
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
    if ([string]::IsNullOrEmpty($startDate)) {
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
    if ([string]::IsNullOrEmpty($endDate)) {
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
		New-Item -ItemType Directory -Force -Name $Outputdir > $null
	}

	switch ($color) {
        "Yellow" { [Console]::ForegroundColor = [ConsoleColor]::Yellow }
        "Red" 	 { [Console]::ForegroundColor = [ConsoleColor]::Red }
        "Green"  { [Console]::ForegroundColor = [ConsoleColor]::Green }
        default  { [Console]::ResetColor() }
    }

    [Console]::WriteLine($message)
    [Console]::ResetColor()
    $logToWrite = [DateTime]::Now.ToString() + ": " + $message
    $logToWrite | Out-File -FilePath $LogFile -Append
}

function versionCheck{
	$moduleName = "Microsoft-Extractor-Suite"
	$currentVersionString = $version

	$currentVersion = [Version]$currentVersionString
    $latestVersionString = (Find-Module -Name $moduleName).Version.ToString()
    $latestVersion = [Version]$latestVersionString


	$latestVersion = (Find-Module -Name $moduleName).Version.ToString()

	if ($currentVersion -lt $latestVersion) {
		write-LogFile -Message "`n[INFO] You are running an outdated version ($currentVersion) of $moduleName. The latest version is ($latestVersion), please update to the latest version." -Color "Yellow"
	}
}

function Get-GraphAuthType {
    param (
        [string[]]$RequiredScopes
    )

    $context = Get-MgContext
    if (-not $context) {
        $authType = "none"
        $scopes = @()
    } else {
        $authType = $context | Select-Object -ExpandProperty AuthType
        $scopes = $context | Select-Object -ExpandProperty Scopes
    }

    $missingScopes = @()
    foreach ($requiredScope in $RequiredScopes) {
        if (-not ($scopes -contains $requiredScope)) {
            $missingScopes += $requiredScope
        }
    }

    $joinedScopes = $RequiredScopes -join ","
    switch ($authType) {
        "delegated" {
            if ($RequiredScopes -contains "Mail.ReadWrite") {
                Write-LogFile -Message "[WARNING] 'Mail.ReadWrite' is being requested under a delegated authentication type. 'Mail.ReadWrite' permissions only work when authenticating with an application." -Color "Yellow"
            }
            elseif ($missingScopes.Count -gt 0) {
                foreach ($missingScope in $missingScopes) {
                    Write-LogFile -Message "[INFO] Missing Graph scope detected: $missingScope" -Color "Yellow"
                }

                Write-LogFile -Message "[INFO] Attempting to re-authenticate with the appropriate scope(s): $joinedScopes" -Color "Green"
                Connect-MgGraph -NoWelcome -Scopes $joinedScopes > $null
            }
        }
        "AppOnly" {
            if ($missingScopes.Count -gt 0) {
                foreach ($missingScope in $missingScopes) {
                    Write-LogFile -Message "[INFO] The connected application is missing Graph scope detected: $missingScope" -Color "Red"
                }
            }
        }
        "none" {
            if ($RequiredScopes -contains "Mail.ReadWrite") {
                Write-LogFile -Message "[WARNING] 'Mail.ReadWrite' is being requested under a delegated authentication type. 'Mail.ReadWrite' permissions only work when authenticating with an application." -Color "Yellow"
            }
            else {
                Write-LogFile -Message "[INFO] No active Connect-MgGraph session found. Attempting to connect with the appropriate scope(s): $joinedScopes" -Color "Green"
                Connect-MgGraph -NoWelcome -Scopes $joinedScopes
            }
        }
    }

    return @{
        AuthType = $authType
        Scopes = $scopes
        MissingScopes = $missingScopes
    }
}

function Set-FileEncoding
{
    <#
    .Description
    This function returns encoding type for setting content.
    #>
    $PSVersion = $PSVersionTable.PSVersion

    $Encoding = 'utf8'

    if ($PSVersion -ge '6.0')
    {
        $Encoding = 'utf8NoBom'
    }

    return $Encoding
}


function Merge-OutputFiles
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDir,

        [Parameter(Mandatory)]
        [ValidateSet('CSV', 'JSON')]
        [string]$OutputType,

        [string]$MergedFileName,

        [int]$BatchSize = 1000,

        [switch]$UseParallel
    )

    begin
    {
        $outputDirMerged = Join-Path -Path $OutputDir -ChildPath "Merged"
        if (!(Test-Path $outputDirMerged))
        {
            Write-LogFile "Creating directory: $outputDirMerged"
            $null = New-Item -ItemType Directory -Force -Path $outputDirMerged
        }

        if (-not $MergedFileName)
        {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $MergedFileName = "merged_$timestamp.$($OutputType.ToLower())"
        }

        $mergedPath = Join-Path -Path $outputDirMerged -ChildPath $MergedFileName
    }

    process
    {
        try
        {
            switch ($OutputType)
            {
                'CSV'
                {
                    $writer = [System.IO.StreamWriter]::new($mergedPath, $false, [System.Text.Encoding]::UTF8)
                    $isHeaderWritten = $false

                    $csvFiles = Get-ChildItem $OutputDir -Filter "*.csv"

                    if ($UseParallel)
                    {
                        $csvData = $csvFiles | ForEach-Object -ThrottleLimit 5 -Parallel {
                            Import-Csv -Path $_.FullName
                        }
                    }
                    else
                    {
                        $csvData = $csvFiles | ForEach-Object { Import-Csv -Path $_.FullName }
                    }

                    $batch = @()
                    foreach ($record in $csvData)
                    {
                        if (-not $isHeaderWritten)
                        {
                            $header = $record.PSObject.Properties.Name -join ','
                            $writer.WriteLine($header)
                            $isHeaderWritten = $true
                        }

                        $batch += $record
                        if ($batch.Count -ge $BatchSize)
                        {
                            $batch | ForEach-Object {
                                $line = $_.PSObject.Properties.Value -join ','
                                $writer.WriteLine($line)
                            }
                            $batch = @()
                        }
                    }

                    if ($batch.Count -gt 0)
                    {
                        $batch | ForEach-Object {
                            $line = $_.PSObject.Properties.Value -join ','
                            $writer.WriteLine($line)
                        }
                    }

                    Write-LogFile "CSV files merged into $mergedPath"
                }

                'JSON'
                {
                    $jsonFiles = Get-ChildItem $OutputDir -Filter "*.json"
                    $allJsonObjects = [System.Collections.Generic.List[object]]::new()

                    if ($UseParallel)
                    {
                        $jsonData = $jsonFiles | ForEach-Object -ThrottleLimit 5 -Parallel {
                            $content = Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
                            if ($content -is [array]) { return $content }
                            return @($content)
                        }
                        $allJsonObjects.AddRange($jsonData)
                    }
                    else
                    {
                        foreach ($file in $jsonFiles)
                        {
                            $jsonContent = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
                            if ($jsonContent -is [array])
                            {
                                $allJsonObjects.AddRange($jsonContent)
                            }
                            else
                            {
                                $allJsonObjects.Add($jsonContent)
                            }
                        }
                    }

                    $writer = [System.IO.StreamWriter]::new($mergedPath, $false, [System.Text.Encoding]::UTF8)
                    $jsonString = $allJsonObjects | ConvertTo-Json -Depth 100 -Compress
                    $writer.Write($jsonString)

                    Write-LogFile "JSON files merged into $mergedPath"
                }
            }
        }
        catch
        {
            Write-LogFile "Error processing files: $_" -Level 'ERROR'
            throw
        }
        finally
        {
            if ($writer)
            {
                $writer.Dispose()
            }
        }
    }
}

versionCheck

Export-ModuleMember -Function * -Alias * -Variable * -Cmdlet *
