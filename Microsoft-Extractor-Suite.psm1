Set-StrictMode -Version Latest

# Set supported TLS methods
[Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls13" # -bxor 3072,12288

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

$outputDir = "$PSScriptRoot\Output"
$logFile = "$outputDir\LogFile.txt"
$retryCount = 0 
enum logctx
{ 
    NULL
    INFO
    WARNING
    ERROR
    DEBUG 
}
Function StartDate([int]$Days)
{
    if ([string]::IsNullOrEmpty($StartDate))
    { $StartDate = (Get-Date $StartDate -format 'yyyy-MM-ddTHH:mm:ss').AddDays(-$Days) }
    if ($Days) 
    { Log "`$StartDate has been set to $StartDate . That is $Days ago." -sev 1 }
    else
    { Log "`$StartDate has been set to $StartDate. Default -90 Days from today." -sev 1 }
}
function EndDate
{
    if ([string]::IsNullOrEmpty($EndDate))
    {
        $endDate = [datetime]::Now.ToString('yyyy-MM-ddTHH:mm:ss')
    }
    Log "`$EndDate has been set to $endDate" -sev 1
}
Function Log([string]$log, [bool]$show, [int]$sev)
{
    $show = $true
    if ([int]$sev)
    { $s = [logctx].GetEnumNames()[$sev] }
    [string]$logtime = $((Get-Date -Format "[yyyy-mm-dd HH:mm:ss]:[$s] |").ToString())
    foreach ($line in $($log -split "`n"))
    {
        if ($VerbosePreference -eq 'Continue' -or $show -eq $true) { [console]::WriteLine("$logtime $line") }
        #Add-Content -Path "C:\Windows\Temp\agent.log" -Value "$logtime $line"
        # Append log entry to the log file using StreamWriter
        $logFile = "C:\Windows\Temp\agent.log"
        $logEntry = "$logtime $line"
        $StreamWriter = New-Object System.IO.StreamWriter($logFile, $true)
        try
        {
            $StreamWriter.WriteLine($logEntry)
        }
        catch
        {
            [console]::WriteLine("1/2 | Error writing to log file.");
            [console]::WriteLine("1/2 | Creating the log file then retrying.");
            if ([string]::IsNullOrEmpty($logFile))
            {
                New-Item -ItemType File -Name activity.log > $null
            }

            try
            {
                $StreamWriter.WriteLine($logEntry)
            }
            catch
            {
                [console]::WriteLine("2/2 | Error writing to log file");
                throw [System.Exception]::new().Message('Critical Exception Thrown.')
                [exit]0
            }
            finally
            {
                $StreamWriter.Close()
            }
        }
        finally
        {
            $StreamWriter.Close()
        }
    }
}

function Write-LogFile([String]$message, $color)
{
    if (!(test-path $outputDir))
    {
        New-Item -ItemType Directory -Force -Name $Outputdir > $Null;
        New-Item -ItemType File 	 -Force -Name $logFile > $Null;
    }

    switch ($color)
    {
        "Yellow"
        {
            [console]::ForegroundColor = 'Yellow'
            #$sevUnicode = [char]::ConvertFromUtf32(0x26A0) # ⚠
            #$sevText = "[!]"
        }
        "Red"
        {
            [console]::ForegroundColor = "Red"
            #$sevUnicode = [char]::ConvertFromUtf32(0x274C) # ❌
            #$sevText = "[?]"
        }
        "Green"
        {
            [console]::ForegroundColor = "Green"
            #$sevUnicode = [char]::ConvertFromUtf32(0x2705) # ✅
            #$sevText = "[✓]"
        }
        default
        {
            [console]::ForegroundColor = "White"
            #$sevUnicode = ""
            #$sevText = ""
        }
    }
    # Write to console with Unicode emoji
    [console]::WriteLine($logTime + ' ' + $message)
    [console]::ResetColor()
    # Write to file with text equivalents
    $logEntry = [String]::Format("{0} {1} {2}", $logTime, $sevText, $message)
    [System.IO.File]::AppendAllText($logFile, $logEntry + [Environment]::NewLine)
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
    # Check for Microsoft-Extractor-Suite in case the psm1 is loaded directly
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
    
##########################################
# This part is for managing importing all the functions during execution / passing functions and variables.

#$internal_modules=@();
#$internal_modules.ForEach({ Import-Module ("{0}{1}{2}" -f $PSScriptRoot, [System.IO.Path]::DirectorySeparatorChar, $_.ToString()) -Force })

#$msal_modules=@();
#$msal_modules.ForEach({ Import-Module ("{0}{1}{2}" -f $PSScriptRoot, [System.IO.Path]::DirectorySeparatorChar, $_.ToString()) -Scope Global -Force })
New-Variable -Name ScriptPath -Value $PSScriptRoot -Scope Script -Force

$cmds = [System.IO.Directory]::EnumerateFiles(("{0}/scripts/" -f $PSScriptRoot), "*.ps1", "AllDirectories")

$p = @{
    ImportModules   = ("{0}/scripts/" -f $PSScriptRoot);
    ImportCommands  = $cmds;
    ImportVariables = @{"ScriptPath" = $PSScriptRoot };
}

$internal_functions = @();
$all_files = $internal_functions.ForEach({
        if ([System.IO.Directory]::Exists(("{0}{1}" -f $PSScriptRoot, $_)))
        {
            [System.IO.Directory]::EnumerateFiles(("{0}{1}" -f $PSScriptRoot, $_), "*.ps1", [System.IO.SearchOption]::AllDirectories)
        }
    })
$all_files = $all_files.Where({ $_.EndsWith('ps1') })
$all_files.ForEach({ . $_ })
