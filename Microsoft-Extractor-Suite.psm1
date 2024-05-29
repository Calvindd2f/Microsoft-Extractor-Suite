# Set supported TLS methods
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
#Enable TLS, TLS1.1, TLS1.2, TLS1.3 in this session if they are available
IF ([Net.SecurityProtocolType]::Tls) { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls }
IF ([Net.SecurityProtocolType]::Tls11) { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls11 }
IF ([Net.SecurityProtocolType]::Tls12) { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 }
IF ([Net.SecurityProtocolType]::Tls13) { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13 }

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

    Function Global:StartDate
    {
        if ([string]::IsNullOrWhiteSpace($startDate))
        {
            # Dates
            $StartDate = ([datetime]::Now.AddDays(-30).ToString('s') + "Z")
            # Dates formatted for API query
            $StartDateSearch = $StartDate   #Write-Host ("{0} is not a valid date" -f $StartDate);Break
            # Message
            $message = "[INFO] No start date provided by user setting the start date to: {0}" -f $StartDate
            $color = "Yellow"

            write-LogFile -Message $message -Color $color

            $Global:StartDate
            return $Global:StartDate
        }
        else 
        {
            break
        }
    }
    Function Global:EndDate
    {
        if ([string]::IsNullOrWhiteSpace($endDate))
        {
            # Dates
            $endDate = ([datetime]::Now.ToString('s') + "Z")
            # Dates formatted for API query
            $endDateSearch = $endDate   #Write-Host ("{0} is not a valid date" -f $endDate);Break
            # Message
            $message = "[INFO] No end date provided by user setting the start date to: {0}" -f $endDate
            $color = "Yellow"
        
            write-LogFile -Message $message -Color $color
        
            $Global:endDate
            return $Global:endDate
        }
        else 
        {
            break
        }
    }

    function Global:Write-LogFile([String]$message, $color)
    {
        [string]$logFile = "$PSScriptRoot\log.txt"
        if (!(Test-Path $logFile)) { [void](New-Item -ItemType File -Path $logFile -Force) }
        [string]$logTime = (Get-Date -Format "[dd/MM/yyyy HH:mm:ss zz] |").ToString()

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
##########################################################################
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
    };Get-ModuleVersion


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

Export-ModuleMember -Function * -Alias * -Variable * -Cmdlet *
