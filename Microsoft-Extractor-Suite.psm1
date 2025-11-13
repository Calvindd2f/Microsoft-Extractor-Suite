param (
    [switch]$NoWelcome = $false,
    [switch]$script:CheckForUpdates = $false,
    [switch]$script:UpdateToLatestVersion = $false
)

# Set supported TLS methods
[Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls13"

$manifest = Import-PowerShellDataFile "$PSScriptRoot\Microsoft-Extractor-Suite.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle = "Microsoft-Extractor-Suite $version"

if (-not $NoWelcome) {
    $logo = @"
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+
 |M|i|c|r|o|s|o|f|t| |E|x|t|r|a|c|t|o|r| |S|u|i|t|e|
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+
Copyright 2025 Invictus Incident Response
Created by Joey Rentenaar & Korstiaan Stam
"@

    Write-Host $logo -ForegroundColor Yellow
}

$outputDir = "Output"
if (!(test-path $outputDir)) {
    New-Item -ItemType Directory -Force -Name $Outputdir > $null
}

$retryCount = 0

Function StartDate {
    param([switch]$Quiet,
        [int]$DefaultOffset = -90)

    if (($startDate -eq "") -Or ($null -eq $startDate)) {
        $script:StartDate = [datetime]::Now.ToUniversalTime().AddDays($DefaultOffset)
        if (-not $Quiet) {
            Write-LogFile -Message "[INFO] No start date provided by user setting the start date to: $($script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
        }
    }
    else {
        $script:startDate = [datetime]::Parse($startDate).ToUniversalTime()
        if (!$script:startDate -and -not $Quiet) {
            Write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"
        }
    }
}

Function StartDateUAL {
    param([switch]$Quiet)

    StartDate -Quiet:$Quiet -DefaultOffset:-180
}

Function StartDateAz {
    param([switch]$Quiet)

    StartDate -Quiet:$Quiet -DefaultOffset:-30
}

function EndDate {
    param([switch]$Quiet)

    if (($endDate -eq "") -Or ($null -eq $endDate)) {
        $script:EndDate = [datetime]::Now.ToUniversalTime()
        if (-not $Quiet) {
            Write-LogFile -Message "[INFO] No end date provided by user setting the end date to: $($script:EndDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
        }
    }
    else {
        $script:endDate = [datetime]::Parse($endDate).ToUniversalTime()
        if (!$endDate -and -not $Quiet) {
            Write-LogFile -Message "[WARNING] Not A valid end date and time, make sure to use YYYY-MM-DD" -Color "Red"
        }
    }
}

[Flags()]
enum LogLevel {
    None = 0
    Minimal = 1
    Standard = 2
    Debug = 3
}

$script:LogLevel = [LogLevel]::Standard

function Set-LogLevel {
    param (
        [LogLevel]$Level
    )
    $script:LogLevel = $Level
}


$logFile = "Output\LogFile.txt"
function Write-LogFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Color,
        [switch]$NoNewLine,
        [LogLevel]$Level = [LogLevel]::Standard
    )

    if ($Level -gt $script:LogLevel) {
        return
    }

    if ($script:LogLevel -eq [LogLevel]::None) {
        return
    }

    $outputDir = "Output"
    if (!(test-path $outputDir)) {
        New-Item -ItemType Directory -Force -Name $Outputdir > $null
    }

    if (!$color -and $Level -eq [LogLevel]::Debug) {
        $color = "Yellow"
    }

    switch ($color) {
        "Yellow" { [Console]::ForegroundColor = [ConsoleColor]::Yellow }
        "Red" { [Console]::ForegroundColor = [ConsoleColor]::Red }
        "Green" { [Console]::ForegroundColor = [ConsoleColor]::Green }
        "Cyan" { [Console]::ForegroundColor = [ConsoleColor]::Cyan }
        "White" { [Console]::ForegroundColor = [ConsoleColor]::White }
        default { [Console]::ResetColor() }
    }

    $logMessage = if (!$NoTimestamp) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    }
    else {
        $Message
    }

    if ($NoNewLine) {
        [Console]::Write($Message)
    }
    else {
        [Console]::WriteLine($Message)
    }

    [Console]::ResetColor()
    [System.IO.File]::AppendAllText($logFile, "$logMessage$([System.Environment]::NewLine)")
}

function versionCheck {
    <#
    .SYNOPSIS
        Checks if a newer version of the module is available on PSGallery.
    .OUTPUTS
        [Version] Returns the latest version if available, otherwise returns current version.
    #>
    $moduleName = "Microsoft-Extractor-Suite"
    $currentVersion = [Version]$version

    try {
        # Single Find-Module call to cache result
        $moduleInfo = Find-Module -Name $moduleName -Repository PSGallery -ErrorAction Stop
        $latestVersion = [Version]$moduleInfo.Version.ToString()

        if ($currentVersion -lt $latestVersion) {
            Write-LogFile -Message "`n[INFO] You are running an outdated version ($currentVersion) of $moduleName. The latest version is ($latestVersion), please update to the latest version." -Color "Yellow"
            return $latestVersion
        }
        else {
            Write-LogFile -Message "[INFO] You are running the latest version ($currentVersion) of $moduleName." -Level Minimal
            return $currentVersion
        }
    }
    catch {
        Write-LogFile -Message "[WARNING] Failed to check for updates: $($_.Exception.Message)" -Color Yellow
        return $currentVersion
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
    }
    else {
        $authType = $context | Select-Object -ExpandProperty AuthType
        $scopes = $context | Select-Object -ExpandProperty Scopes
    }

    $missingScopes = [System.Collections.Generic.List[string]]::new()
    foreach ($requiredScope in $RequiredScopes) {
        if (-not ($scopes -contains $requiredScope)) {
            $missingScopes.Add($requiredScope)
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
        AuthType      = $authType
        Scopes        = $scopes
        MissingScopes = $missingScopes
    }
}

function Init-Logging {
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    $script:scriptStartedAt = Get-Date

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        foreach ($param in $PSBoundParameters.GetEnumerator()) {
            Write-LogFile -Message "[DEBUG]   $($param.Key): $($param.Value)" -Level Debug
        }

        $graphModule = Get-Module -Name Microsoft.Graph* -ErrorAction SilentlyContinue
        if ($graphModule) {
            Write-LogFile -Message "[DEBUG] Microsoft Graph Modules loaded:" -Level Debug
            foreach ($module in $graphModule) {
                Write-LogFile -Message "[DEBUG]   - $($module.Name) v$($module.Version)" -Level Debug
            }
        }
        else {
            Write-LogFile -Message "[DEBUG] No Microsoft Graph modules loaded" -Level Debug
        }
    }
}

function Check-GraphContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$RequiredScopes
    )

    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] Graph authentication completed" -Level Debug
        try {
            $context = Get-MgContext
            if ($context) {
                Write-LogFile -Message "[DEBUG] Graph context information:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Account: $($context.Account)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Environment: $($context.Environment)" -Level Debug
                Write-LogFile -Message "[DEBUG]   TenantId: $($context.TenantId)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Scopes: $($context.Scopes -join ', ')" -Level Debug
            }
        }
        catch {
            Write-LogFile -Message "[DEBUG] Could not retrieve Graph context details" -Level Debug
        }
    }
}

function Init-OutputDir {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Component,
        [string]$SubComponent = "",
        [Parameter(Mandatory = $true)]
        [string]$FilePostfix,
        [string]$CustomOutputDir = ""
    )

    if ([string]::IsNullOrEmpty($CustomOutputDir) -and $script:CollectionOutputDir) {
        $CustomOutputDir = $script:CollectionOutputDir
    }

    $date = [datetime]::Now.ToString('yyyyMMdd')

    if ($CustomOutputDir) {
        # Use custom directory but add component structure
        $OutputDir = if (-not [string]::IsNullOrEmpty($SubComponent)) {
            Join-Path $CustomOutputDir "$Component\$date-$SubComponent"
        }
        else {
            Join-Path $CustomOutputDir "$Component\$date"
        }

        if (!(Test-Path -Path $CustomOutputDir)) {
            Write-LogFile -Message "[ERROR] Custom base directory invalid: $CustomOutputDir" -Level Minimal -Color "Red"
            throw
        }

        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[DEBUG] Creating custom output directory: $OutputDir" -Level Debug
            New-Item -ItemType Directory -Force -Path $OutputDir > $null
        }
    }
    else {
        # Use default directory structure
        $OutputDir = if (-not [string]::IsNullOrEmpty($SubComponent)) {
            "Output\$Component\$date-$SubComponent"
        }
        else {
            "Output\$Component\$date"
        }

        if (!(Test-Path $OutputDir)) {
            Write-LogFile -Message "[DEBUG] Creating output directory: $OutputDir" -Level Debug
            New-Item -ItemType Directory -Force -Path $OutputDir > $null
        }
    }

    Write-LogFile -Message "[DEBUG] Using output directory: $OutputDir" -Level Debug
    $filename = "$($date)-$FilePostfix.csv"
    $script:outputFile = Join-Path $OutputDir $filename
}

function Write-Summary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Summary,
        [string]$Title = "Summary",
        [switch]$SkipExportDetails
    )

    Write-LogFile -Message "$([System.Environment]::NewLine)=== $Title ===$([System.Environment]::NewLine)" -Color "Cyan" -Level Standard

    foreach ($param in $Summary.GetEnumerator()) {
        if ($param.value -is [hashtable] -or $param.value -is [System.Collections.Specialized.OrderedDictionary]) {
            Write-LogFile -Message "$([System.Environment]::NewLine)$($param.key):$([System.Environment]::NewLine)" -Level Standard
            foreach ($subitem in $param.value.GetEnumerator()) {
                Write-LogFile -Message "  $($subitem.key): $($subitem.value)" -Level Standard
            }
        }
        else {
            Write-LogFile -Message "$($param.key): $($param.value)" -Level Standard
        }
    }

    # Only show Export Details if not skipped and outputFile exists
    if (-not $SkipExportDetails -and $script:outputFile) {
        $ProcessingTime = (Get-Date) - $script:ScriptStartedAt
        Write-LogFile -Message "$([System.Environment]::NewLine)Export Details:$([System.Environment]::NewLine)" -Level Standard
        Write-LogFile -Message "  Output File: $script:outputFile" -Level Standard
        Write-LogFile -Message "  Processing Time: $($ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
    }
    elseif (-not $SkipExportDetails) {
        # If no outputFile but we want to show processing time
        $ProcessingTime = (Get-Date) - $script:ScriptStartedAt
        Write-LogFile -Message "`nProcessing Time: $($ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
    }
}

function Merge-OutputFiles {
    param (
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)]
        [ValidateSet('CSV', 'JSON', 'JSONL', 'TSV', 'SOF-ELK')]
        [string]$OutputType,
        [string]$MergedFileName,
        [switch]$SofElk
    )

    $outputDirMerged = Join-Path -Path $OutputDir -ChildPath "Merged"
    If (!(Test-Path $outputDirMerged)) {
        Write-LogFile -Message "[INFO] Creating the following directory: $outputDirMerged"
        New-Item -ItemType Directory -Force -Path $outputDirMerged > $null
    }

    $mergedPath = Join-Path -Path $outputDirMerged -ChildPath $MergedFileName

    switch ($OutputType) {
        'CSV' {
            <#
            Get-ChildItem $OutputDir -Filter *.csv | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $mergedPath -NoTypeInformation -Append -Encoding UTF8;
            <note>The above pipeline chain will bring tears on moderately big tenants...</note>
            #>
            $csvFiles = Get-ChildItem $OutputDir -Filter *.csv
            if ($csvFiles.Count -eq 0) {
                Write-LogFile -Message "[WARNING] No CSV files found in the specified directory: $OutputDir" -Color Yellow
                return
            }

            $wroteHeader = $false
            $headerColumns = $null
            $filesProcessed = 0
            $totalRows = 0

            foreach ($csvFile in $csvFiles) {
                try {
                    # Check if file is empty or has no content
                    if ($csvFile.Length -eq 0) {
                        Write-LogFile -Message "[WARNING] Empty CSV file skipped: $($csvFile.Name)" -Color Yellow
                        continue
                    }

                    $rows = Import-Csv -Path $csvFile.FullName -Encoding UTF8 -ErrorAction Stop
                    
                    # Validate that rows were imported successfully
                    if ($null -eq $rows) {
                        Write-LogFile -Message "[WARNING] Failed to import CSV file (null result): $($csvFile.Name)" -Color Yellow
                        continue
                    }

                    # Check if file has any data rows (not just header)
                    if ($rows.Count -eq 0) {
                        Write-LogFile -Message "[WARNING] CSV file contains no data rows: $($csvFile.Name)" -Color Yellow
                        continue
                    }

                    # Validate column consistency on first file with data
                    if (-not $wroteHeader) {
                        $headerColumns = ($rows[0].PSObject.Properties | Select-Object -ExpandProperty Name | Sort-Object)
                        $rows | Export-Csv $mergedPath -NoTypeInformation -Encoding UTF8
                        $wroteHeader = $true
                        $totalRows += $rows.Count
                        $filesProcessed++
                    }
                    else {
                        # Verify column order matches (warn if different but still process)
                        $currentColumns = ($rows[0].PSObject.Properties | Select-Object -ExpandProperty Name | Sort-Object)
                        $columnsMatch = Compare-Object -ReferenceObject $headerColumns -DifferenceObject $currentColumns
                        
                        if ($columnsMatch) {
                            Write-LogFile -Message "[WARNING] Column mismatch detected in $($csvFile.Name). Columns will be reordered to match header." -Color Yellow -Level Debug
                        }

                        $rows | Export-Csv $mergedPath -NoTypeInformation -Encoding UTF8 -Append
                        $totalRows += $rows.Count
                        $filesProcessed++
                    }
                }
                catch {
                    Write-LogFile -Message "[WARNING] Failed to process CSV file $($csvFile.Name): $($_.Exception.Message)" -Color Yellow
                    continue
                }
            }

            if ($filesProcessed -gt 0) {
                Write-LogFile -Message "[INFO] CSV files merged: $filesProcessed file(s) with $totalRows total rows into $mergedPath"
            }
            else {
                Write-LogFile -Message "[WARNING] No valid CSV data found to merge" -Color Yellow
            }
        }
        'SOF-ELK' {

            $jsonFiles = Get-ChildItem $OutputDir -Filter *.json | Sort-Object Name
            foreach ($file in $jsonFiles) {
                Write-LogFile -Message "[DEBUG] Processing file: $($file.Name)" -Level Debug
                $content = Get-Content -Path $file.FullName -Encoding UTF8

                foreach ($line in $content) {
                    if ($line.Trim() -ne "") {
                        Add-Content -Path $mergedPath -Value $line -Encoding UTF8
                    }
                }
            }
            Write-LogFile -Message "[INFO] SOF-ELK files merged into $mergedPath"
        }
        'JSON' {
            "[" | Set-Content $mergedPath -Encoding UTF8

            $firstFile = $true
            $jsonFiles = Get-ChildItem $OutputDir -Filter *.json
            foreach ($file in $jsonFiles) {
                $content = Get-Content -Path $file.FullName -Raw

                $content = $content.Trim()
                if ($content.StartsWith('[')) {
                    $content = $content.Substring(1)
                }
                if ($content.EndsWith(']')) {
                    $content = $content.Substring(0, $content.Length - 1)
                }
                $content = $content.Trim()

                if (-not $firstFile -and $content) {
                    Add-Content -Path $mergedPath -Value "," -Encoding UTF8 -NoNewline
                }

                if ($content) {
                    Add-Content -Path $mergedPath -Value $content -Encoding UTF8 -NoNewline
                    $firstFile = $false
                }
            }
            "]" | Add-Content $mergedPath -Encoding UTF8
            Write-LogFile -Message "[INFO] JSON files merged into $mergedPath"

        }
        'JSONL' {
            $jsonlFiles = Get-ChildItem -Path $OutputDir -Filter *.jsonl | Sort-Object Name
            if ($jsonlFiles.Count -eq 0) {
                Write-LogFile -Message "[ERROR] No JSONL files found in the specified directory: $OutputDir" -Color Red
                return
            }

            # streamreader for large files along with processing line-by-line = performance boost (noticable by several orders of magnitude if document is arond 100MB or more)
            $mergedLines = [System.Collections.Generic.List[string]]::new()
            foreach ($file in $jsonlFiles) {
                Write-LogFile -Message "[DEBUG] Processing JSONL file: $($file.Name)" -Level Debug
                $reader = $null
                try {
                    $reader = [System.IO.StreamReader]::new($file.FullName)
                    while (-not $reader.EndOfStream) {
                        $line = $reader.ReadLine()
                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            $trimmedLine = $line.Trim()
                            if ($trimmedLine.Length -gt 0) {
                                $mergedLines.Add($trimmedLine)
                            }
                        }
                    }
                }
                catch {
                    Write-LogFile -Message "[WARNING] Failed to process file $($file.Name): $($_.Exception.Message)" -Color Yellow
                }
                finally {
                    if ($null -ne $reader) {
                        $reader.Dispose()
                    }
                }
            }

            if ($mergedLines.Count -gt 0) {
                [System.IO.File]::WriteAllLines($mergedPath, $mergedLines, [System.Text.Encoding]::UTF8)
                Write-LogFile -Message "[INFO] Merged $($mergedLines.Count) JSONL lines from $($jsonlFiles.Count) file(s) into $mergedPath"
            }
            else {
                Write-LogFile -Message "[WARNING] No valid JSONL lines found to merge" -Color Yellow
            }
        }
        'TSV' {
            $tsvFiles = Get-ChildItem -Path $OutputDir -Filter *.tsv | Sort-Object Name
            if ($tsvFiles.Count -eq 0) {
                Write-LogFile -Message "[ERROR] No TSV files found in the specified directory: $OutputDir" -Color Red
                return
            }

            $allRows = [System.Collections.Generic.List[string]]::new()
            $headersWritten = $false
            $totalRows = 0

            foreach ($file in $tsvFiles) {
                Write-LogFile -Message "[DEBUG] Processing TSV file: $($file.Name)" -Level Debug
                $reader = $null
                try {
                    $reader = [System.IO.StreamReader]::new($file.FullName)
                    $isFirstLine = $true
                    while (-not $reader.EndOfStream) {
                        $line = $reader.ReadLine()
                        if ([string]::IsNullOrWhiteSpace($line)) {
                            continue
                        }

                        if ($isFirstLine) {
                            $isFirstLine = $false
                            if (-not $headersWritten) {
                                $allRows.Add($line)
                                $headersWritten = $true
                            }
                            # Skip header if we've already written it
                        }
                        else {
                            $allRows.Add($line)
                            $totalRows++
                        }
                    }
                }
                catch {
                    Write-LogFile -Message "[WARNING] Failed to process TSV file $($file.Name): $($_.Exception.Message)" -Color Yellow
                }
                finally {
                    if ($null -ne $reader) {
                        $reader.Dispose()
                    }
                }
            }

            if ($allRows.Count -gt 0) {
                [System.IO.File]::WriteAllLines($mergedPath, $allRows, [System.Text.Encoding]::UTF8)
                Write-LogFile -Message "[INFO] Merged TSV data from $($tsvFiles.Count) file(s) ($totalRows data rows) into $mergedPath"
            }
            else {
                Write-LogFile -Message "[WARNING] No valid TSV data found to merge" -Color Yellow
            }
        }
        default {
            Write-LogFile -Message "[ERROR] Unsupported file type specified: $OutputType" -Color Red
        }
    }
}

if ($script:CheckForUpdates -or $script:UpdateToLatestVersion) {
    $moduleName = "Microsoft-Extractor-Suite"
    $currentVersion = [Version]$version

    # Single Find-Module call, reuse result for both operations
    try {
        $moduleInfo = Find-Module -Name $moduleName -Repository PSGallery -ErrorAction Stop
        $latestVersion = [Version]$moduleInfo.Version.ToString()
    }
    catch {
        $errorMsg = "Failed to query PSGallery for module updates: $($_.Exception.Message)"
        Write-LogFile -Message "[ERROR] $errorMsg" -Color Red
        if ($script:UpdateToLatestVersion) {
            # only exit if we're trying to update, not just check
            return
        }
        return
    }

    if ($script:CheckForUpdates) {
        # just check and report
        if ($currentVersion -lt $latestVersion) {
            Write-LogFile -Message "`n[INFO] Update available: Current version ($currentVersion) < Latest version ($latestVersion)" -Color Yellow
            Write-LogFile -Message "[INFO] To update, use: Import-Module $moduleName -ArgumentList @{UpdateToLatestVersion=`$true}" -Color Cyan
        }
        else {
            Write-LogFile -Message "[INFO] You are running the latest version ($currentVersion)" -Color Green -Level Minimal
        }
    }
    elseif ($script:UpdateToLatestVersion) {
        # update
        if ($currentVersion -ge $latestVersion) {
            Write-LogFile -Message "[INFO] Already running latest version ($currentVersion)" -Color Green
            return
        }

        Write-LogFile -Message "[INFO] Updating from version $currentVersion to $latestVersion..." -Color Yellow

        # Create backup before update
        $backupCreated = $false
        $backupPath = $null
        $currentModulePath = $null
        
        try {
            # Get current module installation path
            $installedModule = Get-InstalledModule -Name $moduleName -ErrorAction Stop
            $currentModulePath = $installedModule.InstalledLocation
            
            if ($currentModulePath -and (Test-Path $currentModulePath)) {
                # Create backup directory with timestamp
                $backupDir = Join-Path $env:TEMP "Microsoft-Extractor-Suite-Backup-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss'))"
                $backupPath = Join-Path $backupDir (Split-Path $currentModulePath -Leaf)
                
                Write-LogFile -Message "[INFO] Creating backup of current version to: $backupDir" -Color Cyan
                New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
                Copy-Item -Path $currentModulePath -Destination $backupPath -Recurse -Force -ErrorAction Stop
                $backupCreated = $true
                Write-LogFile -Message "[INFO] Backup created successfully" -Color Green
            }
        }
        catch {
            Write-LogFile -Message "[WARNING] Failed to create backup: $($_.Exception.Message). Proceeding with update anyway..." -Color Yellow
        }

        try {
            # avoid elevation requirements by checking if you ran as admin or not and choosing the appropriate scope
            if ([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544') {
                $public:scope = "CurrentUser"
            } else {
                $public:scope = "AllUsers"
            }
            
            Update-Module -Name $moduleName -Repository PSGallery -Force -Scope $public:scope -ErrorAction Stop
            
            # Verify update succeeded
            $updatedModule = Get-InstalledModule -Name $moduleName -ErrorAction Stop
            $installedVersion = [Version]$updatedModule.Version.ToString()
            
            if ($installedVersion -ne $latestVersion) {
                throw "Update verification failed: Expected version $latestVersion but found $installedVersion"
            }
            
            Write-LogFile -Message "[INFO] Successfully updated $moduleName to version $latestVersion" -Color Green

            # Attempt reload - note: binary modules will require session restart
            Write-LogFile -Message "[INFO] Reloading the updated module..." -Color Yellow

            $module = Get-Module -Name $moduleName -ErrorAction SilentlyContinue
            if ($module) {
                # check if module path changed before attempting removal
                $newModulePath = (Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue).InstalledLocation
                if ($newModulePath -and $module.ModuleBase -ne $newModulePath) {
                    Remove-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 500  # brief pause to allow cleanup
                    Import-Module -Name $moduleName -Force -ErrorAction Stop
                    
                    # Verify module loaded correctly
                    $reloadedModule = Get-Module -Name $moduleName -ErrorAction Stop
                    if ($reloadedModule) {
                        Write-LogFile -Message "[INFO] Module reloaded successfully" -Color Green
                    }
                    else {
                        throw "Module reload verification failed"
                    }
                }
                else {
                    Write-LogFile -Message "[WARNING] Module may need manual reload. Restart your PowerShell session or run: Import-Module $moduleName -Force" -Color Yellow
                }
            }
            else {
                Import-Module -Name $moduleName -Force -ErrorAction Stop
                
                # Verify module imported correctly
                $importedModule = Get-Module -Name $moduleName -ErrorAction Stop
                if ($importedModule) {
                    Write-LogFile -Message "[INFO] Module imported successfully" -Color Green
                }
                else {
                    throw "Module import verification failed"
                }
            }
            
            # Clean up backup on successful update
            if ($backupCreated -and $backupPath -and (Test-Path (Split-Path $backupPath -Parent))) {
                Write-LogFile -Message "[INFO] Update successful. Backup can be found at: $(Split-Path $backupPath -Parent)" -Level Debug
            }
        }
        catch {
            $errorMsg = "Failed to update module: $($_.Exception.Message)"
            Write-LogFile -Message "[ERROR] $errorMsg" -Color Red
            
            # Attempt rollback if backup exists
            if ($backupCreated -and $backupPath -and $currentModulePath -and (Test-Path $backupPath)) {
                Write-LogFile -Message "[INFO] Attempting to rollback to previous version..." -Color Yellow
                try {
                    # Remove failed update
                    if (Test-Path $currentModulePath) {
                        Remove-Item -Path $currentModulePath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    
                    # Restore from backup
                    Copy-Item -Path $backupPath -Destination $currentModulePath -Recurse -Force -ErrorAction Stop
                    Write-LogFile -Message "[INFO] Rollback successful. Previous version restored from backup." -Color Green
                    Write-LogFile -Message "[INFO] Backup location: $(Split-Path $backupPath -Parent)" -Color Cyan
                }
                catch {
                    Write-LogFile -Message "[ERROR] Rollback failed: $($_.Exception.Message)" -Color Red
                    Write-LogFile -Message "[INFO] Manual restoration may be required. Backup location: $(Split-Path $backupPath -Parent)" -Color Yellow
                }
            }
            else {
                Write-LogFile -Message "[INFO] No backup available for rollback. Manual update may be required." -Color Yellow
            }
            
            Write-LogFile -Message "[INFO] You may need to manually update using: Update-Module -Name $moduleName -Force" -Color Yellow
            return
        }
    }
}

Export-ModuleMember -Function * -Alias * -Variable * -Cmdlet *
