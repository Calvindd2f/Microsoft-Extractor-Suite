. "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Write-Log {
    [CmdletBinding()]
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::White,
        [switch]$ToFile
    )

    if ($Color) {
        Write-Host $Message -ForegroundColor $Color
    } else {
        Write-Host $Message
    }

    if ($ToFile) {
        $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logFile = Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath "Logs") -ChildPath "$($MyInvocation.MyCommand.Name).log"

        if (-not (Test-Path -Path (Split-Path -Path $logFile -Parent))) {
            try {
                New-Item -ItemType Directory -Force -Path (Split-Path -Path $logFile -Parent)
            } catch {
                Write-Log -Message "[ERROR] Failed to create log directory: $($_.Exception.Message)" -Color "Red" -ToFile
            }
        }

        try {
            Add-Content -Path $logFile -Value "$date - $Message"
        } catch {
            Write-Log -Message "[ERROR] Failed to write to log file: $($_.Exception.Message)" -Color "Red" -ToFile
        }
    }
}

function Invoke-ApiRequest {
    [CmdletBinding()]
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body
    )

    $headers.Add("ConsistencyLevel", "eventual")
    $headers.Add("Prefer", "odata.maxversion=4.0")

    try {
        $response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $headers -Body $Body -UseBasicParsing
    } catch {
        Write-Log -Message "[ERROR] Failed to invoke API request: $($Uri) - $($_.Exception.Message)" -Color "Red" -ToFile
        return $null
    }

    if ($response.Error) {
        Write-Log -Message "[ERROR] API request failed: $($response.Error.Message)" -Color "Red" -ToFile

        if ($response.Error.InnerError) {
            Write-Log -Message "[ERROR] Inner error: $($response.Error.InnerError.Message)" -Color "Red" -ToFile
        }

        if ($response.Error.InnerError.RequestId) {
            Write-Log -Message "[ERROR] Request ID: $($response.Error.InnerError.RequestId)" -Color "Red" -ToFile
        }

        if ($response.Error.InnerError.Date) {
            Write-Log -Message "[ERROR] Date: $($response.Error.InnerError.Date)" -Color "Red" -ToFile
        }

        if ($response.Error.InnerError.Body) {
            Write-Log -Message "[ERROR] Body: $($response.Error.InnerError.Body)" -Color "Red" -ToFile
        }

        if ($response.Error.InnerError.Path) {
            Write-Log -Message "[ERROR] Path: $($response.Error.InnerError.Path)" -Color "Red" -ToFile
        }

        if ($response.Error.InnerError.StatusCode) {
            Write-Log -Message "[ERROR] Status code: $($response.Error.InnerError.StatusCode)" -Color "Red" -ToFile
        }

        if ($response.Error.InnerError.SubStatusCode) {
            Write-Log -Message "[ERROR] Sub status code: $($response.Error.InnerError.SubStatusCode)" -Color "Red" -ToFile
        }

        if ($response.Error.InnerError.Parameters) {
            Write-Log -Message "[ERROR] Parameters: $($response.Error.InnerError.Parameters)" -Color "Red" -ToFile
        }

        if ($response.Error.InnerError.Message) {
            Write-Log -Message "[ERROR] Message: $($response.Error.InnerError.Message)" -Color "Red" -ToFile
        }

        if ($response.Error.InnerError.Details) {
            Write-Log -Message "[ERROR] Details: $($response.Error.InnerError.Details)" -Color "Red" -ToFile
        }

        return $null
    }

    return $response
}

function Format-DateString {
    [CmdletBinding()]
    param(
        [datetime]$Date
    )

    return $Date.ToString("s") + "Z"
}

function Format-OutputFileName {
    [CmdletBinding()]
    param(
        [string]$RecordType,
        [datetime]$StartDate,
        [datetime]$EndDate
    )

    return "$($RecordType)_$(Format-DateString -Date $StartDate)_$(Format-DateString -Date $EndDate).csv"
}

function Format-RecordTypeName {
    [CmdletBinding()]
    param(
        [string]$RecordType
    )

    # Replace the words with their corresponding abbreviations
    $formattedRecordType = $RecordType.Replace("Exchange", "EXCH")
    $formattedRecordType = $formattedRecordType.Replace("SharePoint", "SHAREPOINT")
    $formattedRecordType = $formattedRecordType.Replace("OneDrive", "ONEDRIVE")
    $formattedRecordType = $formattedRecordType.Replace("AzureActiveDirectory", "AAD")
    $formattedRecordType = $formattedRecordType.Replace("DataCenterSecurityCmdlet", "DCSC")
    $formattedRecordType = $formattedRecordType.Replace("ComplianceDLP", "DLP")
    $formattedRecordType = $formattedRecordType.Replace("Sway", "SWAY")
    $formattedRecordType = $formattedRecordType.Replace("SecurityComplianceCenterEOPCmdlet", "SCCEOP")
    $formattedRecordType = $formattedRecordType.Replace("ExchangeAggregatedOperation", "EXCHAGG")
    $formattedRecordType = $formattedRecordType.Replace("PowerBIAudit", "PBIAUDIT")
    $formattedRecordType = $formattedRecordType.Replace("CRM", "CRM")
    $formattedRecordType = $formattedRecordType.Replace("Yammer", "YAMMER")
    $formattedRecordType = $formattedRecordType.Replace("SkypeForBusiness", "SFB")
    $formattedRecordType = $formattedRecordType.Replace("MicrosoftTeams", "MSTEAMS")
    $formattedRecordType = $formattedRecordType.Replace("ThreatIntelligence", "TI")
    $formattedRecordType = $formattedRecordType.Replace("MailSubmission", "MAILSUBM")
    $formattedRecordType = $formattedRecordType.Replace("MicrosoftFlow", "FLOW")
    $formattedRecordType = $formattedRecordType.Replace("AeD", "AED")
    $formattedRecordType = $formattedRecordType.Replace("MicrosoftStream", "STREAM")
    $formattedRecordType = $formattedRecordType.Replace("ComplianceDLPSharePointClassification", "DLPCLASS")
    $formattedRecordType = $formattedRecordType.Replace("ThreatFinder", "TF")
    $formattedRecordType = $formattedRecordType.Replace("Project", "PROJ")
    $formattedRecordType = $formattedRecordType.Replace("SharePointListOperation", "SHAREPOINTLIST")
    $formattedRecordType = $formattedRecordType.Replace("SharePointCommentOperation", "SHAREPOINTCOMMENT")
    $formattedRecordType = $formattedRecordType.Replace("DataGovernance", "DG")
    $formattedRecordType = $formattedRecordType.Replace("Kaizala", "KAIZALA")
    $formattedRecordType = $formattedRecordType.Replace("SecurityComplianceAlerts", "SCALERTS")
    $formattedRecordType = $formattedRecordType.Replace("ThreatIntelligenceUrl", "TIURL")
    $formattedRecordType = $formattedRecordType.Replace("SecurityComplianceInsights", "SCINSIGHTS")
    $formattedRecordType = $formattedRecordType.Replace("MIPLabel", "MIPLABEL")
    $formattedRecordType = $formattedRecordType.Replace("WorkplaceAnalytics", "WPA")
    $formattedRecordType = $formattedRecordType.Replace("PowerAppsApp", "POWERAPPSAPP")
    $formattedRecordType = $formattedRecordType.Replace("PowerAppsPlan", "POWERAPPSPLAN")
    $formattedRecordType = $formattedRecordType.Replace("ThreatIntelligenceAtpContent", "TIATPCONTENT")
    $formattedRecordType = $formattedRecordType.Replace("LabelContentExplorer", "LABELCONTENTEXP")
    $formattedRecordType = $formattedRecordType.Replace("TeamsHealthcare", "TEAMSHEALTHCARE")
    $formattedRecordType = $formattedRecordType.Replace("ExchangeItemAggregated", "EXCHITEM")

    return $formattedRecordType
}

function Log-ScriptStart {
    Write-Log -Message "Script execution started" -ToFile
}

function Log-ScriptEnd {
    Write-Log -Message "Script execution ended" -ToFile
}

function Log-RecordTypeStart {
    param(
        [string]$RecordType
    )

    $formattedRecordType = Format-RecordTypeName -RecordType $RecordType
    Write-Log -Message "Processing record type: $formattedRecordType" -ToFile
}

function Log-RecordTypeEnd {
    param(
        [string]$RecordType
    )

    $formattedRecordType = Format-RecordTypeName -RecordType $RecordType
    Write-Log -Message "Finished processing record type: $formattedRecordType" -ToFile
}

function Log-ApiRequestStart {
    param(
        [string]$RecordType,
        [string]$Uri
    )

    $formattedRecordType = Format-RecordTypeName -RecordType $RecordType
    Write-Log -Message "Starting API request for record type: $formattedRecordType - Uri: $Uri" -ToFile
}

function Log-ApiRequestEnd {
    param(
        [string]$RecordType,
        [string]$Uri
    )

    $formattedRecordType = Format-RecordTypeName -RecordType $RecordType
    Write-Log -Message "Finished API request for record type: $formattedRecordType - Uri: $Uri" -ToFile
}

function Log-CsvExportStart {
    param(
        [string]$RecordType,
        [string]$OutputFile
    )

    $formattedRecordType = Format-RecordTypeName -RecordType $RecordType
    Write-Log -Message "Starting CSV export for record type: $formattedRecordType - Output file: $OutputFile" -ToFile
}

function Log-CsvExportEnd {
    param(
        [string]$RecordType,
        [string]$OutputFile
    )

    $formattedRecordType = Format-RecordTypeName -RecordType $RecordType
    Write-Log -Message "Finished CSV export for record type: $formattedRecordType - Output file: $OutputFile" -ToFile
}

# Log script start
Log-ScriptStart

# Process record types
# Add your record type processing logic here


