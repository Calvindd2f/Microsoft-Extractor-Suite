# Load required functions from module
try {
    Import-Module "$PSScriptRoot\Microsoft-Extractor-Suite.psm1" -ErrorAction Stop
} catch {
    Write-Error "Error loading module: $_"
    exit 1
}

function Log-Message {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ConsoleColor]$Color = 'White'
    )
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message" -ForegroundColor $Color
}

function Test-GraphResponse {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [object]$Response
    )
    if ($Response.IsSuccessStatusCode) {
        return $true
    } else {
        Log-Message "Error: Graph API request failed with status code: $($Response.StatusCode) and reason: $($Response.ReasonPhrase)" -Color 'Red'
        return $false
    }
}

function Get-SpecificEmail {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [Parameter(Mandatory = $true)]
        [string]$InternetMessageId,

        [Parameter(Mandatory=$false)]
        [ValidateSet('msg', 'eml')]
        [string]$OutputFormat = 'msg',

        [Parameter(Mandatory=$false)]
        [string]$OutputDirectory = "Output\EmailExport",

        [Parameter(Mandatory=$false)]
        [switch]$IncludeAttachments,

        [Parameter(Mandatory=$false)]
        [string]$Token,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Yes', 'No')]
        [string]$Confirm = 'No'
    )

    if ($Confirm -eq 'Yes') {
        $continue = $PSCmdlet.ShouldProcess("Email with InternetMessageId $InternetMessageId")
    } else {
        $continue = $true
    }

    if (-not $continue) {
        return
    }

    $headers = @{
        "Authorization" = "Bearer $Token"
    }

    $uri = "https://graph.microsoft.com/v1.0/users/$UserId/messages"

    try {
        $queryParams = @{
            '$filter' = "internetMessageId eq '$InternetMessageId'"
        }
        $message = Invoke-MgGraphRequest -Uri $uri -Headers $headers -Method Get -QueryParameters $queryParams
    }
    catch {
        Log-Message "Error fetching data: $_"
        return
    }

    if (!(Test-GraphResponse $message)) {
        return
    }

    if (!(Test-Path -Path $OutputDirectory)) {
        Log-Message "Invalid output directory: $OutputDirectory"
        return
    }

    $subject = $message.Subject -replace '[\\/:*?"<>|]', '_'
    $receivedDateTime = [datetime]::Parse($message.ReceivedDateTime).ToString("yyyyMMdd_HHmmss")
    $filePath = Join-Path -Path $OutputDirectory -ChildPath "$receivedDateTime-$subject.$OutputFormat"

    if (-not (Test-Path -Path $filePath)) {
        Invoke-MgGraphRequest -Uri $message.ContentUrl -Headers $headers -OutFile $filePath
        Log-Message "[INFO] Output written to $filePath" -Color 'Green'
    } else {
        Log-Message "[WARNING] Output file already exists: $filePath" -Color 'Yellow'
    }

    if ($IncludeAttachments) {
        foreach ($attachment in $message.Attachments) {
            $attachmentHeaders = @{
                "Authorization" = "Bearer $Token"
                "Prefer" = "return=representation"
            }

            $attachmentFile = Join-Path -Path $OutputDirectory -ChildPath "$receivedDateTime-$($attachment.Name)$($attachment.ContentType.Split('/')[1])"

            if (-not (Test-Path -Path $attachmentFile)) {
                Invoke-MgGraphRequest -Uri $attachment.ContentUrl -Headers $attachmentHeaders -OutFile $attachmentFile
                Log-Message "[INFO] Attachment written to $attachmentFile" -Color 'Green'
            } else {
                Log-Message "[WARNING] Attachment file already exists: $attachmentFile" -Color 'Yellow'
            }
        }
    }
}

<#
This function retrieves a specific email and its attachments using Microsoft Graph API.
The output format and directory can be specified.
By default, attachments are not included.
To include attachments, use the IncludeAttachments switch parameter.
A confirmation prompt is shown before processing if the Confirm parameter is not specified.
#>
