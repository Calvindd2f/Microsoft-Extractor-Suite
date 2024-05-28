# Load required functions from module
try {
    Import-Module "$PSScriptRoot\Microsoft-Extractor-Suite.psm1" -ErrorAction Stop
} catch {
    Write-Error "Error loading module: $_"
    exit 1
}

function Get-SpecificEmail {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [Parameter(Mandatory = $true)]
        [string]$InternetMessageId,

        [string]$OutputFormat = "msg",

        [string]$OutputDirectory = "Output\EmailExport",

        [switch]$IncludeAttachments,

        [string]$Token,

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
        Write-Error "Error fetching data: $_"
        return
    }

    if (!(Test-Path -Path $OutputDirectory)) {
        Write-Error "Invalid output directory: $OutputDirectory"
        return
    }

    $subject = $message.Subject -replace '[\\/:*?"<>|]', '_'
    $receivedDateTime = [datetime]::Parse($message.ReceivedDateTime).ToString("yyyyMMdd_HHmmss")
    $filePath = Join-Path -Path $OutputDirectory -ChildPath "$receivedDateTime-$subject.$OutputFormat"

    Invoke-MgGraphRequest -Uri $message.ContentUrl -Headers $headers -OutFile $filePath
    Write-Host "[INFO] Output written to $filePath" -ForegroundColor Green

    if ($IncludeAttachments) {
        foreach ($attachment in $message.Attachments) {
            $attachmentHeaders = @{
                "Authorization" = "Bearer $Token"
                "Prefer" = "return=representation"
            }

            $attachmentFile = Join-Path -Path $OutputDirectory -ChildPath "$receivedDateTime-$($attachment.Name)$($attachment.ContentType.Split('/')[1])"

            Invoke-MgGraphRequest -Uri $attachment.ContentUrl -Headers $attachmentHeaders -OutFile $attachmentFile
            Write-Host "[INFO] Attachment written to $attachmentFile" -ForegroundColor Green
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
