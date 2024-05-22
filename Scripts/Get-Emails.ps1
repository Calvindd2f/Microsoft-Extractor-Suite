using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Get-SpecificEmail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [Parameter(Mandatory = $true)]
        [string]$InternetMessageId,

        [string]$Output = "msg",

        [string]$OutputDirectory = "Output\EmailExport",

        [string]$Attachment,

        [string]$Token
    )

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
    $filePath = Join-Path -Path $OutputDirectory -ChildPath "$receivedDateTime-$subject.$Output"

    $contentUri = "$uri/$($message.Id)/$value"
    Invoke-MgGraphRequest -Uri $contentUri -Headers $headers -OutFile $filePath
    Write-Host "[INFO] Output written to $filePath" -ForegroundColor Green

    if ($Attachment -eq "True") {
        # Attachments would be retrieved in a manner similar to the above message content
        # Here you would need to implement the logic to download attachments.
    }
}

<#
You need to have an AccessToken to authenticate the API request. This token is typically obtained after authenticating with OAuth 2.0.
The $headers hashtable is used to pass the necessary headers for the HTTP request.
The $uri is the endpoint for the Microsoft Graph API to get messages for a user.
You will have to write the Get-Attachment part of the script to handle attachments via API calls, depending on the email service API you're using.
This example assumes that $message.value[0] contains the expected email. You would need to handle cases where the $message.value array might be empty or contain multiple items depending on the API's response.
#>

Function Get-Attachment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$userIds,
        [Parameter(Mandatory=$true)]$internetMessageId,
        [string]$outputDir
    )

    Write-logFile -Message "[INFO] Running Get-Attachment" -Color "Green"

    try {
        $areYouConnected = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages?filter=internetMessageId eq '$internetMessageId'" -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes Mail.Read, Mail.ReadBasic, Mail.ReadBasic.All before running this script" -Color "Red"
        Write-logFile -Message "[WARNING] The 'Mail.ReadBasic.All' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red"
        break
    }

    if ($outputDir -eq "" ){
        $outputDir = "Output\EmailExport"
        if (!(test-path $outputDir)) {
            New-Item -ItemType Directory -Force -Name $outputDir | Out-Null
            write-logFile -Message "[INFO] Creating the following directory: $outputDir"
        }
    }

    else {
        if (Test-Path -Path $OutputDir) {
            write-LogFile -Message "[INFO] Custom directory set to: $OutputDir"
        }
        else {
            write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
            write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script"
        }
    }

    $getMessage = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages?filter=internetMessageId eq '$internetMessageId'"
    $messageId = $getMessage.value.Id
    $hasAttachment = $getMessage.value.HasAttachments
    $ReceivedDateTime = $getMessage.value.ReceivedDateTime.ToString("yyyyMMdd_HHmmss")
    $subject = $getMessage.value.Subject

    if ($hasAttachment -eq "True"){
        $url = "https://graph.microsoft.com/v1.0/users/$userIds/messages/$messageId/attachments"
        $response = Invoke-MgGraphRequest -Method GET -Uri $url

        foreach ($attachment in $response.value) {
            $filename = $attachment.Name

            Write-logFile -Message "[INFO] Downloading attachment"
            Write-host "[INFO] Name: $filename"
            write-host "[INFO] Size: $($attachment.Size)"

            $url = "https://graph.microsoft.com/v1.0/users/$userIds/messages/$messageId/attachments/$($attachment.Id)/$($attachment.Name)"
            $response = Invoke-MgGraphRequest -Method GET -Uri $url -Download

            $filename = $filename -replace '[\\/:*?"<>|]', '_'
            $filePath = Join-Path -Path $outputDir -ChildPath "$ReceivedDateTime-$filename"
            Set-Content -Path $filePath -Value $response -Encoding Byte

            Write-logFile -Message "[INFO] Output written to '$subject-$filename'" -Color "Green"
        }
    }

    else {
        Write-logFile -Message "[WARNING] No attachment found for: $subject" -Color "Red"
    }
}
#This code uses Invoke-MgGraphRequest to make the API calls to retrieve the attachment. It first retrieves the list of attachments for the message, then loops through each attachment and retrieves the attachment data using a separate API call. The attachment data is then saved to the specified output directory.



Function Show-Email {
    <#
    .SYNOPSIS
    Show a specific email in the PowerShell Window.

    .DESCRIPTION
    Show a specific email in the PowerShell Window based on userId and Internet Message Id.

    .EXAMPLE
    Show-Email -userIds {userId} -internetMessageId {InternetMessageId}
    Show a specific email in the PowerShell Window.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$userIds,
        [Parameter(Mandatory=$true)]$internetMessageId
    )

    Write-logFile -Message "[INFO] Running Show-Email" -Color "Green"

    try {
        $message = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages?filter=internetMessageId eq '$internetMessageId'" -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes Mail.Read, Mail.ReadBasic, Mail.ReadBasic.All, Mail.ReadWrite before running this script" -Color "Red"
        Write-logFile -Message "[WARNING] The 'Mail.ReadBasic.All' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red"
        break
    }

    $message.value | Format-List *
}

 #I replaced the Get-MgUserMessage cmdlet with Invoke-MgGraphRequest to make a GET request to the Microsoft Graph API. The response is stored in the $message variable, and then the properties of the email are displayed using Format-List *.


