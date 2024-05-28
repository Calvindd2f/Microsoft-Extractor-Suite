# Check if the current user has the required permissions
function Test-HasRequiredPermissions {
    [CmdletBinding()]
    param ()

    try {
        Get-AdminAuditLogConfig -ErrorAction Stop
    }
    catch {
        Write-Error "You must call Connect-M365 before running this script"
        return $false
    }

    return $true
}

# Get the sessions
function Get-Sessions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$StartDate,

        [Parameter(Mandatory=$true)]
        [string]$EndDate,

        [string]$UserIds,

        [string]$IP,

        [string]$OutputDir = "Output\MailItemsAccessed",

        [string]$Encoding = "UTF8",

        [string]$Output = "Y"
    )

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    $params = @{
        StartDate   = $StartDate
        EndDate     = $EndDate
        ResultSize  = 5000
        Operations  = "MailItemsAccessed"
    }

    if ($UserIds) {
        $params.UserIds = $UserIds
    }

    if ($IP) {
        $params.FreeText = $IP
    }

    $results = Search-UnifiedAuditLog @params

    if ($UserIds) {
        $results = $results | Where-Object { $_.AuditData.UserId -eq $UserIds }
    }

    if ($IP) {
        $results = $results | Where-Object { $_.AuditData.ClientIPAddress -eq $IP }
    }

    $results = $results | ForEach-Object {
        [PSCustomObject]@{
            TimeStamp   = $_.AuditData.CreationTime
            User        = $_.AuditData.UserId
            Action      = $_.AuditData.Operation
            SessionId   = $_.AuditData.SessionId
            ClientIP    = $_.AuditData.ClientIPAddress
            OperationCount = $_.AuditData.OperationCount
        }
    }

    if ($Output -eq "Y") {
        $filePath = Join-Path -Path $OutputDir -ChildPath "Sessions.csv"
        $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
        Write-Host "Output written to $filePath"
    }

    $results
}

# Get the message IDs
function Get-MessageIDs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$StartDate,

        [Parameter(Mandatory=$true)]
        [string]$EndDate,

        [string]$Sessions,

        [string]$IP,

        [string]$OutputDir = "Output\MailItemsAccessed",

        [string]$Encoding = "UTF8",

        [string]$Output = "Y"
    )

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    $params = @{
        StartDate   = $StartDate
        EndDate     = $EndDate
        ResultSize  = 5000
        Operations  = "MailItemsAccessed"
    }

    if ($Sessions) {
        $params.SessionIds = $Sessions
    }

    if ($IP) {
        $params.FreeText = $IP
    }

    $results = Search-UnifiedAuditLog @params

    if ($Sessions) {
        $results = $results | Where-Object { $_.AuditData.SessionId -in $Sessions }
    }

    if ($IP) {
        $results = $results | Where-Object { $_.AuditData.ClientIPAddress -eq $IP }
    }

    $results = $results | ForEach-Object {
        [PSCustomObject]@{
            TimeStamp   = $_.AuditData.CreationTime
            User        = $_.AuditData.UserId
            IPaddress   = $_.AuditData.ClientIPAddress
            SessionID   = $_.AuditData.SessionId
            MessageID   = $_.AuditData.MessageId
        }
    }

    if ($Output -eq "Y") {
        $filePath = Join-Path -Path $OutputDir -ChildPath "MessageIDs.csv"
        $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
        Write-Host "Output written to $filePath"
    }

    $results
}

# Download the emails and attachments
function Download-Emails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$MessageID,

        [Parameter(Mandatory=$true)]
        [string]$UserIds,

        [string]$OutputDir = "Output\MailItemsAccessed\Emails"
    )

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    $message = Get-MgUserMessage -Filter "internetMessageId eq '$MessageID'" -UserId $UserIds -ErrorAction Stop
    $attachment = $message.Attachments

    $filePath = Join-Path -Path $OutputDir -ChildPath "$($message.ReceivedDateTime.ToString("yyyyMMdd_HHmmss"))-$($message.Subject).msg"
    Get-MgUserMessageContent -MessageId $message.Id -UserId $UserIds -OutFile $filePath
    Write-Host "Output written to $filePath"

    if ($attachment -eq "True") {
        Write-Host "Found Attachment file!"
        $attachment = Get-MgUserMessageAttachment -UserId $UserIds -MessageId $MessageID
        $filename = $attachment.Name

        Write-Host "Downloading attachment"
        Write-Host "Name: $filename"
        Write-Host "Size: $($attachment.Size)"

        $base64B = ($attachment).AdditionalProperties.contentBytes
        $decoded = [System.Convert]::FromBase64String($base64B)

        $filename = $filename -replace '[\\/:*?"<>|]', '_'
        $filePath = Join-Path -Path $OutputDir -ChildPath "$($message.ReceivedDateTime.ToString("yyyyMMdd_HHmmss"))-$filename"
        Set-Content -Path $filePath -Value $decoded -Encoding Byte

        Write-Host "File Attachment Successfully Written to $filePath"
    }
}

# Check if the current user has the required permissions
if (-not (Test-HasRequiredPermissions)) {
    exit 1
}

# Get the sessions
$sessions = Get-Sessions -StartDate "2023-01-01" -EndDate "2023-02-01" -UserIds "user1@example.com" -IP "192.168.1.1"

# Get the message IDs
$messageIDs = Get-MessageIDs -StartDate "2023-01-01" -EndDate "2023-02-01" -Sessions $sessions.SessionId -IP "192.168.1.1"

# Download the emails and attachments
$messageIDs.MessageID | ForEach-Object { Download-Emails -MessageID $_ -UserIds "user1@example.com" }
