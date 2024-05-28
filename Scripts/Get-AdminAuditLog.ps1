# Load required modules
Import-Module -Name "Microsoft.PowerShell.Utility"

# Define the function
function Get-AdminAuditLogs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({$_ -as [datetime]})]
        [datetime]$StartDate,

        [Parameter(Mandatory)]
        [ValidateScript({$_ -as [datetime]})]
        [datetime]$EndDate,

        [Parameter(Mandatory)]
        [string]$OutputDirectory
    )

    # Convert input dates to universal time
    $startDateUtc = $StartDate.ToUniversalTime()
    $endDateUtc = $EndDate.ToUniversalTime()

    # Generate output file name
    $outputFileName = "{0}-AdminAuditLog-$(Get-Date -Format yyyyMMddHHmmss).csv" -f $startDateUtc.ToString("yyyy-MM-ddTHH:mm:ssK")
    $outputPath = Join-Path $OutputDirectory $outputFileName

    # Write log messages
    Write-Host "[INFO] Running Get-AdminAuditLogs" -ForegroundColor Green
    Write-Host "[INFO] Extracting all available Admin Audit Logs between $($startDateUtc.ToString("yyyy-MM-ddTHH:mm:ssK")) and $($endDateUtc.ToString("yyyy-MM-ddTHH:mm:ssK"))" -ForegroundColor Green

    # Get an access token for Microsoft Graph API
    $clientId = "your-client-id"
    $tenantId = "your-tenant-id"
    $clientSecret = "your-client-secret"
    $resourceAppIdUri = "https://graph.microsoft.com"

    $tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/token"
    $body = @{
        client_id     = $clientId
        client_secret = $clientSecret
        resource      = $resourceAppIdUri
        grant_type    = "client_credentials"
    }

    $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body
    $token = $response.access_token

    # Define the API URL
    $apiUrl = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge '$startDateUtc' and activityDateTime le '$endDateUtc'"

    # Initialize the list for storing audit logs
    $auditLogs = @()

    # Retrieve and export audit logs
    do {
        $response = Invoke-RestMethod -Headers @{Authorization = "Bearer $token"} -Uri $apiUrl -Method Get -ContentType 'application/json'
        $currentAuditLogs = $response.value

        if ($currentAuditLogs) {
            $auditLogs += $currentAuditLogs
            $apiUrl = $response.'@odata.nextLink'
        }
    } while ($apiUrl)

    # Export the audit logs to a CSV file
    $auditLogs | Export-Csv $outputPath -NoTypeInformation -Encoding UTF8

    Write-Host "[INFO] Output is written to: $outputPath" -ForegroundColor Green
}

# Call the function
Get-AdminAuditLogs -StartDate (Get-Date "2022-01-01T00:00:00Z") -EndDate (Get-Date "2022-01-31T23:59:59Z") -OutputDirectory "C:\Temp"
