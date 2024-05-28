# Azure Active Directory Sign-in Logs via Graph API

function Get-ADSignInLogsGraph {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$false)]
        [DateTime]$startDate = (Get-Date).AddDays(-30).Date,

        [Parameter(Mandatory=$false)]
        [DateTime]$endDate = (Get-Date).Date,

        [Parameter(Mandatory=$false)]
        [string]$OutputDir = "AzureAD",

        [Parameter(Mandatory=$false)]
        [string]$Encoding = "utf8",

        [Parameter(Mandatory=$false)]
        [Microsoft.Graph.AuthProvider]$AuthProvider,

        [Parameter(Mandatory=$false)]
        [string]$UserIds,

        [Parameter(Mandatory=$false)]
        [switch]$MergeOutput
    )

    # Check if the start date is before the end date
    if ($startDate -gt $endDate) {
        Write-Error "Start date cannot be later than end date."
        return
    }

    # Create the output directory if it doesn't exist
    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir
    }

    # Get the sign-in logs from the Graph API
    try {
        $signInLogs = Get-MgUserSignInLogs -Top 999 -Filter "signInTime ge $($startDate.ToString("s")) and signInTime le $($endDate.ToString("s"))" -Property "id,userId,signInTime,application,ipAddress,clientAppUsed,deviceDetail,location,status,additionalDetails" -AuthProvider $AuthProvider
    } catch {
        Write-Error "Failed to retrieve sign-in logs: $_"
        return
    }

    # Convert the sign-in logs to CSV format
    $csvContent = $signInLogs | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1
    $csvContent = $csvContent -join [Environment]::NewLine

    # Save the CSV content to a file
    $outputFile = Join-Path $OutputDir "SignInLogsGraph_$(Get-Date -Format yyyy-MM-dd).csv"
    $csvContent | Out-File -Encoding $Encoding -FilePath $outputFile

    # Merge the CSV outputs if specified
    if ($MergeOutput) {
        $mergedContent = Import-Csv -Path (Get-ChildItem -Path $OutputDir -Filter "SignInLogsGraph*.csv").FullName | Sort-Object signInTime -Unique
        $mergedContent | Export-Csv -Path (Join-Path $OutputDir "SignInLogsGraph_Merged.csv") -NoTypeInformation -Encoding $Encoding
    }

    Write-Host "Sign-in logs saved to $outputFile"
}

# Connect to the Microsoft Graph API
$AuthProvider = Get-MgAuthProvider -ClientId "your-client-id" -ClientSecret "your-client-secret" -TenantId "your-tenant-id"
Connect-MgGraph -AuthProvider $AuthProvider -Scopes "AuditLog.Read.All", "Directory.Read.All"

# Call the function to retrieve the sign-in logs
Get-ADSignInLogsGraph -startDate "2023-04-01" -endDate "2023-04-12" -OutputDir "C:\Temp" -MergeOutput
