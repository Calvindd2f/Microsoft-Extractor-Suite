<#
.SYNOPSIS
This script gathers information about user accounts, including creation dates, last password change dates, risky detections, administrator users, and MFA status.

.DESCRIPTION
The script retrieves user information using the Microsoft Graph API and exports the data to CSV files. It also provides options to specify output directories and encoding.

.PARAMETER OutputDir
The output directory where the CSV files will be saved. Default is 'UserInfo' under the current directory.

.PARAMETER Encoding
The encoding of the CSV files. Default is UTF8.

.PARAMETER Application
Specifies App-only access (access without a user) for authentication and authorization. Default is Delegated access (access on behalf a user).

.EXAMPLE
.\UserInfo.ps1

This example retrieves user information without any parameters and saves the output to the 'UserInfo' directory within the current directory.

.EXAMPLE
.\UserInfo.ps1 -OutputDir C:\Temp -Encoding utf32

This example retrieves user information and exports the output to CSV files with UTF-32 encoding in the 'C:\Temp\UserInfo' directory.
#>

[Parameter(Mandatory=$false)]
[string]$OutputDir = "UserInfo"

[Parameter(Mandatory=$false)]
[string]$Encoding = "UTF8"

[Parameter(Mandatory=$false)]
[string]$Application = "Delegated"

# Check if OutputDir exists, create if not
if (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
}
else {
    if ((Test-Path $OutputDir) -and (-not (Test-Path -Path $OutputDir -PathType Container))) {
        Write-Error "OutputDir is not a directory. Please provide a valid directory path."
        exit 1
    }
}

# Connect to Microsoft Graph API
try {
    Connect-MgGraph -Scopes @("User.Read.All", "Directory.AccessAsUser.All", "Directory.Read.All", "IdentityRiskyUser.Read.All", "IdentityRiskEvent.Read.All", "UserAuthenticationMethod.Read.All") -ErrorAction Stop
}
catch {
    Write-Error "Failed to connect to Microsoft Graph API: $_"
    exit 1
}

# Define functions
Function Get-CsvOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$CsvPath,

        [Parameter(Mandatory=$true)]
        [object]$Data
    )

    $CsvPath = Join-Path -Path $OutputDir -ChildPath $CsvPath
    $Data | Export-Csv -Path $CsvPath -Encoding $Encoding -NoTypeInformation
}

Function Get-Users {
    Get-MgUser -Property UserPrincipalName, AccountEnabled, CreatedDateTime, PasswordPolicies, OnPremisesSyncEnabled |
        Select-Object UserPrincipalName, AccountEnabled, CreatedDateTime, PasswordPolicies, OnPremisesSyncEnabled |
        Get-CsvOutput -CsvPath "Users.csv" -Data $_
}

Function Get-AdminUsers {
    $adminRoles = Get-MgRole -Property DisplayName | Where-Object { $_.DisplayName -like "Directory * Administrator" }
    $adminUsers = foreach ($role in $adminRoles) {
        Get-MgRoleMember -RoleId $role.Id | Where-Object { $_.MemberType -eq "User" } | Select-Object DisplayName, UserPrincipalName
    }

    $adminUsers | Get-CsvOutput -CsvPath "AdminUsers.csv" -Data $_
}

Function Get-MFA {
    Get-MgUserAuthenticationMethod -Property UserPrincipalName, AuthenticationMethod |
        Where-Object { $_.AuthenticationMethod -eq "mfa" } |
        Select-Object UserPrincipalName |
        Get-CsvOutput -CsvPath "MFA.csv" -Data $_
}

Function Get-RiskyUsers {
    Get-MgIdentityRiskyUser -Property UserPrincipalName, RiskState, RiskLevel, RiskDetail |
        Where-Object { $_.RiskState -eq "atRisk" } |
        Select-Object UserPrincipalName, RiskState, RiskLevel, RiskDetail |
        Get-CsvOutput -CsvPath "RiskyUsers.csv" -Data $_
}

Function Get-RiskyDetections {
    Get-MgIdentityRiskEvent -Property RiskEventType, RiskState, UserPrincipalName, EventDateTime |
        Where-Object { $_.RiskState -eq "confirmed" } |
        Select-Object RiskEventType, RiskState, UserPrincipalName, EventDateTime |
        Get-CsvOutput -CsvPath "RiskyDetections.csv" -Data $_
}

# Call functions
Try {
    Get-Users
    Get-AdminUsers
    Get-MFA
    Get-RiskyUsers
    Get-RiskyDetections
}
catch {
    Write-Error "An error occurred while retrieving data: $_"
    exit 1
}

Disconnect-MgGraph
