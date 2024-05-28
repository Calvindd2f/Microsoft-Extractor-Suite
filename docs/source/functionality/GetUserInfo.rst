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
    New-Item -ItemType Directory -Force -Path $OutputDir
}

# Connect to Microsoft Graph API
Connect-MgGraph -Scopes @("User.Read.All", "Directory.AccessAsUser.All", "Directory.Read.All", "IdentityRiskyUser.Read.All", "IdentityRiskEvent.Read.All", "UserAuthenticationMethod.Read.All")

# Get users
Function Get-Users {
    Get-MgUser -Property UserPrincipalName, AccountEnabled, CreatedDateTime, PasswordPolicies, OnPremisesSyncEnabled | Select-Object UserPrincipalName, AccountEnabled, CreatedDateTime, PasswordPolicies, OnPremisesSyncEnabled | Export-Csv -Path "$OutputDir\Users.csv" -Encoding $Encoding -NoTypeInformation
}

# Get administrator directory roles
Function Get-AdminUsers {
    $adminRoles = Get-MgRole -Property DisplayName | Where-Object { $_.DisplayName -like "Directory * Administrator" }
    $adminUsers = @()
    foreach ($role in $adminRoles) {
        $adminUsers += Get-MgRoleMember -RoleId $role.Id | Where-Object { $_.MemberType -eq "User" } | Select-Object DisplayName, UserPrincipalName
    }
    $adminUsers | Export-Csv -Path "$OutputDir\AdminUsers.csv" -Encoding $Encoding -NoTypeInformation
}

# Get MFA status
Function Get-MFA {
    Get-MgUserAuthenticationMethod -Property UserPrincipalName, AuthenticationMethod | Where-Object { $_.AuthenticationMethod -eq "mfa" } | Select-Object UserPrincipalName | Export-Csv -Path "$OutputDir\MFA.csv" -Encoding $Encoding -NoTypeInformation
}

# Get risky users
Function Get-RiskyUsers {
    Get-MgIdentityRiskyUser -Property UserPrincipalName, RiskState, RiskLevel, RiskDetail | Where-Object { $_.RiskState -eq "atRisk" } | Select-Object UserPrincipalName, RiskState, RiskLevel, RiskDetail | Export-Csv -Path "$OutputDir\RiskyUsers.csv" -Encoding $Encoding -NoTypeInformation
}

# Get risky detections
Function Get-RiskyDetections {
    Get-MgIdentityRiskEvent -Property RiskEventType, RiskState, UserPrincipalName, EventDateTime | Where-Object { $_.RiskState -eq "confirmed" } | Select-Object RiskEventType, RiskState, UserPrincipalName, EventDateTime | Export-Csv -Path "$OutputDir\RiskyDetections.csv" -Encoding $Encoding -NoTypeInformation
}

# Call functions
Get-Users
Get-AdminUsers
Get-MFA
Get-RiskyUsers
Get-RiskyDetections

Disconnect-MgGraph
