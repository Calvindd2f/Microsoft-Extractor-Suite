# Load required modules
$MSOnlineModule = Get-Module -ListAvailable -Name MSOnline -ErrorAction SilentlyContinue
if ($MSOnlineModule -eq $null) {
    Install-Module -Name MSOnline -Force
}

$AzureADModule = Get-Module -ListAvailable -Name AzureAD -ErrorAction SilentlyContinue
if ($AzureADModule -eq $null) {
    Install-Module -Name AzureAD -Force
}

# Import required modules
Import-Module MSOnline
Import-Module AzureAD

# Define constants
$Domain = "lvin.ie"
$Database = "AuthMe"
$ApplicationName = "Partner Application" + " - " + "$Database"
$HomePage = "https://" + $Domain
$AppIdURL = "https://" + $Domain + "/$((New-Guid).ToString())"
$LogoutURL = "https://portal.office.com"
$PermissionList = @(
    "Directory.AccessAsUser.All",
    "Mail.Read",
    "offline_access",
    "AppCatalog.ReadWrite.All",
    "AuditLog.Read.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementRBAC.ReadWrite.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "Calendars.ReadWrite.Shared",
    "User.Read",
    "Group.ReadWrite.All",
    "Mail.Send",
    "IdentityRiskEvent.Read.All",
    "AppRoleAssignment.ReadWrite.All",
    "BitlockerKey.Read.All",
    "UserAuthenticationMethod.ReadWrite.All",
    "ConsentRequest.ReadWrite.All",
    "Chat.ReadWrite",
    "ChatMessage.Send",
    "ChannelMessage.Read.All",
    "Device.ReadWrite.All",
    "User.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All",
    "WindowsUpdates.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Group.ReadWrite.All",
    "DeviceManagementServiceConfig.ReadWrite.All",
    "TeamMember.ReadWrite.All",
    "Organization.ReadWrite.All",
    "ConsentRequest.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.ManageIdentities.All",
    "MailboxSettings.ReadWrite",
    "ChannelMember.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "GroupMember.ReadWrite.All",
    "IdentityRiskEvent.Read.All",
    "AdministrativeUnit.ReadWrite.All",
    "AuditLog.Read.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "ServiceHealth.Read.All",
    "DeviceManagementRBAC.ReadWrite.All"
)

# Define functions

# Confirm-MicrosoftGraphServicePrincipal
function Confirm-MicrosoftGraphServicePrincipal {
    [CmdletBinding()]
    param ()

    $GraphSP = Get-AzureADServicePrincipal -SearchString "Microsoft Graph" -ErrorAction Ignore
    if ($GraphSP -eq $null) {
        $GraphSP = Get-AzureADServicePrincipal -SearchString "Microsoft.Azure.AgregatorService" -ErrorAction Ignore
    }
    if ($GraphSP -eq $null) {
        $Credential = Get-Credential
        Login-AzureRmAccount -TenantId $customer.customercontextid -Credential $Credential
        New-AzureRmADServicePrincipal -ApplicationId "00000003-0000-0000-c000-000000000000"
        $GraphSP = Get-AzureADServicePrincipal -SearchString "Microsoft Graph" -ErrorAction Ignore
    }
    return $GraphSP
}

# Confirm-MicrosoftManagementServicePrincipal
function Confirm-MicrosoftManagementServicePrincipal {
    [CmdletBinding()]
    param ()

    $ReqSP = Get-AzureADServicePrincipal -SearchString "Office 365 Management APIs" -ErrorAction Ignore
    if ($ReqSP -eq $null) {
        $ReqSP = Get-AzureADServicePrincipal -SearchString "OfficeManagePlatform" -ErrorAction Ignore
    }
    if ($ReqSP -eq $null) {
        $Credential = Get-Credential
        Login-AzureRmAccount -TenantId $customer.customercontextid -Credential $Credential
        New-AzureRmADServicePrincipal -ApplicationId "5393580-f805-4401-95e8-94b7a6ef2fc2"
        $ReqSP = Get-AzureADServicePrincipal -SearchString "Office 365 Management APIs" -ErrorAction Ignore
    }
    return $ReqSP
}

# New-AppKey
function New-AppKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [DateTime]$FromDate,
        [Parameter(Mandatory=$true)]
        [int]$DurationInYears,
        [Parameter(Mandatory=$true)]
        [string]$Pw
    )

    $EndDate = $FromDate.AddYears($DurationInYears)
    $KeyId = (New-Guid).ToString()
    $Key = New-Object Microsoft.Open.AzureAD.Model.PasswordCredential($null, $EndDate, $KeyId, $FromDate, $Pw)
    return $Key
}

# Initialize-AppKey
function Initialize-AppKey {
    [CmdletBinding()]
    param ()

    $AesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $AesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $AesManaged.BlockSize = 128
    $AesManaged.KeySize = 256
    $AesManaged.GenerateKey()
    return [System.Convert]::ToBase64String($AesManaged.Key)
}

# Test-AppKey
function Test-AppKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [DateTime]$FromDate,
        [Parameter(Mandatory=$true)]
        [int]$DurationInYears,
        [Parameter(Mandatory=$true)]
        [string]$Pw
    )

    $TestKey = New-AppKey -FromDate $FromDate -DurationInYears $DurationInYears -Pw $Pw
    while ($TestKey.Value -match "\+" -or $TestKey.Value -match "/") {
        $Pw = Initialize-AppKey
        $TestKey = New-AppKey -FromDate $FromDate -DurationInYears $DurationInYears -Pw $Pw
    }
    $Key = $TestKey
    return $Key
}

# Get-RequiredPermissions
function Get-RequiredPermissions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$RequiredDelegatedPermissions,
        [Parameter(Mandatory=$true)]
        [string]$RequiredApplicationPermissions,
        [Parameter(Mandatory=$true)]
        [object]$ReqSP
    )

    $SP = $ReqSP
    $AppId = $SP.AppId
    $RequiredAccess = New-Object Microsoft.Open.AzureAD.Model.RequiredResourceAccess
    $RequiredAccess.ResourceAppId = $AppId
    $RequiredAccess.ResourceAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]
    if ($RequiredDelegatedPermissions) {
        Add-ResourcePermission $RequiredAccess -ExposedPermissions $SP.Oauth2Permissions -RequiredAccesses $RequiredDelegatedPermissions -PermissionType "Scope"
    }
    if ($RequiredApplicationPermissions) {
        Add-ResourcePermission $RequiredAccess -ExposedPermissions $SP.AppRoles -RequiredAccesses $RequiredApplicationPermissions -PermissionType "Role"
    }
    return $RequiredAccess
}

# Add-ResourcePermission
function Add-ResourcePermission {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [object]$RequiredAccess,
        [Parameter(Mandatory=$true)]
        [object]$ExposedPermissions,
        [Parameter(Mandatory=$true)]
        [object]$RequiredAccesses,
        [Parameter(Mandatory=$true)]
        [string]$PermissionType
    )

    foreach ($Permission in $RequiredAccesses.Trim().Split(" ")) {
        $ReqPermission = $null
        $ReqPermission = $ExposedPermissions | Where-Object {$_.Value -contains $Permission}
        $ResourceAccess = New-Object Microsoft.Open.AzureAD.Model.ResourceAccess
        $ResourceAccess.Type = $PermissionType
        $ResourceAccess.Id = $ReqPermission.Id
        $RequiredAccess.ResourceAccess.Add($ResourceAccess)
    }
}

# Write-Error
function Write-Error {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    Write-Host ""
    Write-Host "*************************************************************************************" -ForegroundColor Red
    Write-Host ""
    Write-Host $Message -ForegroundColor Red
    Write-Host ""
    Write-Host "*************************************************************************************" -ForegroundColor Red
}

# Write-Update
function Write-Update {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    Write-Host $Message -ForegroundColor Green
}

# Verify-Modules
function Verify-Modules {
    [CmdletBinding()]
    param ()

    try {
        Write-Host "Verifying MSOnline Module" -ForegroundColor Green
        if (-not (Get-Module -ListAvailable -Name MSOnline)) {
            Install-Module -Name MSOnline -Force
        }
        Write-Host "Verifying AzureAD Module" -ForegroundColor Green
        if (-not (Get-Module -ListAvailable -Name AzureAD)) {
            Install-Module -Name AzureAD -Force
        }
        return $true
    }
    catch {
        return $false
    }
}

# Main script

Write-Host "┌────────────────────────────────────────────────────────┐"
Write-Host "│ Calvindd2fs SIMPLIFIED Az APPLICATION                  │"
Write-Host "│ VERSION 3 - All below turned into function             │"
Write-Host "│                                                        │"
Write-Host "└────────────────────────────────────────────────────────┘"
Write-Host ""
Write-Host "Instructions" -ForegroundColor Green
Write-Host "This script will install the application in your partner tenant."
Write-Host "After it completes, you will be given the values to complete your teamserver setup."
Write-Host "If you rerun this application in the future, you will need to update your teamserver settings."
Write-Host "More information at https://cpaq.it/Canary.txt"
Write-Host ""

$Prompt = Read-Host -Prompt "Specify domain or press Enter for default ($Domain)"
if ($Prompt -ne "") {
    $Domain = $Prompt
    $HomePage = "https://" + $Domain
    $AppIdURL = "https://" + $Domain + "/$((New-Guid).ToString())"
}

$Success = Verify-Modules

if ($Success) {
    $Credential = Get-Credential
    Connect-AzureAD -Credential $Credential

    $AdminAgentsGroup = Get-AzureADGroup -Filter "displayName eq 'Adminagents'" -ErrorAction Ignore
    if ($null -eq $AdminAgentsGroup) {
        Write-Error "This account is not setup as a Microsoft Partner"
        $Success = $false
    }
}

if ($Success) {
    Write-Update "Checking for Microsoft Graph Service Principal"
    $GraphSP = Confirm-MicrosoftGraphServicePrincipal
    $GraphSP = $GraphSP[0]
    $ReqSP = Confirm-MicrosoftManagementServicePrincipal

    Write-Update "Checking for Existing Application"
    $ExistingApp = Get-AzureADApplication -SearchString $ApplicationName -ErrorAction Ignore
    if ($ExistingApp) {
        Write-Update "Removing Existing Application"
        Remove-Azureadapplication -ObjectId $ExistingApp.objectId -Confirm:$False
        $ExistingApp = $null
    }

    Write-Update "Installing Application"

    $RequiredResourcesAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.RequiredResourceAccess]
    $MicrosoftGraphRequiredPermissions = Get-RequiredPermissions -RequiredDelegatedPermissions $PermissionList -RequiredApplicationPermissions $PermissionList -ReqSP $GraphSP
    $RequiredResourcesAccess.Add($MicrosoftGraphRequiredPermissions)

    $Pw = Initialize-AppKey
    $FromDate = [System.DateTime]::Now
    $AppKey = Test-AppKey -FromDate $FromDate -DurationInYears 99 -Pw $Pw

    $Params = @{
        DisplayName = $ApplicationName
        HomePage = $HomePage
        ReplyUrls = @($HomePage)
        IdentifierUris = @($AppIdURL)
        LogoutUrl = $LogoutURL
        RequiredResourceAccess = $RequiredResourcesAccess
        PasswordCredentials = @($AppKey)
        AvailableToOtherTenants = $true
    }

    Write-Update "Creating the application: $($Params.DisplayName)"
    $App = New-AzureADApplication @Params -WhatIf

    $Params = @{
        AppId = $App.AppId
    }

    $ServicePrincipal = New-AzureADServicePrincipal @Params

    Write-Update "Assigning Permissions"

    foreach ($App in $RequiredResourcesAccess) {
        $ReqAppSP = $
