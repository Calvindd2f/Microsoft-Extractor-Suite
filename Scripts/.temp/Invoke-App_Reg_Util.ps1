# Load required modules
try {
    $null = Get-Module -ListAvailable -Name MSOnline -ErrorAction Stop
} catch {
    Install-Module -Name MSOnline -Force -ErrorAction Stop
}

try {
    $null = Get-Module -ListAvailable -Name AzureAD -ErrorAction Stop
} catch {
    Install-Module -Name AzureAD -Force -ErrorAction Stop
}

# Import required modules
Import-Module MSOnline
Import-Module AzureAD

# Define constants
$domain = "lvin.ie"
$database = "AuthMe"
$applicationName = "Partner Application" + " - " + "$database"
$homePage = "https://$domain"
$appIdUrl = "https://$domain/[System.Guid]::NewGuid().ToString()"
$logoutUrl = "https://portal.office.com"
$permissionList = @(
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

    $graphSp = Get-AzureADServicePrincipal -SearchString "Microsoft Graph" -ErrorAction Ignore
    if ($graphSp -eq $null) {
        $graphSp = Get-AzureADServicePrincipal -SearchString "Microsoft.Azure.AgregatorService" -ErrorAction Ignore
    }
    if ($graphSp -eq $null) {
        $credential = Get-Credential
        Login-AzureRmAccount -TenantId $customer.customercontextid -Credential $credential
        New-AzureRmADServicePrincipal -ApplicationId "00000003-0000-0000-c000-000000000000"
        $graphSp = Get-AzureADServicePrincipal -SearchString "Microsoft Graph" -ErrorAction Ignore
    }
    return $graphSp
}

# Confirm-MicrosoftManagementServicePrincipal
function Confirm-MicrosoftManagementServicePrincipal {
    [CmdletBinding()]
    param ()

    $reqSp = Get-AzureADServicePrincipal -SearchString "Office 365 Management APIs" -ErrorAction Ignore
    if ($reqSp -eq $null) {
        $reqSp = Get-AzureADServicePrincipal -SearchString "OfficeManagePlatform" -ErrorAction Ignore
    }
    if ($reqSp -eq $null) {
        $credential = Get-Credential
        Login-AzureRmAccount -TenantId $customer.customercontextid -Credential $credential
        New-AzureRmADServicePrincipal -ApplicationId "5393580-f805-4401-95e8-94b7a6ef2fc2"
        $reqSp = Get-AzureADServicePrincipal -SearchString "Office 365 Management APIs" -ErrorAction Ignore
    }
    return $reqSp
}

# New-AppKey
function New-AppKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [DateTime]$fromDate,
        [Parameter(Mandatory=$true)]
        [int]$durationInYears,
        [Parameter(Mandatory=$true)]
        [string]$pw
    )

    [Parameter(Mandatory=$true)]
    [ValidateScript({ $_ -ge [DateTime]::UtcNow })]
    [DateTime]$fromDate,

    [Parameter(Mandatory=$true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$durationInYears,

    [Parameter(Mandatory=$true)]
    [string]$pw
)

    $endDate = $fromDate.AddYears($durationInYears)
    $keyId = [System.Guid]::NewGuid().ToString()
    $key = [Microsoft.Open.AzureAD.Model.PasswordCredential]::new(
        $null,
        $endDate,
        $keyId,
        $fromDate,
        $pw
    )
    return $key
}

# Initialize-AppKey
function Initialize-AppKey {
    [CmdletBinding()]
    param ()

    $aesManaged = [System.Security.Cryptography.AesManaged]::new()
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    $aesManaged.GenerateKey()
    return [System.Convert]::ToBase64String(
        [System.Text.Encoding]::UTF8.GetBytes($aesManaged.Key)
    )
}

# Test-AppKey
function Test-AppKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [DateTime]$fromDate,
        [Parameter(Mandatory=$true)]
        [int]$durationInYears,
        [Parameter(Mandatory=$true)]
        [string]$pw
    )

    $testKey = New-AppKey -fromDate $fromDate -durationInYears $durationInYears -pw $pw
    while ($testKey.Value -match "\+" -or $testKey.Value -match "/") {
        $pw = Initialize-AppKey
        $testKey = New-AppKey -fromDate $fromDate -durationInYears $durationInYears -pw $pw
    }
    $key = $testKey
    return $key
}

# Get-RequiredPermissions
function Get-RequiredPermissions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$requiredDelegatedPermissions,
        [Parameter(Mandatory=$true)]
        [string]$requiredApplicationPermissions,
        [Parameter(Mandatory=$true)]
        [object]$reqSp
    )

    [Parameter(Mandatory=$true)]
    [string]$requiredDelegatedPermissions,

    [Parameter(Mandatory=$true)]
    [string]$requiredApplicationPermissions,

    [Parameter(Mandatory=$true)]
    [object]$reqSp
)

    $sp = $reqSp
    $appId = $sp.AppId
    $requiredAccess = [Microsoft.Open.AzureAD.Model.RequiredResourceAccess]::new()
    $requiredAccess.ResourceAppId = $appId
    $requiredAccess.ResourceAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]
    if ($requiredDelegatedPermissions) {
        $requiredAccess.ResourceAccess.Add(
            Add-ResourcePermission -exposedPermissions $sp.Oauth2Permissions -requiredAccesses $requiredDelegatedPermissions -permissionType "Scope"
        )
    }
    if ($requiredApplicationPermissions) {
        $requiredAccess.ResourceAccess.Add(
            Add-ResourcePermission -exposedPermissions $sp.AppRoles -requiredAccesses $requiredApplicationPermissions -permissionType "Role"
        )
    }
    return $requiredAccess
}

# Add-ResourcePermission
function Add-ResourcePermission {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [object]$requiredAccess,
        [Parameter(Mandatory=$true)]
        [object]$exposedPermissions,
        [Parameter(Mandatory=$true)]
        [object]$requiredAccesses,
        [Parameter(Mandatory=$true)]
        [string]$permissionType
    )

    [Parameter(Mandatory=$true)]
    [object]$requiredAccess,

    [Parameter(Mandatory=$true)]
    [object]$exposedPermissions,

    [Parameter(Mandatory=$true)]
    [object]$requiredAccesses,

    [Parameter(Mandatory=$true)]
    [string]$permissionType
)

    $resourceAccess = [Microsoft.Open.AzureAD.Model.ResourceAccess]::new()
    $resourceAccess.Type = $permissionType
    $resourceAccess.Id = $exposedPermissions | Where-Object { $_.Value -contains $requiredAccesses } | Select-Object -ExpandProperty Id
    return $resourceAccess
}

# Write-Error
function Write-Error {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$message
    )

    [Parameter(Mandatory=$true)]
    [string]$message

    Write-Host ""
    Write-Host "*************************************************************************************" -ForegroundColor Red
    Write-Host ""
    Write-Host $message -ForegroundColor Red
    Write-Host ""
    Write-Host "*************************************************************************************" -ForegroundColor Red
}

# Write-Update
function Write-Update {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$message
    )

    [Parameter(Mandatory=$true)]
    [string]$message

    Write-Host $message -ForegroundColor Green
}

# Verify-Modules
function Verify-Modules {
    [CmdletBinding()]
    param ()

    try {
        Write-Host "Verifying MSOnline Module" -ForegroundColor Green
        if (-not (Get-Module -ListAvailable -Name MSOnline)) {
            Install-Module -Name MSOnline -Force -ErrorAction Stop
        }
        Write-Host "Verifying AzureAD Module" -ForegroundColor Green
        if (-not (Get-Module -ListAvailable -Name AzureAD)) {
            Install-Module -Name AzureAD -Force -ErrorAction Stop
        }
        return $true
    } catch {
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

$prompt = Read-Host -Prompt "Specify domain or press Enter for default ($domain)"
if ($prompt -ne "") {
    $domain = $prompt
    $homePage = "https://$domain"
    $appIdUrl = "https://$domain/[System.Guid]::NewGuid().ToString()"
}

$success = Verify-Modules

if ($success) {
    $credential = Get-Credential
    Connect-AzureAD -Credential $credential

    $adminAgentsGroup = Get-AzureADGroup -Filter "displayName eq 'Adminagents'" -ErrorAction Ignore
    if ($null -eq $adminAgentsGroup) {
        Write-Error "This account is not setup as a Microsoft Partner"
        $success = $false
    }
}

if ($success) {
    Write-Update "Checking for Microsoft Graph Service Principal"
    $graphSp = Confirm-MicrosoftGraphServicePrincipal
    $graphSp = $graphSp[0]
    $reqSp = Confirm-MicrosoftManagementServicePrincipal

    Write-Update "Checking for Existing Application"
    $existingApp = Get-AzureADApplication -SearchString $applicationName -ErrorAction Ignore
    if ($existingApp) {
        Write-Update "Removing Existing Application"
        Remove-Azureadapplication -ObjectId $existingApp.objectId -Confirm:$False
        $existingApp = $null
    }

    Write-Update "Installing Application"

    $requiredResourcesAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.RequiredResourceAccess]
    $microsoftGraphRequiredPermissions = Get-RequiredPermissions -requiredDelegatedPermissions $permissionList -requiredApplicationPermissions $permissionList -reqSp $graphSp
    $requiredResourcesAccess.Add($microsoftGraphRequiredPermissions)

    $pw = Initialize-AppKey
    $fromDate = [System.DateTime]::UtcNow
    $appKey = Test-AppKey -fromDate $fromDate -durationInYears 99 -pw $pw

    $params = @{
        DisplayName = $applicationName
        HomePage = $homePage
        ReplyUrls = @($homePage)
        IdentifierUris = @($appIdUrl)
        LogoutUrl = $logoutUrl
        RequiredResourceAccess = $requiredResourcesAccess
        PasswordCredentials = @($appKey)
        AvailableToOtherTenants = $true
    }

    Write-Update "Creating the application: $($params.DisplayName)"
    $app = New-AzureADApplication @params -WhatIf

    $params = @{
        AppId = $app.AppId
    }

    $servicePrincipal = New-AzureADServicePrincipal @params

    Write-Update "Assigning Permissions"

    foreach ($app in $requiredResourcesAccess) {
        $reqAppSp = $null
        $reqAppSp = New-AzureADApplication -AppId $app.ResourceAppId -RequiredResourceAccess $app.ResourceAccess
        Add-AzureADApplicationPermission -Id $app.ResourceAppId -Type $app.ResourceAccess.Type -PermissionId $app.ResourceAccess.Id
    }

    Write-Update "Assigning Application to Admin Agents Group"
    Add-AzureADGroupMember -ObjectId $adminAgentsGroup.ObjectId -RefObjectId $servicePrincipal.ObjectId

    Write-Update "Application Installed Successfully"
    Write-Host ""
    Write-Host "To complete your teamserver setup, use the following values:" -ForegroundColor Green
    Write-Host "Application ID: $($app.AppId)" -ForegroundColor Green
    Write-Host "Application Key: $($appKey.Value)" -ForegroundColor Green
    Write-Host ""
}
