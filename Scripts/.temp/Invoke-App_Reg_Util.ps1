. "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";
<#┌────────────────────────────────────────────────────────┐
  │ Calvin appreg Workflow [Create,ApplyPerms,SPOs,GDAP]   │
  │ VERSION 3 - Released Sept 1 , 2023                     │
  │ Calvindd2f                                             │
  └────────────────────────────────────────────────────────┘#>

# The permission User.ReadWrite.All is optional in the list of permissions defined in the variable $permissionList.
# User.ReadWrite.All may be removed, but users or admins will not be able to update Office 365 details from within application.
$permissions = @("Directory.AccessAsUser.All,Mail.Read,offline_access,AppCatalog.ReadWrite.All,AuditLog.Read.All,DeviceManagementConfiguration.ReadWrite.All,DeviceManagementRBAC.ReadWrite.All,DeviceManagementManagedDevices.PrivilegedOperations.All,Calendars.ReadWrite.Shared,User.Read,Group.ReadWrite.All,Mail.Send,IdentityRiskEvent.Read.All,AppRoleAssignment.ReadWrite.All,BitlockerKey.Read.All,UserAuthenticationMethod.ReadWrite.All,ConsentRequest.ReadWrite.All,Chat.ReadWrite,ChatMessage.Send,ChannelMessage.Read.All,Device.ReadWrite.All,User.ReadWrite.All,UserAuthenticationMethod.ReadWrite.All,WindowsUpdates.ReadWrite.All,Directory.ReadWrite.All,Group.ReadWrite.All,DeviceManagementServiceConfig.ReadWrite.All,TeamMember.ReadWrite.All,Organization.ReadWrite.All,ConsentRequest.ReadWrite.All,AppRoleAssignment.ReadWrite.All,User.ManageIdentities.All,MailboxSettings.ReadWrite,ChannelMember.ReadWrite.All,RoleManagement.ReadWrite.Directory,GroupMember.ReadWrite.All,IdentityRiskEvent.Read.All,AdministrativeUnit.ReadWrite.All,AuditLog.Read.All,DeviceManagementConfiguration.ReadWrite.All,DeviceManagementManagedDevices.PrivilegedOperations.All,ServiceHealth.Read.All,DeviceManagementRBAC.ReadWrite.All")
$domain = "lvin.ie"
$database = "AuthMe"
$permissionList = $permissions
$applicationName = "Partner Application"+" - "+"$database"
$homePage = "https://" + $domain
$appIdURL = "https://" + $domain + "/$((New-Guid).ToString())"
$logoutURL = "https://portal.office.com"

# historical changes are in Calvindd2f\Proactive_issues

Function Confirm-MicrosoftGraphServicePrincipal {
    $graphsp = Get-AzureADServicePrincipal -SearchString "Microsoft Graph"
    if (!$graphsp) {
        $graphsp = Get-AzureADServicePrincipal -SearchString "Microsoft.Azure.AgregatorService"
    }
    if (!$graphsp) {
        Login-AzureRmAccount -Credential $Credential
        New-AzureRmADServicePrincipal -ApplicationId "00000003-0000-0000-c000-000000000000"
        $graphsp = Get-AzureADServicePrincipal -SearchString "Microsoft Graph"
    }
    return $graphsp
}

Function Confirm-MicrosoftManagementServicePrincial {
    $reqSP = -SearchString "Office 365 Management APIs"
    if (!$reqSP) {
        $reqSP = Get-AzureADServicePrincipal -SearchString "OfficeManagePlatform"
    }
    if (!$reqSP) {
        Login-AzureRmAccount -TenantId $customer.customercontextid -Credential $credentials
        New-AzureRmADServicePrincipal -ApplicationId "5393580-f805-4401-95e8-94b7a6ef2fc2"
        $reqSP = Get-AzureADServicePrincipal -SearchString "Office 365 Management APIs"
    }
    return $reqSP
}

Function New-AppKey ($fromDate, $durationInYears, $pw) {
    $endDate = $fromDate.AddYears($durationInYears)
    $keyId = (New-Guid).ToString()
    $key = New-Object Microsoft.Open.AzureAD.Model.PasswordCredential($null, $endDate, $keyId, $fromDate, $pw)
    return $key
}

Function Initialize-AppKey {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    $aesManaged.GenerateKey()
    return [System.Convert]::ToBase64String($aesManaged.Key)
}

Function Test-AppKey($fromDate, $durationInYears, $pw) {
    $testKey = New-AppKey -fromDate $fromDate -durationInYears $durationInYears -pw $pw
    while ($testKey.Value -match "\+" -or $testKey.Value -match "/") {
        $pw = Initialize-AppKey
        $testKey = New-AppKey -fromDate $fromDate -durationInYears $durationInYears -pw $pw
    }
    $key = $testKey
    return $key
}

Function Get-RequiredPermissions($requiredDelegatedPermissions, $requiredApplicationPermissions, $reqsp) {
    $sp = $reqsp
    $appid = $sp.AppId
    $requiredAccess = New-Object Microsoft.Open.AzureAD.Model.RequiredResourceAccess
    $requiredAccess.ResourceAppId = $appid
    $requiredAccess.ResourceAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]
    if ($requiredDelegatedPermissions) {
        Add-ResourcePermission $requiredAccess -exposedPermissions $sp.Oauth2Permissions -requiredAccesses $requiredDelegatedPermissions -permissionType "Scope"
    }
    if ($requiredApplicationPermissions) {
        Add-ResourcePermission $requiredAccess -exposedPermissions $sp.AppRoles -requiredAccesses $requiredApplicationPermissions -permissionType "Role"
    }
    return $requiredAccess
}

Function Add-ResourcePermission($requiredAccess, $exposedPermissions, $requiredAccesses, $permissionType) {
    foreach ($permission in $requiredAccesses.Trim().Split(" ")) {
        $reqPermission = $null
        $reqPermission = $exposedPermissions | Where-Object {$_.Value -contains $permission}
        $resourceAccess = New-Object Microsoft.Open.AzureAD.Model.ResourceAccess
        $resourceAccess.Type = $permissionType
        $resourceAccess.Id = $reqPermission.Id
        $requiredAccess.ResourceAccess.Add($resourceAccess)
    }
}

Function Write-Error($message) {
    Write-Host ""
    Write-Host "*************************************************************************************" -ForegroundColor Red
    Write-Host ""
    Write-Host $message -ForegroundColor Red
    Write-Host ""
    Write-Host "*************************************************************************************" -ForegroundColor Red
}

Function Write-Update($message) {
    Write-Host $message -ForegroundColor Green
}

Function Verify-Modules {
    try {
		Write-Host "Verifying MSOnline Module" -ForegroundColor Green
		if (Get-Module -ListAvailable -Name MSOnline) {
		}
		else {
			Install-Module -Name MSOnline
		}
		Write-Host "Verifying AzureAD Module" -ForegroundColor Green
		if (Get-Module -ListAvailable -Name AzureAD) {
		}
		else {
			Install-Module -Name AzureAD
		}
		return $True
	}
	catch {
		return $False
	}
}



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
$prompt = ""
$prompt = Read-Host -Prompt "Specify domain or press Enter for default ($domain)"
if ($prompt -ne "") {
	$domain = $prompt
    $homePage = "https://" + $domain
    $appIdURL = "https://" + $domain + "/$((New-Guid).ToString())"
}

Write-Host ""
$success = Verify-Modules

if ($success -eq $True) {
	Import-module MSOnline
	Write-Host ""
	Write-Host "You will now be prompted for your log in. Log in as a Global Administrator for the following domain: "
	Write-Host ""
	Write-Host $domain -ForegroundColor Green
	Write-Host ""
	Connect-AzureAD
	$adminAgentsGroup = Get-AzureADGroup -Filter "displayName eq 'Adminagents'"
	if ($null -eq $adminAgentsGroup) {
		Write-Error "This account is not setup as a Microsoft Partner"
		#$success = $False
  		$success = $True
	}
}
else {
		Write-Error "Rerun this script as an administrator to install the required modules."
}

if ($success -eq $True) {
    Write-Update "Checking for Microsoft Graph Service Principal"
    $graphsp = Confirm-MicrosoftGraphServicePrincipal
    $graphsp = $graphsp[0]
    $reqSP = Confirm-MicrosoftManagementServicePrincial

    Write-Update "Checking for Existing Application"
    $existingapp = $null
    $existingapp = Get-AzureADApplication -SearchString $applicationName
    if ($existingapp) {
        Write-Update "Removing Existing Application"
        Remove-Azureadapplication -ObjectId $existingApp.objectId
        $existingapp = $null
    }

    Write-Update "Installing Application"

    $rsps = @()
    if ($reqSP -and $graphsp -and ($null -eq $existingapp)) {
        $rsps += $graphsp
        $tenantInfo = Get-AzureADTenantDetail
        $tenant_id = $tenantInfo.ObjectId
        $initialDomain = ($tenantInfo.verifiedDomains | Where-Object {$_.Initial}).name

        $requiredResourcesAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.RequiredResourceAccess]
        $microsoftGraphRequiredPermissions = Get-RequiredPermissions -reqsp $graphsp -requiredApplicationPermissions $permissionList -requiredDelegatedPermissions $DelegatedPermissions
        $requiredResourcesAccess.Add($microsoftGraphRequiredPermissions)

        $pw = Initialize-AppKey
        $fromDate = [System.DateTime]::Now
        $appKey = Test-AppKey -fromDate $fromDate -durationInYears 99 -pw $pw

        Write-Update "Creating the application: $applicationName"
        $aadApplication = New-AzureADApplication -DisplayName $applicationName `
            -HomePage $homePage `
            -ReplyUrls $homePage `
            -IdentifierUris $appIdURL `
            -LogoutUrl $logoutURL `
            -RequiredResourceAccess $requiredResourcesAccess `
            -PasswordCredentials $appKey `
            -AvailableToOtherTenants $true

        $servicePrincipal = New-AzureADServicePrincipal -AppId $aadApplication.AppId

        Write-Update "Assigning Permissions"

        foreach ($app in $requiredResourcesAccess) {
            $reqAppSP = $rsps | Where-Object {$_.appid -contains $app.ResourceAppId}
            Write-Update "Assigning permissions for $($reqAppSP.displayName)"
            foreach ($resource in $app.ResourceAccess) {
                if ($resource.Type -match "Role") {
                    $success = 0
                    try {
                        New-AzureADServiceAppRoleAssignment -ObjectId $serviceprincipal.ObjectId `
                            -PrincipalId $serviceprincipal.ObjectId -ResourceId $reqAppSP.ObjectId -Id $resource.Id
                        $success = 1
                    }
                    catch { }
                    if ($success -eq 0) {
                        try {
                            New-AzureADServiceAppRoleAssignment -ObjectId $serviceprincipal.ObjectId `
                                -PrincipalId $serviceprincipal.ObjectId -ResourceId $reqSP.ObjectId -Id $resource.Id
                      }
                      catch {}
                    }
                }
            }
        }

        Add-AzureADGroupMember -ObjectId $adminAgentsGroup.ObjectId -RefObjectId $servicePrincipal.ObjectId
        Write-Update "Application Created"
        Write-Host ""
        Write-Host ""
        Write-Host "Copy these values to Bitwarden or equivilant... maybe not lastpass lol."
        Write-Host ""
        Write-Host ""
        Write-Host "AppId:"
        Write-Host $aadApplication.AppId -ForegroundColor Green
        Write-Host ""
        Write-Host "AppSecret:"
        Write-Host $appKey.Value -ForegroundColor Green
        Write-Host ""
        Write-Host "TenantId:"
        Write-Host $tenant_id -ForegroundColor Green
        Write-Host ""
        Write-Host "Realm:"
        Write-Host $initialDomain -ForegroundColor Green
        Write-Host ""
        Write-Host ""
        Write-Update "Application configuration detailed."

        Get-PSSession | Remove-PSSession
    }
}
