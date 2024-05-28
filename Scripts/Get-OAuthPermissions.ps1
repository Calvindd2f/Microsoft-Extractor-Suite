function Get-TenantDetails {
    [CmdletBinding()]
    param()
    try {
        return Get-AzureADTenantDetail -ErrorAction stop
    }
    catch {
        Write-LogFile -Message "[WARNING] You must call Connect-Azure before running this script" -Color "Red"
        break
    }
}

function Get-ObjectDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectId,
        [string]$ObjectClass = 'ServicePrincipal'
    )
    try {
        $servicePrincipal = Get-AzureADObjectByClassAndId -Class $ObjectClass -Id $ObjectId -ErrorAction stop
        $Output = New-Object PSObject -Property @{
            Homepage         = $servicePrincipal.Homepage
            PublisherName   = $servicePrincipal.PublisherName
            ReplyUrls        = $servicePrincipal.ReplyUrls -join ', '
            AppDisplayName  = $servicePrincipal.AppDisplayName
            AppId            = $servicePrincipal.AppId
        }
        return $Output
    }
    catch {
        Write-LogFile -Message ("Error retrieving {0} with ObjectId {1}: {2}" -f $ObjectClass, $ObjectId, $_.Exception.Message) -Color "Red"
        return $null
    }
}

function Cache-Object {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object
    )
    $ObjectClass = $Object.GetType().Name
    $ObjectId = $Object.ObjectId
    if ($null -eq $script:ObjectByObjectId[$ObjectId]) {
        $script:ObjectByObjectId[$ObjectId] = $Object
        $script:ObjectByObjectClassId[$ObjectClass].Add($ObjectId, $Object)
    }
}

function Get-OAuth2PermissionGrants {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$FastMode
    )
    try {
        $query = "oauth2PermissionGrants"
        if ($FastMode) {
            $query += "?`$top=999"
        }
        $response = Invoke-RestMethod -Uri "https://graph.windows.net/$($tenant.TenantId)/$query" -Headers $headers -Method GET
        return $response.value
    }
    catch {
        Write-LogFile -Message ("Error retrieving OAuth2 permission grants: {0}" -f $_.Exception.Message) -Color "Red"
        return $null
    }
}

function Convert-OutputToCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Output
    )
    $prop = $Output.ForEach{ $_.PSObject.Properties.Name } | Select-Object -Unique
    $Output | Select-Object $prop | ConvertTo-Csv -NoTypeInformation | Format-Table | Out-Null
}

function Write-LogFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Color = 'White'
    )
    Write-Host $Message -ForegroundColor $Color
}

<#
.SYNOPSIS
Gets the OAuth permissions for the specified tenant.

.DESCRIPTION
This function retrieves the OAuth permissions for the specified tenant,
including delegated and application permissions, and saves them to a CSV file.

.PARAMETER DelegatedPermissions
Specifies whether to include delegated permissions in the output.

.PARAMETER ApplicationPermissions
Specifies whether to include application permissions in the output.

.PARAMETER UserProperties
Specifies the properties of the user object to include in the output.

.PARAMETER ServicePrincipalProperties
Specifies the properties of the service principal object to include in the output.

.PARAMETER ShowProgress
Specifies whether to show the progress of the function.

.PARAMETER PrecacheSize
Specifies the number of objects to precache in one API call.

.PARAMETER OutputDir
Specifies the directory to save the output CSV file.

.PARAMETER Encoding
Specifies the encoding of the output CSV file.

.EXAMPLE
Get-OAuthPermissions -DelegatedPermissions -ApplicationPermissions

This example retrieves all the OAuth permissions for the current tenant,
including delegated and application permissions, and saves them to a CSV file.

.EXAMPLE
Get-OAuthPermissions -DelegatedPermissions -UserProperties DisplayName,Mail -ServicePrincipalProperties DisplayName,AppId

This example retrieves only the delegated OAuth permissions for the current tenant,
and includes the DisplayName and Mail properties of the user object,
and the DisplayName and AppId properties of the service principal object in the output,
and saves them to a CSV file.
#>
function Get-OAuthPermissions {
    [CmdletBinding()]
    param(
        [switch] $DelegatedPermissions,
        [switch] $ApplicationPermissions,
        [string[]] $UserProperties = @('DisplayName'),
        [string[]] $ServicePrincipalProperties = @('DisplayName'),
        [switch] $ShowProgress = $true,
        [int] $PrecacheSize = 999,
        [string] $OutputDir = "Output\OAuthPermissions",
        [string] $Encoding = "UTF8"
    )
    # Validate and initialize the input parameters
    if (-not (Get-Module AzureAD -ErrorAction SilentlyContinue)) {
        Write-LogFile -Message "[ERROR] You must install the AzureAD module before running this script" -Color "Red"
        return
    }
    if (-not $PSCmdlet.SessionState.PSVariable.Get('tenant').Value) {
        Write-LogFile -Message "[ERROR] You must call Connect-Azure before running this script" -Color "Red"
        return
    }
    $tenant = Get-TenantDetails
    if (-not $tenant) {
        return
    }
    $headers = @{
        'Authorization' = "Bearer $((Connect-Azure -TenantId $tenant.TenantId).AccessToken)"
    }
    $script:ObjectByObjectId = @{}
    $script:ObjectByObjectClassId = @{
        'User' = @{}
        'ServicePrincipal' = @{}
    }

    # Get all ServicePrincipal objects and add to the cache
    Write-Verbose "Retrieving all ServicePrincipal objects..."
    Get-AzureADServicePrincipal -All $true | ForEach-Object {
        Cache-Object -Object $_
    }
    $servicePrincipalCount = $script:ObjectByObjectClassId['ServicePrincipal'].Count

    if ($DelegatedPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {

        # Get one page of User objects and add to the cache
        Write-Verbose ("Retrieving up to {0} User objects..." -f $PrecacheSize)
        Get-AzureADUser -Top $PrecacheSize | Where-Object {
            Cache-Object -Object $_
        }

        # Get all existing OAuth2 permission grants, get the client, resource and scope details
        Write-Verbose "Retrieving OAuth2PermissionGrants..."
        $oauth2PermissionGrants = Get-OAuth2PermissionGrants
        foreach ($grant in $oauth2PermissionGrants) {
            $grantDetails =  [ordered]@{
                "PermissionType" = 'Delegated'
            }
            if ($grant.ClientId) {
                $grantDetails["AppId"] = $null
                $grantDetails["ClientObjectId"] = $grant.ClientId
                $servicePrincipal = Get-ObjectDetails -ObjectId $grant.ClientId -ObjectClass 'ServicePrincipal'
                if ($servicePrincipal) {
                    $grantDetails["Homepage"] = $servicePrincipal.Homepage
                    $grantDetails["PublisherName"] = $servicePrincipal.PublisherName
                    $grantDetails["ReplyUrls"] = $servicePrincipal.ReplyUrls
                }
            }
            if ($grant.ResourceId) {
                $grantDetails["ResourceObjectId"] = $grant.ResourceId
                $resource = Get-ObjectDetails -ObjectId $grant.ResourceId
                if ($resource) {
                    $grantDetails["ResourceDisplayName"] = $resource.DisplayName
                }
            }
            if ($grant.Scope) {
                $grantDetails["Permission"] = $grant.Scope
            }
            if ($grant.ConsentType) {
                $grantDetails["ConsentType"] = $grant.ConsentType
            }
            if ($grant.PrincipalId) {
                $grantDetails["PrincipalObjectId"] = $grant.PrincipalId
                $principal = Get-ObjectDetails -ObjectId $grant.PrincipalId -ObjectClass 'User'
                if ($principal) {
                    foreach ($propertyName in $UserProperties) {
                        $grantDetails["Principal$propertyName"] = $principal.$propertyName
                    }
                }
            }
            New-Object PSObject -Property $grantDetails
        }
    }

    if ($ApplicationPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {

        # Iterate over all ServicePrincipal objects and get app permissions
        Write-Verbose "Retrieving AppRoleAssignments..."
        $script:ObjectByObjectClassId['ServicePrincipal'].GetEnumerator() | ForEach-Object { $i = 0 } {

            if ($ShowProgress) {
                Write-Progress -Activity "Retrieving application permissions..." `
                               -Status ("Checked {0}/{1} apps" -f $i++, $servicePrincipalCount) `
                               -PercentComplete (($i / $servicePrincipalCount) * 100)
            }

            $sp = $_.Value
            $servicePrincipal = Get-ObjectDetails -ObjectId $sp.ObjectId

            $appRoleAssignments = Get-AzureADServiceAppRoleAssignedTo -ObjectId $sp.ObjectId -All $true `
                                 | Where-Object { $_.PrincipalType -eq "ServicePrincipal" }
            foreach ($assignment in $appRoleAssignments) {
                $resource = Get-ObjectDetails -ObjectId $assignment.ResourceId
                $appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.Id }

                $grantDetails =  [ordered]@{
                    "PermissionType" = 'Application'
                }
                if ($sp.AppId) {
                    $grantDetails["AppId"] = $sp.AppId
                }
                if ($appRole) {
                    $grantDetails["Permission"] = $appRole.Value
                    $grantDetails["IsEnabled"] = $appRole.IsEnabled
                    $grantDetails["Description"] = $appRole.Description
                    $grantDetails["CreationTimestamp"] = $assignment.CreationTimestamp
                }
                if ($resource) {
                    $grantDetails["ResourceObjectId"] = $assignment.ResourceId
                    $grantDetails["ResourceDisplayName"] = $resource.DisplayName
                }
                New-Object PSObject -Property $grantDetails
            }
        }
    }

    # Save the output to a CSV file
    $date = Get-Date -Format "ddMMyyyyHHmmss"
    $report = $Output | Select-Object * -ExcludeProperty PSObject
    Convert-OutputToCsv -Output $report
    $report | ConvertTo-Csv | Format-Table | out-null
    $prop = $report.ForEach{ $_.PSObject.Properties.Name } | Select-Object -Unique
    $report | Select-Object $prop | Export-CSV -NoTypeInformation -Path "$OutputDir\$($date)-OAuthPermissions.csv" -Encoding $Encoding

    Write-LogFile -Message "Done, saving output to: $OutputDir\$($date)-OAuthPermissions.csv" -Color "Green"
}
