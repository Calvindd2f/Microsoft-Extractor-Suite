function Get-ServicePrincipalDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectId
    )
    process {
        try {
            $servicePrincipal = Get-AzureADServicePrincipal -ObjectId $ObjectId -ErrorAction Stop
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
            Write-LogFile -Message ("Error retrieving service principal with ObjectId {0}: {1}" -f $ObjectId, $_.Exception.Message) -Color "Red"
            return $null
        }
    }
}

function Get-OAuthPermissions {
    [CmdletBinding()]
    param(
        [switch] $DelegatedPermissions,
        [switch] $ApplicationPermissions,
        [string[]] $UserProperties = @("DisplayName"),
        [string[]] $ServicePrincipalProperties = @("DisplayName"),
        [switch] $ShowProgress = $true,
        [int] $PrecacheSize = 999,
        [string] $OutputDir = "Output\OAuthPermissions",
        [string] $Encoding = "UTF8"
    )
    begin {
        try {
            $tenant_details = Get-AzureADTenantDetail -ErrorAction stop
        }
        catch {
            Write-LogFile -Message "[WARNING] You must call Connect-Azure before running this script" -Color "Red"
            break
        }

        if (!(test-path $OutputDir)) {
            New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
            Write-LogFile -Message "[INFO] Creating the following directory: $OutputDir"
        }
    }
    process {
        $date = Get-Date -Format "ddMMyyyyHHmmss"

        # An in-memory cache of objects by {object ID} andy by {object class, object ID}
        $script:ObjectByObjectId = @{}
        $script:ObjectByObjectClassId = @{}

        $empty = @{} # Used later to avoid null checks

        # Get all ServicePrincipal objects and add to the cache
        Write-Verbose "Retrieving all ServicePrincipal objects..."
        Get-AzureADServicePrincipal -All $true | ForEach-Object {
            CacheObject -Object $_
        }
        $servicePrincipalCount = $script:ObjectByObjectClassId['ServicePrincipal'].Count

        if ($DelegatedPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {

            # Get one page of User objects and add to the cache
            Write-Verbose ("Retrieving up to {0} User objects..." -f $PrecacheSize)
            Get-AzureADUser -Top $PrecacheSize | Where-Object {
                CacheObject -Object $_
            }

            Write-Verbose "Testing for OAuth2PermissionGrants bug before querying..."
            $fastQueryMode = $false
            try {
                # There's a bug in Azure AD Graph which does not allow for directly listing
                # oauth2PermissionGrants if there are more than 999 of them. The following line will
                # trigger this bug (if it still exists) and throw an exception.
                $null = Get-AzureADOAuth2PermissionGrant -Top 999
                $fastQueryMode = $true
            }
            catch {
                if ($_.Exception.Message -and $_.Exception.Message.StartsWith("Unexpected end when deserializing array.")) {
                    Write-Verbose ("Fast query for delegated permissions failed, using slow method...")
                }
                else {
                    throw $_
                }
            }

            # Get all existing OAuth2 permission grants, get the client, resource and scope details
            Write-Verbose "Retrieving OAuth2PermissionGrants..."
            GetOAuth2PermissionGrants -FastMode:$fastQueryMode | ForEach-Object {
                $grant = $_
                $servicePrincipal = Get-ServicePrincipalDetails -ObjectId $grant.ClientId

                if ($grant.Scope) {

                    $grant.Scope.Split(" ") | Where-Object { $_ } | ForEach-Object {

                        $grantDetails =  [ordered]@{
                            "PermissionType" = "Delegated"
                            "AppId" = $servicePrincipal.AppId
                            "ClientObjectId" = $grant.ClientId
                            "ResourceObjectId" = $grant.ResourceId
                            "Permission" = $_
                            "ConsentType" = $grant.ConsentType
                            "PrincipalObjectId" = $grant.PrincipalId
                            "Homepage" = $servicePrincipal.Homepage
                            "PublisherName" = $servicePrincipal.PublisherName
                            "ReplyUrls" = $servicePrincipal.ReplyUrls
                            "ExpiryTime" = $grant.ExpiryTime
                        }

                        # Add properties for client and resource service principals
                        if ($ServicePrincipalProperties.Count -gt 0) {

                            $client = GetObjectByObjectId -ObjectId $grant.ClientId
                            $resource = GetObjectByObjectId -ObjectId $grant.ResourceId

                            $insertAtClient = 2
                            $insertAtResource = 3
                            foreach ($propertyName in $ServicePrincipalProperties) {
                                $grantDetails.Insert($insertAtClient++, "Client$propertyName", $client.$propertyName)
                                $insertAtResource++
                                $grantDetails.Insert($insertAtResource, "Resource$propertyName", $resource.$propertyName)
                                $insertAtResource ++
                            }
                        }

                        # Add properties for principal (will all be null if there's no principal)
                        if ($UserProperties.Count -gt 0) {

                            $principal = $empty
                            if ($grant.PrincipalId) {
                                $principal = GetObjectByObjectId -ObjectId $grant.PrincipalId
                            }

                            foreach ($propertyName in $UserProperties) {
                                $grantDetails["Principal$propertyName"] = $principal.$propertyName
                            }
                        }

                        New-Object PSObject -Property $grantDetails
                    }
                }
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
                $servicePrincipal = Get-ServicePrincipalDetails -ObjectId $sp.ObjectId

                Get-AzureADServiceAppRoleAssignedTo -ObjectId $sp.ObjectId -All $true `
                | Where-Object { $_.PrincipalType -eq "ServicePrincipal" } | ForEach-Object {
                    $assignment = $_

                    $resource = GetObjectByObjectId -ObjectId $assignment.ResourceId
                    $appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.Id }

                    $grantDetails =  [ordered]@{
                        "PermissionType" = "Application"
                        "AppId" = $null
                        "ClientObjectId" = $assignment.PrincipalId
                        "ResourceObjectId" = $assignment.ResourceId
                        "Permission" = $appRole.Value
                        "IsEnabled" = $null
                        "Description" = $null
                        "CreationTimestamp" = $null
                        "Homepage" = $servicePrincipal.Homepage
                        "PublisherName" = $servicePrincipal.PublisherName
                        "ReplyUrls" = $servicePrincipal.ReplyUrls
                    }

                    # Add the properties if they are available and not null or empty
                    if ($null -ne $sp -and $sp.AppId) {
                        $grantDetails["AppId"] = $sp.AppId
                    }

                    if ($null -ne $appRole -and $appRole.IsEnabled) {
                        $grantDetails["IsEnabled"] = $appRole.IsEnabled
                    }

                    if ($null -ne $appRole -and $appRole.Description) {
                        $grantDetails["Description"] = $appRole.Description
                    }

                    if ($null -ne $assignment - and $assignment.CreationTimestamp) {
                        $grantDetails["CreationTimestamp"] = $assignment.CreationTimestamp
                    }

                    # Add properties for client and resource service principals
                    if ($ServicePrincipalProperties.Count -gt 0) {

                        $client = GetObjectByObjectId -ObjectId $assignment.PrincipalId

                        $insertAtClient = 2
                        $insertAtResource = 3
                        foreach ($propertyName in $ServicePrincipalProperties) {
                            $grantDetails.Insert($insertAtClient++, "Client$propertyName", $client.$propertyName)
                            $insertAtResource++
                            $grantDetails.Insert($insertAtResource, "Resource$propertyName", $resource.$propertyName)
                            $insertAtResource ++
                        }
                    }
                    New-Object PSObject -Property $grantDetails
                }
            }
        }
    }
    end {
        $report | ConvertTo-Csv | Format-Table | out-null
        $prop = $report.ForEach{ $_.PSObject.Properties.Name } | Select-Object -Unique
        $report | Select-Object $prop | Export-CSV -NoTypeInformation -Path "$OutputDir\$($date)-OAuthPermissions.csv" -Encoding $Encoding

        Write-LogFile -Message "Done, saving output to: $OutputDir\$($date)-OAuthPermissions.csv" -Color "Green"
    }
}
