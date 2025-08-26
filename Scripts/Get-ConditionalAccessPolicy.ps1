
Function Get-ConditionalAccessPolicies {
    <#
    .SYNOPSIS
    Retrieves all the conditional access policies.

    .DESCRIPTION
    Retrieves all the conditional access policies.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\ConditionalAccessPolicies

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Standard

    .EXAMPLE
    Get-ConditionalAccessPolicies
    Retrieves all the conditional access policies.

    .EXAMPLE
    Get-ConditionalAccessPolicies -Application
    Retrieves all the conditional access policies via application authentication.

    .EXAMPLE
    Get-ConditionalAccessPolicies -Encoding utf32
    Retrieves all the conditional access policies and exports the output to a CSV file with UTF-32 encoding.

    .EXAMPLE
    Get-ConditionalAccessPolicies -OutputDir C:\Windows\Temp
    Retrieves all the conditional access policies and saves the output to the C:\Windows\Temp folder.
    #>
    [CmdletBinding()]
    param(
        [string]
        $OutputDir = "Output\ConditionalAccessPolicies",
        [string]
        $Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]
        $LogLevel = 'Standard'
    )

    begin {
        Set-LogLevel -Level ([LogLevel]::$LogLevel)
        $isDebugEnabled = $Global:DebugEnabled

        # Use ArrayList instead of array for better performance
        $results = [System.Collections.ArrayList]::new()

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
            Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
            Write-LogFile -Message "[DEBUG]   OutputDir: $OutputDir" -Level Debug
            Write-LogFile -Message "[DEBUG]   Encoding: $Encoding" -Level Debug
            Write-LogFile -Message "[DEBUG]   LogLevel: $LogLevel" -Level Debug

            $graphModule = Get-Module -Name Microsoft.Graph* -ErrorAction SilentlyContinue
            if ($graphModule) {
                Write-LogFile -Message "[DEBUG] Microsoft Graph Modules loaded:" -Level Debug
                foreach ($module in $graphModule) {
                    Write-LogFile -Message "[DEBUG]   - $($module.Name) v$($module.Version)" -Level Debug
                }
            }
            else {
                Write-LogFile -Message "[DEBUG] No Microsoft Graph modules loaded" -Level Debug
            }
        }

        $requiredScopes = @("Policy.Read.All")
        $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Graph authentication completed" -Level Debug
            try {
                $context = Get-MgContext
                if ($context) {
                    Write-LogFile -Message "[DEBUG] Graph context information:" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Account: $($context.Account)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Environment: $($context.Environment)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   TenantId: $($context.TenantId)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Scopes: $($context.Scopes -join ', ')" -Level Debug
                }
            }
            catch {
                Write-LogFile -Message "[DEBUG] Could not retrieve Graph context details" -Level Debug
            }
        }

        Write-LogFile -Message "=== Starting Conditional Access Policy Collection ===" -Color "Cyan" -Level Standard

        UpsertOutputDirectory($OutputDir)
    }

    process {
        try {
            $policies = Get-MgIdentityConditionalAccessPolicy -All

            $stringBuilder = [System.Text.StringBuilder]::new()

            foreach ($policy in $policies) {
                Write-LogFile -Message "[INFO] Processing policy: $($policy.DisplayName)" -Level Standard

                if ($isDebugEnabled) {
                    [void]$stringBuilder.Clear()
                    [void]$stringBuilder.AppendLine("`n`t[DEBUG] Policy details:`n`t[DEBUG]   ID: $($policy.Id)`n`t[DEBUG]   State: $($policy.State)`n`t[DEBUG]   Created: $($policy.CreatedDateTime)`n`t[DEBUG]   Modified: $($policy.ModifiedDateTime)`n")
                    Write-LogFile $stringBuilder.ToString() -Level Debug
                }

                $policyDetails = [pscustomobject]@{
                    includeUsers                    = if ($policy.Conditions.Users.IncludeUsers) { $policy.Conditions.Users.IncludeUsers -join '; ' } else { '' }
                    excludeUsers                    = if ($policy.Conditions.Users.ExcludeUsers) { $policy.Conditions.Users.ExcludeUsers -join '; ' } else { '' }
                    includeGroups                   = if ($policy.Conditions.Users.IncludeGroups) { $policy.Conditions.Users.IncludeGroups -join '; ' } else { '' }
                    excludeGroups                   = if ($policy.Conditions.Users.ExcludeGroups) { $policy.Conditions.Users.ExcludeGroups -join '; ' } else { '' }
                    includeRoles                    = if ($policy.Conditions.Users.IncludeRoles) { $policy.Conditions.Users.IncludeRoles -join '; ' } else { '' }
                    excludeRoles                    = if ($policy.Conditions.Users.ExcludeRoles) { $policy.Conditions.Users.ExcludeRoles -join '; ' } else { '' }
                    includeApplications             = if ($policy.Conditions.Applications.IncludeApplications) { $policy.Conditions.Applications.IncludeApplications -join '; ' } else { '' }
                    excludeApplications             = if ($policy.Conditions.Applications.ExcludeApplications) { $policy.Conditions.Applications.ExcludeApplications -join '; ' } else { '' }
                    includePlatforms                = if ($policy.Conditions.Platforms.IncludePlatforms) { $policy.Conditions.Platforms.IncludePlatforms -join '; ' } else { '' }
                    excludePlatforms                = if ($policy.Conditions.Platforms.ExcludePlatforms) { $policy.Conditions.Platforms.ExcludePlatforms -join '; ' } else { '' }
                    includeLocations                = if ($policy.Conditions.Locations.IncludeLocations) { $policy.Conditions.Locations.IncludeLocations -join '; ' } else { '' }
                    excludeLocations                = if ($policy.Conditions.Locations.ExcludeLocations) { $policy.Conditions.Locations.ExcludeLocations -join '; ' } else { '' }
                    userRiskLevels                  = if ($policy.Conditions.UserRiskLevels) { $policy.Conditions.UserRiskLevels -join '; ' } else { '' }
                    signInRiskLevels                = if ($policy.Conditions.SignInRiskLevels) { $policy.Conditions.SignInRiskLevels -join '; ' } else { '' }
                    servicePrincipalRiskLevels      = if ($policy.Conditions.ServicePrincipalRiskLevels) { $policy.Conditions.ServicePrincipalRiskLevels -join '; ' } else { '' }
                    includeDeviceStates             = if ($policy.Conditions.Devices.IncludeDeviceStates) { $policy.Conditions.Devices.IncludeDeviceStates -join '; ' } else { '' }
                    excludeDeviceStates             = if ($policy.Conditions.Devices.ExcludeDeviceStates) { $policy.Conditions.Devices.ExcludeDeviceStates -join '; ' } else { '' }
                    deviceFilter                    = if ($policy.Conditions.Devices.DeviceFilter.Rule) {
                        "{0}: {1}" -f $policy.Conditions.Devices.DeviceFilter.Mode, $policy.Conditions.Devices.DeviceFilter.Rule
                    }
                    else { "Not Configured" }
                    builtInControls                 = if ($policy.GrantControls.BuiltInControls) { $policy.GrantControls.BuiltInControls -join '; ' } else { '' }
                    customAuthenticationFactors     = if ($policy.GrantControls.CustomAuthenticationFactors) { $policy.GrantControls.CustomAuthenticationFactors -join '; ' } else { '' }
                    grantOperator                   = $policy.GrantControls.Operator
                    termsOfUse                      = if ($policy.GrantControls.TermsOfUse) { $policy.GrantControls.TermsOfUse -join '; ' } else { '' }
                    applicationEnforcedRestrictions = $policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
                    cloudAppSecurity                = $policy.SessionControls.CloudAppSecurity.IsEnabled
                    disableResilienceDefaults       = $policy.SessionControls.DisableResilienceDefaults
                    persistentBrowser               = $policy.SessionControls.PersistentBrowser.Mode
                    signInFrequency                 = if ($policy.SessionControls.SignInFrequency.Value -and $policy.SessionControls.SignInFrequency.Type) {
                        "{0} {1}" -f $policy.SessionControls.SignInFrequency.Value, $policy.SessionControls.SignInFrequency.Type
                    }
                    else { '' }
                    deviceFilterMode                = $policy.Conditions.Devices.DeviceFilter.Mode
                    deviceFilterRule                = $policy.Conditions.Devices.DeviceFilter.Rule
                    userActions                     = if ($policy.Conditions.UserRiskLevels) { $policy.Conditions.UserRiskLevels -join '; ' } else { '' }
                    clientAppsV2                    = if ($policy.Conditions.ClientAppTypes) { $policy.Conditions.ClientAppTypes -join '; ' } else { '' }
                    deviceStates                    = if ($policy.Conditions.Devices.DeviceStates) { $policy.Conditions.Devices.DeviceStates -join '; ' } else { '' }
                }

                [void]$results.Add($policyDetails)
            }
        }
        catch {
            Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)"  -Color "Red" -Level Minimal
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG]   Policies collected before error: $($results.Count)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
                Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
            }
            throw
        }
    }

    end {
        $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
        $filePath = "{0}\{1}-ConditionalAccessPolicy.csv" -f $OutputDir, $date

        $resultsArray = @($results)
        $resultsArray | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding

        Write-LogFile -Message "`n=== Conditional Access Policy Summary ===" -Color "Cyan" -Level Standard
        Write-LogFile -Message "Total Policies: $($results.Count)" -Level Standard

        $enabledCount = 0
        $disabledCount = 0
        foreach ($result in $results) {
            if ($result.State -eq 'enabled') { $enabledCount++ }
            elseif ($result.State -eq 'disabled') { $disabledCount++ }
        }

        Write-LogFile -Message "Enabled Policies: $enabledCount" -Level Standard
        Write-LogFile -Message "Disabled Policies: $disabledCount" -Level Standard
        Write-LogFile -Message "Output: $filePath" -Level Standard
        Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
    }
}
