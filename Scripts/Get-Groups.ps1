Function Get-Groups {
<#
    .SYNOPSIS
    Retrieves all groups in the organization.

    .DESCRIPTION
    Retrieves all groups, including details such as group ID and display name.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Groups

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
    Get-Groups
    Retrieves all groups and exports the output to a CSV file.

    .EXAMPLE
    Get-Groups -Encoding utf32
    Retrieves all groups and exports the output to a CSV file with UTF-32 encoding.

    .EXAMPLE
    Get-Groups -OutputDir C:\Windows\Temp
    Retrieves all groups and saves the output to the C:\Windows\Temp folder.
#>

    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging
    Init-OutputDir -Component "Groups" -FilePostfix "Groups" -CustomOutputDir $OutputDir

    $requiredScopes = @("Group.Read.All", "AuditLog.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $requiredScopes

    Write-LogFile -Message "=== Starting Groups Collection ===" -Color "Cyan" -Level Standard

    try {
        Write-LogFile -Message "[INFO] Fetching all groups..." -Level Standard

        if ($isDebugEnabled) {
            $performance = Measure-Command {
                $allGroups = Get-MgGroup -All
            }
            Write-LogFile -Message "[DEBUG] Groups retrieval completed in $([math]::round($performance.TotalSeconds, 2)) seconds" -Level Debug
        } else {
            $allGroups = Get-MgGroup -All
        }

        Write-LogFile -Message "[INFO] Found $($allGroups.Count) groups" -Level Standard -Color "Green"

        $results = [System.Collections.Generic.List[object]]::new($allGroups.Count)
        foreach ($group in $allGroups) {
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing group: $($group.DisplayName)" -Level Debug
                if ($group.MembershipRule) {
                    Write-LogFile -Message "[DEBUG]   Rule length: $($group.MembershipRule.Length) characters" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Processing state: $($group.MembershipRuleProcessingState)" -Level Debug
                }
                Write-LogFile -Message "[DEBUG]   Security enabled: $($group.SecurityEnabled)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Mail enabled: $($group.MailEnabled)" -Level Debug
            }

            $results.Add([PSCustomObject]@{
                GroupId = $group.Id
                DisplayName = $group.DisplayName
                Description = $group.Description
                Mail = $group.Mail
                MailEnabled = $group.MailEnabled
                MailNickname = $group.MailNickname
                SecurityEnabled = $group.SecurityEnabled
                GroupTypes = $group.GroupTypes -join ','
                CreatedDateTime = $group.CreatedDateTime
                RenewedDateTime = $group.RenewedDateTime
                ExpirationDateTime = $group.ExpirationDateTime
                Visibility = $group.Visibility
                OnPremisesSyncEnabled = $group.OnPremisesSyncEnabled
                OnPremisesLastSyncDateTime = $group.OnPremisesLastSyncDateTime
                SecurityIdentifier = $group.SecurityIdentifier
                IsManagementRestricted = $group.IsManagementRestricted
                MembershipRule = $group.MembershipRule
                MembershipRuleProcessingState = $group.MembershipRuleProcessingState
                Classification = $group.Classification
                HideFromAddressLists = $group.HideFromAddressLists
                HideFromOutlookClients = $group.HideFromOutlookClients
                IsAssignableToRole = $group.IsAssignableToRole
                PreferredDataLocation = $group.PreferredDataLocation
                ProxyAddresses = $group.ProxyAddresses -join ';'
            })
        }

        $results | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
        $securityEnabledCount = 0
        $mailEnabledCount = 0
        $onPremisesSyncedCount = 0
        foreach ($result in $results) {
            if ($result.SecurityEnabled -eq $true) { $securityEnabledCount++ }
            if ($result.MailEnabled -eq $true) { $mailEnabledCount++ }
            if ($result.OnPremisesSyncEnabled -eq $true) { $onPremisesSyncedCount++ }
        }
        $summaryData = [ordered]@{
            "Group Summary" = [ordered]@{
                "Total Groups" = $results.Count
                "Security Enabled" = $securityEnabledCount
                "Mail Enabled" = $mailEnabledCount
                "On-Premises Synced" = $onPremisesSyncedCount
            }
        }
        Write-Summary -Summary $summaryData -Title "Group Analysis Summary"
    }
    catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }
}

Function Get-GroupMembers {
<#
    .SYNOPSIS
    Retrieves all members of each group and their relevant details.

    .DESCRIPTION
    Enumerates all members of every group in the organization, including when they were added, their permissions, and roles.

    .PARAMETER OutputDir
    The output directory for saving group member details.
    Default: Output\Groups

    .PARAMETER Encoding
    The encoding for CSV files.
    Default: UTF8

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard

    .EXAMPLE
    Get-GroupMembers
    Retrieves all group members and their details.

    .EXAMPLE
    Get-GroupMembers -OutputDir C:\Temp -Encoding utf32
    Retrieves all group members and saves details to C:\Temp with UTF-32 encoding.
#>

    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging
    Init-OutputDir -Component "Groups" -FilePostfix "GroupMembers" -CustomOutputDir $OutputDir

    $requiredScopes = @("Group.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    Write-LogFile -Message "=== Starting Group Members Collection ===" -Color "Cyan" -Level Standard

    try {
        Write-LogFile -Message "[INFO] Fetching all groups..." -Level Standard
        if ($isDebugEnabled) {
            $groupsPerformance = Measure-Command {
                $allGroups = Get-MgGroup -All
            }
            Write-LogFile -Message "[DEBUG] Groups retrieval completed in $([math]::round($groupsPerformance.TotalSeconds, 2)) seconds" -Level Debug
        } else {
            $allGroups = Get-MgGroup -All
        }
        Write-LogFile -Message "[INFO] Found $($allGroups.Count) groups" -Level Standard -Color "Green"

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Starting member enumeration for $($allGroups.Count) groups..." -Level Debug
        }

        $results = [System.Collections.Generic.List[object]]::new()
        foreach ($group in $allGroups) {
            Write-LogFile -Message "[INFO] Processing group: $($group.DisplayName)" -Level Standard

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing group details:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Group ID: $($group.Id)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Display Name: $($group.DisplayName)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Group Types: $($group.GroupTypes -join ', ')" -Level Debug
                Write-LogFile -Message "[DEBUG]   Mail Enabled: $($group.MailEnabled)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Security Enabled: $($group.SecurityEnabled)" -Level Debug
            }

            try {
                $members = Get-MgGroupMember -GroupId $group.Id -All
                foreach ($member in $members) {
                    $results.Add([PSCustomObject]@{
                        GroupName = $group.DisplayName
                        GroupId = $group.Id
                        MemberId = $member.Id
                        DisplayName = $member.AdditionalProperties.displayName
                        Email = $member.AdditionalProperties.mail
                        UserPrincipalName = $member.AdditionalProperties.userPrincipalName
                        GroupCreated = $member.CreatedDateTime
                    })
                }
            }
            catch {
                Write-LogFile -Message "[ERROR] Failed to retrieve members for group: $($group.DisplayName) Error: $($_.Exception.Message)" -Color "Red" -Level Minimal
            }
        }

        $results | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
        $summaryData = [ordered]@{
            "Collection Results" = [ordered]@{
                "Total Groups Processed" = $allGroups.Count
                "Total Members Found" = $results.Count
            }
        }

        Write-Summary -Summary $summaryData -Title "Group Members Summary"
    }
    catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }
}
Function Get-DynamicGroups {
<#
    .SYNOPSIS
    Retrieves all dynamic groups and their membership rules.

    .DESCRIPTION
    Retrieves dynamic groups and includes details about their membership rules, which determine automatic user inclusion.

    .PARAMETER OutputDir
    The output directory for saving dynamic group details.
    Default: Output\Groups

    .PARAMETER Encoding
    The encoding for CSV files.
    Default: UTF8

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard

    .EXAMPLE
    Get-DynamicGroups
    Retrieves dynamic groups and their membership rules, outputting the details to a CSV file.

    .EXAMPLE
    Get-DynamicGroups -OutputDir C:\Temp -Encoding utf32
    Retrieves dynamic groups and saves details to C:\Temp with UTF-32 encoding.
#>

    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging
    Init-OutputDir -Component "Groups" -FilePostfix "DynamicGroups" -CustomOutputDir $OutputDir

    $requiredScopes = @("Group.Read.All", "Directory.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    Write-LogFile -Message "=== Starting Dynamic Groups Collection ===" -Color "Cyan" -Level Standard
    try {
        Write-LogFile -Message "[INFO] Fetching all groups from Microsoft Graph..." -Level Standard

        if ($isDebugEnabled) {
            $groupsPerformance = Measure-Command {
                $allGroups = Get-MgGroup -All
            }
            Write-LogFile -Message "[DEBUG] Groups retrieval completed in $([math]::round($groupsPerformance.TotalSeconds, 2)) seconds" -Level Debug
        } else {
            $allGroups = Get-MgGroup -All
        }

        Write-LogFile -Message "[INFO] Found $($allGroups.Count) total groups" -Level Standard

        $dynamicGroups = [System.Collections.Generic.List[object]]::new()
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Analyzing groups for dynamic membership rules..." -Level Debug
            $filterPerformance = Measure-Command {
                foreach ($group in $allGroups) {
                    if ($group.MembershipRule -ne $null) {
                        $dynamicGroups.Add($group)
                    }
                }
            }
            Write-LogFile -Message "[DEBUG] Dynamic groups filtering completed in $([math]::round($filterPerformance.TotalSeconds, 2)) seconds" -Level Debug
        } else {
            foreach ($group in $allGroups) {
                if ($group.MembershipRule -ne $null) {
                    $dynamicGroups.Add($group)
                }
            }
        }

        Write-LogFile -Message "[INFO] Found $($dynamicGroups.Count) dynamic groups" -Level Standard

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Dynamic groups breakdown:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Dynamic groups: $($dynamicGroups.Count)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Static groups: $($allGroups.Count - $dynamicGroups.Count)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Dynamic percentage: $([math]::Round(($dynamicGroups.Count / [math]::Max($allGroups.Count, 1)) * 100, 2))%" -Level Debug
        }

        $results = [System.Collections.Generic.List[object]]::new($dynamicGroups.Count)
        foreach ($group in $dynamicGroups) {
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing dynamic group: $($group.DisplayName)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Rule length: $($group.MembershipRule.Length) characters" -Level Debug
                Write-LogFile -Message "[DEBUG]   Processing state: $($group.MembershipRuleProcessingState)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Security enabled: $($group.SecurityEnabled)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Mail enabled: $($group.MailEnabled)" -Level Debug
            }

            $results.Add([PSCustomObject]@{
                GroupId = $group.Id
                DisplayName = $group.DisplayName
                Description = $group.Description
                Mail = $group.Mail
                MailEnabled = $group.MailEnabled
                MailNickname = $group.MailNickname
                SecurityEnabled = $group.SecurityEnabled
                GroupTypes = $group.GroupTypes -join ','
                CreatedDateTime = $group.CreatedDateTime
                RenewedDateTime = $group.RenewedDateTime
                MembershipRule = $group.MembershipRule
                MembershipRuleProcessingState = $group.MembershipRuleProcessingState
                OnPremisesSyncEnabled = $group.OnPremisesSyncEnabled
                SecurityIdentifier = $group.SecurityIdentifier
                Classification = $group.Classification
                Visibility = $group.Visibility
            })
        }

        $results | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
        $totalCount = $results.Count
        $securityEnabledCount = 0
        $mailEnabledCount = 0
        foreach ($result in $results) {
            if ($result.SecurityEnabled -eq $true) { $securityEnabledCount++ }
            if ($result.MailEnabled -eq $true) { $mailEnabledCount++ }
        }

        $processingStates = $results | Group-Object -Property MembershipRuleProcessingState
        $statesHashtable = [ordered]@{}
        foreach ($state in $processingStates) {
            $statesHashtable[$state.Name] = $state.Count
        }

        $summaryData = [ordered]@{
            "Dynamic Group Summary" = [ordered]@{
                "Total Dynamic Groups" = $totalCount
                "Security Enabled" = $securityEnabledCount
                "Mail Enabled" = $mailEnabledCount
            }
            "Membership Rule Processing States" = $statesHashtable
        }

        Write-Summary -Summary $summaryData -Title "Dynamic Group Analysis Summary"
    }
    catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }
}
