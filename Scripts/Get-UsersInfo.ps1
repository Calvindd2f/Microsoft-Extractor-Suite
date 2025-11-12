function Get-Users {
<#
    .SYNOPSIS
    Retrieves the creation time and date of the last password change for all users.
    Script inspired by: https://github.com/tomwechsler/Microsoft_Graph/blob/main/Entra_ID/Create_time_last_password.ps1

    .DESCRIPTION
    Retrieves the creation time and date of the last password change for all users.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Users

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

    .PARAMETER UserIds
    UserId is the parameter specifying a single user ID or UPN to filter the results.
    Default: All users will be included if not specified.

    .EXAMPLE
    Get-Users
    Retrieves the creation time and date of the last password change for all users.

    .EXAMPLE
    Get-Users -Encoding utf32
    Retrieves the creation time and date of the last password change for all users and exports the output to a CSV file with UTF-32 encoding.

    .EXAMPLE
    Get-Users -OutputDir C:\Windows\Temp
    Retrieves the creation time and date of the last password change for all users and saves the output to the C:\Windows\Temp folder.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [string]$UserIds,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    begin {
        Init-Logging
        Init-OutputDir -Component "Users" -FilePostfix "Users" -CustomOutputDir $OutputDir

        $requiredScopes = @("User.Read.All")
        $null = Get-GraphAuthType -RequiredScopes $RequiredScopes
        Write-LogFile -Message "=== Starting Users Collection ===" -Color "Cyan" -Level Standard
    }

    process {

    try {
        $selectobjects = "UserPrincipalName","DisplayName","Id","CompanyName","Department","JobTitle","City","Country","Identities","UserType","LastPasswordChangeDateTime","AccountEnabled","CreatedDateTime","CreationType","ExternalUserState","ExternalUserStateChangeDateTime","SignInActivity","OnPremisesSyncEnabled"
        $mgUsers = @()

        if ($UserIds) {
            Write-LogFile -Message "[INFO] Filtering results for user: $UserIds" -Level Standard

            try {
                $mgUsers = Get-Mguser -Filter "userPrincipalName eq '$UserIds'" -select $selectobjects

                if (-not $mgUsers) {
                    Write-LogFile -Message "[WARNING] User not found: $UserIds" -Color "Yellow" -Level Standard
                    $mgUsers = @()
                }
            } catch {
                Write-LogFile -Message "[WARNING] Error retrieving user $UserIds`: $($_.Exception.Message)" -Color "Yellow" -Level Standard
                $mgUsers = @()
            }
        } else {
            $mgUsers = Get-MgUser -All -Select $selectobjects
            Write-LogFile -Message "[INFO] Found $($mgUsers.Count) users" -Level Standard
        }

        $formattedUsers = [System.Collections.Generic.List[object]]::new($mgUsers.Count)
        foreach ($user in $mgUsers) {
            $federatedIdentity = $user.Identities.Where({ $_.SignInType -eq "federated" }, 'First')
            $formattedUsers.Add([PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                Id = $user.Id
                Department = $user.Department
                JobTitle = $user.JobTitle
                AccountEnabled = $user.AccountEnabled
                CreatedDateTime = $user.CreatedDateTime
                LastPasswordChangeDateTime = $user.LastPasswordChangeDateTime
                UserType = $user.UserType
                OnPremisesSyncEnabled = $user.OnPremisesSyncEnabled
                Mail = $user.Mail
                LastSignInDateTime = $user.SignInActivity.LastSignInDateTime
                LastNonInteractiveSignInDateTime = $user.SignInActivity.LastNonInteractiveSignInDateTime
                IdentityProvider = if ($federatedIdentity) { $federatedIdentity.Issuer } else { $null }
                City = $user.City
                Country = $user.Country
                UsageLocation = $user.UsageLocation
            })
        }

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] User formatting completed:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Original users: $($mgUsers.Count)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Formatted users: $($formattedUsers.Count)" -Level Debug
            Write-LogFile -Message "[DEBUG] Starting user analysis by creation date..." -Level Debug
        }

        $now = Get-Date
        $date7 = $now.AddDays(-7)
        $date30 = $now.AddDays(-30)
        $date90 = $now.AddDays(-90)
        $date180 = $now.AddDays(-180)
        $date360 = $now.AddDays(-360)

        $countOneWeek = 0
        $countOneMonth = 0
        $countThreeMonths = 0
        $countSixMonths = 0
        $countOneYear = 0
        $countEnabled = 0
        $countDisabled = 0
        $countSynced = 0
        $countGuest = 0

        foreach ($user in $mgUsers) {
            if ($user.CreatedDateTime) {
                if ($user.CreatedDateTime -gt $date7) { $countOneWeek++ }
                if ($user.CreatedDateTime -gt $date30) { $countOneMonth++ }
                if ($user.CreatedDateTime -gt $date90) { $countThreeMonths++ }
                if ($user.CreatedDateTime -gt $date180) { $countSixMonths++ }
                if ($user.CreatedDateTime -gt $date360) { $countOneYear++ }
            }
            if ($user.AccountEnabled) { $countEnabled++ } else { $countDisabled++ }
            if ($user.OnPremisesSyncEnabled) { $countSynced++ }
            if ($user.UserType -eq "Guest") { $countGuest++ }
        }

        $formattedUsers | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding

        $summary = [ordered]@{
            "User Counts" = [ordered]@{
                "Total Users" = $mgUsers.Count
                "Enabled Users" = $countEnabled
                "Disabled Users" = $countDisabled
                "Synced from On-Premises" = $countSynced
                "Guest Users" = $countGuest
            }
            "Recent Account Creation" = [ordered]@{
                "Last 7 days" = $countOneWeek
                "Last 30 days" = $countOneMonth
                "Last 90 days" = $countThreeMonths
                "Last 6 months" = $countSixMonths
                "Last 1 year" = $countOneYear
            }
        }

        Write-Summary -Summary $summary -Title "User Analysis Summary"
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Error message: $($_.Exception.Message)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }
    }

    end {
    }
}

Function Get-AdminUsers {
<#
    .SYNOPSIS
    Retrieves all Administrator directory roles.

    .DESCRIPTION
    Retrieves Administrator directory roles, including the identification of users associated with each specific role.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Admins

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
    Get-AdminUsers
    Retrieves Administrator directory roles, including the identification of users associated with each specific role.

    .EXAMPLE
    Get-AdminUsers -Encoding utf32
    Retrieves Administrator directory roles, including the identification of users associated with each specific role and exports the output to a CSV file with UTF-32 encoding.

    .EXAMPLE
    Get-AdminUsers -OutputDir C:\Windows\Temp
    Retrieves Administrator directory roles, including the identification of users associated with each specific role and saves the output to the C:\Windows\Temp folder.
#>

    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    begin {
        Init-Logging
        Init-OutputDir -Component "Admins" -FilePostfix "AdminUsers" -CustomOutputDir $OutputDir

        Write-LogFile -Message "=== Starting Admin Users Collection ===" -Color "Cyan" -Level Standard

        $requiredScopes = @("User.Read.All", "Directory.Read.All")
        $null = Get-GraphAuthType -RequiredScopes $RequiredScopes

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Graph authentication details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Required scopes: $($requiredScopes -join ', ')" -Level Debug
        }

        Write-LogFile -Message "[INFO] Analyzing administrator roles..." -Level Standard
        $rolesWithUsers = [System.Collections.Generic.List[string]]::new()
        $rolesWithoutUsers = [System.Collections.Generic.List[string]]::new()
        $exportedFiles = [System.Collections.Generic.List[string]]::new()
        $totalAdminCount = 0
        $inactiveAdminCount = 0
        $inactiveThreshold = (Get-Date).AddDays(-30)
        $inactiveAdmins = [System.Collections.Generic.List[string]]::new()
    }

    process {

    try {
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Retrieving all directory roles..." -Level Debug
            $performance = Measure-Command {
                $getRoles = Get-MgDirectoryRole -all
            }
            Write-LogFile -Message "[DEBUG] Directory roles retrieval took $([math]::round($performance.TotalSeconds, 2)) seconds" -Level Debug
            Write-LogFile -Message "[DEBUG] Found $($getRoles.Count) total directory roles" -Level Debug
        } else {
            $getRoles = Get-MgDirectoryRole -all
        }

        foreach ($role in $getRoles) {
            $roleId = $role.Id
            $roleName = $role.DisplayName

            if ($roleName -like "*Admin*") {
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Processing admin role: $roleName" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Role ID: $roleId" -Level Debug
                }

                if ($isDebugEnabled) {
                    $memberPerformance = Measure-Command {
                        $areThereUsers = Get-MgDirectoryRoleMember -DirectoryRoleId $roleId
                    }
                    Write-LogFile -Message "[DEBUG]   Role member query took $([math]::round($memberPerformance.TotalSeconds, 2)) seconds" -Level Debug
                } else {
                    $areThereUsers = Get-MgDirectoryRoleMember -DirectoryRoleId $roleId
                }

                if ($null -eq $areThereUsers) {
                    $rolesWithoutUsers.Add($roleName)
                    continue
                }

                $results = [System.Collections.Generic.List[object]]::new()
                $count = 0
                foreach ($user in $areThereUsers) {
                    $userid = $user.Id
                    if ($userid -eq ".") {
                        if ($isDebugEnabled) {
                            Write-LogFile -Message "[DEBUG]     Skipping invalid user ID: $userid" -Level Debug
                        }
                        continue
                    }

                    $count++
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]     Processing user $count/$($areThereUsers.Count): $userid" -Level Debug
                    }
                    try {
                        $selectProperties = @(
                        "UserPrincipalName", "DisplayName", "Id", "Department", "JobTitle",
                        "AccountEnabled", "CreatedDateTime","SignInActivity"
                        )


                        try {
                            $getUserName = Get-MgUser -UserId $userid -Select $selectProperties -ErrorAction Stop
                        } catch {
                            if ($_.Exception.Response.StatusCode -eq 429) {
                                Start-Sleep -Seconds 5
                                $getUserName = Get-MgUser -UserId $userid -Select $selectProperties -ErrorAction Stop
                            } else {
                                throw
                            }
                        }

                        $userName = $getUserName.UserPrincipalName
                        $userObject = [PSCustomObject]@{
                            UserName = $userName
                            UserId = $userid
                            Role = $roleName
                            DisplayName = $getUserName.DisplayName
                            Department = $getUserName.Department
                            JobTitle = $getUserName.JobTitle
                            AccountEnabled = $getUserName.AccountEnabled
                            CreatedDateTime = $getUserName.CreatedDateTime
                            LastInteractiveSignIn = $getUserName.SignInActivity.LastSignInDateTime
                            LastNonInteractiveSignIn = $getUserName.SignInActivity.LastNonInteractiveSignInDateTime
                        }

                        if ($getUserName.SignInActivity.LastSignInDateTime) {
                            $daysSinceSignIn = (New-TimeSpan -Start $getUserName.SignInActivity.LastSignInDateTime -End (Get-Date)).Days
                            $userObject | Add-Member -MemberType NoteProperty -Name "DaysSinceLastSignIn" -Value $daysSinceSignIn

                            if ($getUserName.SignInActivity.LastSignInDateTime -lt $inactiveThreshold) {
                                $inactiveAdminCount++
                                $inactiveAdmins.Add("$($getUserName.DisplayName) ($userName) - $daysSinceSignIn days")
                            }
                        } else {
                            $userObject | Add-Member -MemberType NoteProperty -Name "DaysSinceLastSignIn" -Value "No sign-in data"
                            $inactiveAdminCount++
                            $inactiveAdmins.Add("$($getUserName.DisplayName) ($userName) - No sign-in data")
                        }
                        $results.Add($userObject)
                    }
                    catch {
                        Write-LogFile -Message "[WARNING] Error processing user $userid in role $roleName`: $($_.Exception.Message)" -Color "Yellow" -Level Standard
                    }
                }

                if ($results.Count -gt 0) {
                    $totalAdminCount += $results.Count
                    $rolesWithUsers.Add("$roleName ($($results.Count) users)")

                    $date = [datetime]::Now.ToString('yyyyMMdd')
                    $safeRoleName = $roleName -replace '[^\w\-_\.]', '_'
                    $rolePath = Split-Path $script:outputFile -Parent
                    $roleFilePath = Join-Path $rolePath "$date-$safeRoleName.csv"

                    $results | Export-Csv -Path $roleFilePath -NoTypeInformation -Encoding $Encoding
                    $exportedFiles.Add($roleFilePath)
                }
                else {
                    $rolesWithoutUsers.Add($roleName)
                }
            }
        }

        # Create merged file
        $outputDirPath = Split-Path $script:outputFile -Parent
        $outputDirMerged = Join-Path $outputDirPath "Merged"
        if (!(Test-Path $outputDirMerged)) {
            New-Item -ItemType Directory -Force -Path $outputDirMerged > $null
        }

        $date = [datetime]::Now.ToString('yyyyMMdd')
        $mergedFile = Join-Path $outputDirMerged "$date-All-Administrators.csv"

        # Get all individual admin role files and merge them
        $adminFiles = Get-ChildItem $outputDirPath -Filter "*Admin*.csv" -ErrorAction SilentlyContinue
        if ($adminFiles.Count -gt 0) {
            $adminFiles |
                ForEach-Object { Import-Csv $_.FullName } |
                Export-Csv $mergedFile -NoTypeInformation -Encoding $Encoding
        }

        $summary = [ordered]@{
            "Role Summary" = [ordered]@{
                "Total admin roles" = ($rolesWithUsers.Count + $rolesWithoutUsers.Count)
                "Roles with users" = $rolesWithUsers.Count
                "Empty roles" = $rolesWithoutUsers.Count
                "Total administrators" = $totalAdminCount
                "Inactive administrators (30+ days)" = $inactiveAdminCount
            }
        }

        # Keep the detailed lists before the summary
        Write-LogFile -Message "`nRoles with users:" -Color "Green" -Level Standard
        foreach ($role in $rolesWithUsers) {
            Write-LogFile -Message "  + $role" -Level Standard
        }

        Write-LogFile -Message "`nEmpty roles:" -Color "Yellow" -Level Standard
        foreach ($role in $rolesWithoutUsers) {
            Write-LogFile -Message "  - $role" -Level Standard
        }

        if ($inactiveAdmins.Count -gt 0) {
            Write-LogFile -Message "`nInactive administrators (30+ days):" -Color "Yellow" -Level Standard
            foreach ($admin in $inactiveAdmins) {
                Write-LogFile -Message "  ! $admin" -Level Standard
            }
        }

        Write-Summary -Summary $summary -Title "Admin Users Summary"
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Error message: $($_.Exception.Message)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }
    }

    end {
    }
}
