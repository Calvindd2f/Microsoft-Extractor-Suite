Function Get-SecurityAlerts {
<#
    .SYNOPSIS
    Retrieves security alerts.

    .DESCRIPTION
    Retrieves security alerts from Microsoft Graph, choosing between Get-MgSecurityAlert and
    Get-MgSecurityAlertV2 based on the authentication type used.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\SecurityAlerts

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

    .PARAMETER AlertId
    AlertId is the parameter specifying a specific alert ID to retrieve.
    Default: All alerts will be retrieved if not specified.

    .PARAMETER DaysBack
    Number of days to look back for alerts.
    Default: 90

    .PARAMETER Filter
    Custom filter string to apply to the alert retrieval.
    Default: None

    .EXAMPLE
    Get-SecurityAlerts
    Retrieves all security alerts from the past 30 days.

    .EXAMPLE
    Get-SecurityAlerts -AlertId "123456-abcdef-7890"
    Retrieves a specific security alert by ID.

    .EXAMPLE
    Get-SecurityAlerts -DaysBack 7
    Retrieves security alerts from the past 7 days.

    .EXAMPLE
    Get-SecurityAlerts -Filter "severity eq 'high'"
    Retrieves high severity security alerts.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [string]$AlertId,
        [int]$DaysBack = 90,
        [string]$Filter,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging
    Init-OutputDir -Component "SecurityAlerts" -FilePostfix "SecurityAlerts" -CustomOutputDir $OutputDir

    Write-LogFile -Message "=== Starting Security Alerts Collection ===" -Color "Cyan" -Level Standard

    $requiredScopes = @("SecurityEvents.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
    Write-LogFile -Message "[INFO] Analyzing security alerts..." -Level Standard

    try {
        # Choose the appropriate cmdlet based on auth type
        if ($graphAuth.Type -eq "Application") {
            #Write-LogFile -Message "[INFO] Using application authentication - selecting Get-MgSecurityAlertV2" -Level Standard
            $cmdlet = "Get-MgSecurityAlertV2"
        } else {
            #Write-LogFile -Message "[INFO] Using delegated authentication - selecting Get-MgSecurityAlert" -Level Standard
            $cmdlet = "Get-MgSecurityAlert"
        }

        $params = @{}
        if ($AlertId) {
            Write-LogFile -Message "[INFO] Retrieving specific alert: $AlertId" -Level Standard
            $params.Add("AlertId", $AlertId)
        }
        else {
            if ($DaysBack -gt 0) {
                $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddT00:00:00Z")

                if ($Filter) {
                    $timeFilter = "createdDateTime ge $startDate"
                    $params.Add("Filter", "($Filter) and ($timeFilter)")
                    Write-LogFile -Message "[INFO] Using combined filter: $($params.Filter)" -Level Standard
                }
                else {
                    $params.Add("Filter", "createdDateTime ge $startDate")
                    Write-LogFile -Message "[INFO] Filtering alerts from $startDate" -Level Standard
                }
            }
            elseif ($Filter) {
                $params.Add("Filter", $Filter)
                Write-LogFile -Message "[INFO] Using custom filter: $Filter" -Level Standard
            }

            $params.Add("All", $true)
        }

        if ($cmdlet -eq "Get-MgSecurityAlert") {
            if ($AlertId) {
                $alerts = Get-MgSecurityAlert -AlertId $AlertId
            } else {
                $alerts = Get-MgSecurityAlert @params
            }
        } else {
            if ($AlertId) {
                $alerts = Get-MgSecurityAlertV2 -AlertId $AlertId
            } else {
                $alerts = Get-MgSecurityAlertV2 @params
            }
        }

        $alertSummary = @{
            TotalAlerts = 0
            SeverityHigh = 0
            SeverityMedium = 0
            SeverityLow = 0
            SeverityInformational = 0
            StatusNew = 0
            StatusInProgress = 0
            StatusResolved = 0
            StatusDismissed = 0
            StatusUnknown = 0
        }

        $formattedAlerts = [System.Collections.Generic.List[object]]::new($alerts.Count)
        foreach ($alert in $alerts) {
            $alertSummary.TotalAlerts++

            switch ($alert.Severity) {
                "high" { $alertSummary.SeverityHigh++ }
                "medium" { $alertSummary.SeverityMedium++ }
                "low" { $alertSummary.SeverityLow++ }
                "informational" { $alertSummary.SeverityInformational++ }
            }

            switch ($alert.Status) {
                "newAlert" { $alertSummary.StatusNew++ }
                "new" { $alertSummary.StatusNew++ }
                "inProgress" { $alertSummary.StatusInProgress++ }
                "resolved" { $alertSummary.StatusResolved++ }
                "dismissed" { $alertSummary.StatusDismissed++ }
                default { $alertSummary.StatusUnknown++ }
            }

            # Extract affected users, handling both null and populated UserStates
            $affectedUsers = ""
            if ($alert.UserStates -and $alert.UserStates.Count -gt 0) {
                $userDetails = [System.Collections.Generic.List[string]]::new()
                foreach ($userState in $alert.UserStates) {
                    if ($userState.UserPrincipalName) {
                        $userInfo = $userState.UserPrincipalName
                        if ($userState.LogonIP) {
                            $userInfo += "/$($userState.LogonIP)"
                        } else {
                            $userInfo += "/null"
                        }
                        $userDetails.Add($userInfo)
                    } elseif ($userState.Name) {
                        $userDetails.Add("$($userState.Name)/null")
                    }
                }
                $affectedUsers = $userDetails -join "; "
            }

            $affectedHosts = ""
            if ($alert.HostStates -and $alert.HostStates.Count -gt 0) {
                $hostDetails = [System.Collections.Generic.List[string]]::new()
                foreach ($hostState in $alert.HostStates) {
                    $hostInfo = ""
                    if ($hostState.NetBiosName) {
                        $hostInfo = $hostState.NetBiosName
                    } elseif ($hostState.PrivateHostName) {
                        $hostInfo = $hostState.PrivateHostName
                    } else {
                        $hostInfo = "Unknown"
                    }

                    if ($hostState.PrivateIpAddress) {
                        $hostInfo += "/$($hostState.PrivateIpAddress)"
                    } else {
                        $hostInfo += "/null"
                    }

                    $hostDetails.Add($hostInfo)
                }
                $affectedHosts = $hostDetails -join "; "
            }

            $sourceURLs = if ($alert.SourceMaterials) { ($alert.SourceMaterials -join "; ") } else { "" }

            $cloudApps = ""
            if ($alert.CloudAppStates -and $alert.CloudAppStates.Count -gt 0) {
                $cloudAppList = [System.Collections.Generic.List[string]]::new()
                foreach ($cloudApp in $alert.CloudAppStates) {
                    $cloudAppList.Add("$($cloudApp.Name): $($cloudApp.InstanceName)")
                }
                $cloudApps = $cloudAppList -join "; "
            }

            $comments = ""
            if ($alert.Comments -and $alert.Comments.Count -gt 0) {
                $commentList = [System.Collections.Generic.List[string]]::new()
                foreach ($comment in $alert.Comments) {
                    if ($comment.CreatedBy.User.DisplayName) {
                        $commentList.Add("$($comment.Comment) - $($comment.CreatedBy.User.DisplayName)")
                    } else {
                        $commentList.Add($comment.Comment)
                    }
                }
                $comments = $commentList -join "; "
            }

            $formattedAlerts.Add([PSCustomObject]@{
                Id = $alert.Id
                Title = $alert.Title
                Category = $alert.Category
                Severity = $alert.Severity
                Status = $alert.Status
                CreatedDateTime = $alert.CreatedDateTime
                EventDateTime = $alert.EventDateTime
                LastModifiedDateTime = $alert.LastModifiedDateTime
                AssignedTo = $alert.AssignedTo
                Description = $alert.Description
                DetectionSource = $alert.DetectionSource
                AffectedUser = $affectedUsers
                AffectedHost = $affectedHosts
                AzureTenantId = $alert.AzureTenantId
                AzureSubscriptionId = $alert.AzureSubscriptionId
                Confidence = $alert.Confidence
                ActivityGroupName = $alert.ActivityGroupName
                ClosedDateTime = $alert.ClosedDateTime
                Feedback = $alert.Feedback
                LastEventDateTime = $alert.LastEventDateTime
                SourceURL = $sourceURLs
                CloudAppStates = $cloudApps
                Comments = $comments
                Tags = if ($alert.Tags) { ($alert.Tags -join ", ") } else { "" }
                Vendor = $alert.VendorInformation.Vendor
                Provider = $alert.VendorInformation.Provider
                SubProvider = $alert.VendorInformation.SubProvider
                ProviderVersion = $alert.VendorInformation.ProviderVersion
                IncidentIds = if ($alert.IncidentIds) { ($alert.IncidentIds -join ", ") } else { "" }
            })
        }

        $formattedAlerts | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding

        $summary = [ordered]@{
            "Alert Summary" = [ordered]@{
                "Total Alerts" = $alertSummary.TotalAlerts
            }
            "Severity Distribution" = [ordered]@{
                "High" = $alertSummary.SeverityHigh
                "Medium" = $alertSummary.SeverityMedium
                "Low" = $alertSummary.SeverityLow
                "Informational" = $alertSummary.SeverityInformational
            }
            "Status Distribution" = [ordered]@{
                "New" = $alertSummary.StatusNew
                "In Progress" = $alertSummary.StatusInProgress
                "Resolved" = $alertSummary.StatusResolved
                "Dismissed" = $alertSummary.StatusDismissed
                "Unknown" = $alertSummary.StatusUnknown
            }
        }

        Write-Summary -Summary $summary -Title "Security Alerts Analysis"
    }
    catch {
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }
}
