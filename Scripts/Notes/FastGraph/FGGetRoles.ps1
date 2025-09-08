# ===================================================================
# DIRECTORY ROLES + LAST SIGN-IN — FAST
# ===================================================================
function Get-AllRoleActivityFast {
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Roles",
        [string]$Encoding = "UTF8",
        [switch]$IncludeEmptyRoles = $false,
        [ValidateSet('None','Minimal','Standard')] [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    Write-LogFile -Message "=== Starting Directory Role Membership Export (fast) ===" -Color "Cyan" -Level Standard
    UpsertOutputDirectory $OutputDir
    $null = Get-GraphAuthType -RequiredScopes @('User.Read.All','Directory.Read.All','AuditLog.Read.All')

    $roles = @()
    $uri = "$($script:BaseGraphUri)/v1.0/directoryRoles?`$top=999"
    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement; $val = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e = $val[$i]
                    $roles += [pscustomobject]@{
                        id = J-GetStr -E $e -Name 'id'
                        displayName = J-GetStr -E $e -Name 'displayName'
                    }
                }
            }
            $next=$null; foreach($p in $root.EnumerateObject()){ if($p.Name -eq '@odata.nextLink'){ $next=$p.Value.GetString(); break } }
            $uri = $next
        } finally { $doc.Dispose() }
    } while ($uri)

    Write-LogFile -Message "[INFO] Found $($roles.Count) directory roles" -Level Standard

    $date = (Get-Date).ToString('yyyyMMddHHmm')
    $out  = Join-Path $OutputDir "$date-All-Roles.csv"
    $sw = New-Object System.IO.StreamWriter($out,$false,[System.Text.Encoding]::UTF8)
    try {
        $sw.WriteLine('Role,UserName,UserId,DisplayName,Department,JobTitle,AccountEnabled,CreatedDateTime,LastInteractiveSignIn,LastNonInteractiveSignIn,DaysSinceLastSignIn')

        foreach ($r in $roles) {
            # members
            $members = @()
            $muri = "$($script:BaseGraphUri)/v1.0/directoryRoles/$($r.id)/members?`$select=id,displayName,userPrincipalName,@odata.type&`$top=999"
            do {
                $doc = Invoke-GraphGet -Uri $muri
                try {
                    $root = $doc.RootElement; $val = J-GetElem -E $root -Name 'value'
                    if ($val -and $val.ValueKind -eq 'Array') {
                        for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                            $e=$val[$i]
                            $type = $null; foreach($p in $e.EnumerateObject()){ if($p.Name -eq '@odata.type'){ $type=$p.Value.GetString(); break } }
                            $members += [pscustomobject]@{
                                id   = J-GetStr -E $e -Name 'id'
                                upn  = J-GetStr -E $e -Name 'userPrincipalName'
                                dn   = J-GetStr -E $e -Name 'displayName'
                                type = $type
                            }
                        }
                    }
                    $next=$null; foreach($p in $root.EnumerateObject()){ if($p.Name -eq '@odata.nextLink'){ $next=$p.Value.GetString(); break } }
                    $muri = $next
                } finally { $doc.Dispose() }
            } while ($muri)

            if (-not $members.Count) {
                if ($IncludeEmptyRoles) { Write-LogFile -Message "  - $($r.displayName): no members" -Level Standard }
                continue
            }

            # only user members (skip service principals, etc.)
            $userMembers = $members | Where-Object { $_.type -match '\.user$' }
            if (-not $userMembers.Count) { continue }

            # batch fetch user details (20 per batch)
            for ($i=0; $i -lt $userMembers.Count; $i+=20) {
                $chunk = $userMembers[$i..([Math]::Min($i+19,$userMembers.Count-1))]
                $reqs = New-Object System.Collections.Generic.List[object]
                foreach ($u in $chunk) {
                    $reqs.Add(@{
                        id=$u.id; method='GET';
                        url="users/$($u.id)?`$select=userPrincipalName,displayName,department,jobTitle,accountEnabled,createdDateTime,signInActivity"
                    })
                }
                $resp = Invoke-GffBatch -Requests $reqs

                foreach ($rsp in $resp.responses) {
                    $uid = $rsp.id
                    $u = $chunk | Where-Object { $_.id -eq $uid } | Select-Object -First 1
                    if (-not $u) { continue }

                    if ($rsp.status -ge 200 -and $rsp.status -lt 300 -and $rsp.body) {
                        $b = $rsp.body
                        $li = $b.signInActivity.lastSignInDateTime
                        $ln = $b.signInActivity.lastNonInteractiveSignInDateTime
                        $days = 'No sign-in data'
                        if ($li) { try { $days = (New-TimeSpan -Start ([datetime]$li) -End (Get-Date)).Days } catch {} }
                        $sw.WriteLine( ('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}' -f `
                            ($r.displayName -replace ',',''), $b.userPrincipalName, $uid, ($b.displayName -replace ',',''),
                            ($b.department -replace ',',''), ($b.jobTitle -replace ',',''), $b.accountEnabled,
                            $b.createdDateTime, $li, $ln, $days) )
                    } else {
                        # fallback with whatever we have
                        $sw.WriteLine( ('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}' -f `
                            ($r.displayName -replace ',',''), $u.upn, $u.id, ($u.dn -replace ',',''),
                            '','','','','','','Error') )
                    }
                }
            }
        }
    } finally { $sw.Flush(); $sw.Dispose() }

    Write-LogFile -Message "Exported file: $out" -Level Standard
}

# ===================================================================
# PIM ROLE ASSIGNMENTS — FAST (beta)
# ===================================================================
function Get-PIMAssignmentsFast {
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Roles",
        [string]$Encoding = "UTF8",
        [ValidateSet('None','Minimal','Standard')] [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    Write-LogFile -Message "=== Starting PIM Role Assignment Export (fast) ===" -Color "Cyan" -Level Standard
    UpsertOutputDirectory $OutputDir
    $null = Get-GraphAuthType -RequiredScopes @(
        'RoleAssignmentSchedule.Read.Directory','RoleEligibilitySchedule.Read.Directory','User.Read.All','Group.Read.All'
    )

    $all = New-Object System.Collections.Generic.List[object]

    function Get-AllPages($firstUri){
        $acc = @()
        $uri = $firstUri
        do {
            $doc = Invoke-GraphGet -Uri $uri
            try {
                $root=$doc.RootElement; $val=J-GetElem -E $root -Name 'value'
                if ($val -and $val.ValueKind -eq 'Array') {
                    for ($i=0; $i -lt $val.GetArrayLength(); $i++) { $acc += $val[$i] }
                }
                $next=$null; foreach($p in $root.EnumerateObject()){ if($p.Name -eq '@odata.nextLink'){ $next=$p.Value.GetString(); break } }
                $uri=$next
            } finally { $doc.Dispose() }
        } while ($uri)
        ,$acc
    }

    # Active schedules
    $actUri = "$($script:BaseGraphUri)/beta/roleManagement/directory/roleAssignmentSchedules?`$expand=principal,roleDefinition"
    $act = Get-AllPages $actUri
    Write-LogFile -Message "[INFO] Active PIM schedules: $($act.Count)" -Level Standard

    # Eligible schedules
    $eligUri = "$($script:BaseGraphUri)/beta/roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition"
    $elig = Get-AllPages $eligUri
    Write-LogFile -Message "[INFO] Eligible PIM schedules: $($elig.Count)" -Level Standard

    # Helper to expand group members -> user rows
    function Add-GroupPrincipalRows($roleName,$assignment,$status){
        $g = $assignment.GetProperty('principal')
        $gid = J-GetStr -E $assignment -Name 'principalId'
        $gname = J-GetStr -E $g -Name 'displayName'
        if (-not $gid) { return }

        $members = @()
        $muri = "$($script:BaseGraphUri)/v1.0/groups/$gid/members?`$select=id&`$top=999"
        do {
            $doc = Invoke-GraphGet -Uri $muri
            try {
                $root=$doc.RootElement; $val=J-GetElem -E $root -Name 'value'
                if ($val -and $val.ValueKind -eq 'Array') {
                    for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                        $e=$val[$i]
                        $otype=$null; foreach($p in $e.EnumerateObject()){ if($p.Name -eq '@odata.type'){ $otype=$p.Value.GetString(); break } }
                        if ($otype -and $otype -match '\.user$') { $members += (J-GetStr -E $e -Name 'id') }
                    }
                }
                $next=$null; foreach($p in $root.EnumerateObject()){ if($p.Name -eq '@odata.nextLink'){ $next=$p.Value.GetString(); break } }
                $muri=$next
            } finally { $doc.Dispose() }
        } while ($muri)

        if (-not $members.Count) { return }

        # Batch fetch user UPN/displayName for members
        for ($i=0; $i -lt $members.Count; $i+=20) {
            $chunk = $members[$i..([Math]::Min($i+19,$members.Count-1))]
            $reqs = New-Object System.Collections.Generic.List[object]
            foreach ($id in $chunk) {
                $reqs.Add(@{ id=$id; method='GET'; url="users/$id?`$select=userPrincipalName,displayName,onPremisesSyncEnabled" })
            }
            $resp = Invoke-GffBatch -Requests $reqs
            foreach ($r in $resp.responses) {
                if ($r.status -ge 200 -and $r.status -lt 300 -and $r.body) {
                    $b = $r.body
                    $all.Add([pscustomobject]@{
                        RoleName           = $roleName
                        UserPrincipalName  = $b.userPrincipalName
                        DisplayName        = $b.displayName
                        AssignmentType     = "PIM $status"
                        SourceType         = 'Group'
                        SourceName         = $gname
                        OnPremisesSynced   = [bool]$b.onPremisesSyncEnabled
                        AssignmentStatus   = $status
                        StartDateTime      = (J-GetStr -E (J-GetElem -E $assignment -Name 'scheduleInfo') -Name 'startDateTime')
                        EndDateTime        = (J-GetStr -E (J-GetElem -E (J-GetElem -E $assignment -Name 'scheduleInfo') -Name 'expiration') -Name 'endDateTime')
                        DirectoryScopeId   = J-GetStr -E $assignment -Name 'directoryScopeId'
                    }) | Out-Null
                }
            }
        }
    }

    # Map one schedule element to rows
    function Add-PrincipalRow($assignment,$status){
        $roleName = J-GetStr -E (J-GetElem -E $assignment -Name 'roleDefinition') -Name 'displayName'
        $principal = J-GetElem -E $assignment -Name 'principal'
        $otype=$null; foreach($p in $principal.EnumerateObject()){ if($p.Name -eq '@odata.type'){ $otype=$p.Value.GetString(); break } }
        if ($otype -match '\.user$') {
            $upn = J-GetStr -E $principal -Name 'userPrincipalName'
            $dn  = J-GetStr -E $principal -Name 'displayName'
            $ops = J-GetStr -E $principal -Name 'onPremisesSyncEnabled'
            $all.Add([pscustomobject]@{
                RoleName           = $roleName
                UserPrincipalName  = $upn
                DisplayName        = $dn
                AssignmentType     = "PIM $status"
                SourceType         = 'Direct'
                SourceName         = 'N/A'
                OnPremisesSynced   = [bool]::Parse(($ops ?? 'false'))
                AssignmentStatus   = $status
                StartDateTime      = (J-GetStr -E (J-GetElem -E $assignment -Name 'scheduleInfo') -Name 'startDateTime')
                EndDateTime        = (J-GetStr -E (J-GetElem -E (J-GetElem -E $assignment -Name 'scheduleInfo') -Name 'expiration') -Name 'endDateTime')
                DirectoryScopeId   = J-GetStr -E $assignment -Name 'directoryScopeId'
            }) | Out-Null
        } elseif ($otype -match '\.group$') {
            Add-GroupPrincipalRows -roleName $roleName -assignment $assignment -status $status
        }
    }

    foreach ($a in $act)  { Add-PrincipalRow -assignment $a -status 'Active' }
    foreach ($e in $elig) { Add-PrincipalRow -assignment $e -status 'Eligible' }

    $date = (Get-Date).ToString('yyyyMMddHHmm')
    $out  = Join-Path $OutputDir "$date-PIM-Assignments.csv"
    $all | Export-Csv -NoTypeInformation -Encoding $Encoding -Path $out

    $total = $all.Count
    $pimActive   = ($all | Where-Object { $_.AssignmentStatus -eq 'Active' }).Count
    $pimEligible = ($all | Where-Object { $_.AssignmentStatus -eq 'Eligible' }).Count
    $direct      = ($all | Where-Object { $_.SourceType -eq 'Direct' }).Count
    $group       = ($all | Where-Object { $_.SourceType -eq 'Group' }).Count
    $onprem      = ($all | Where-Object { $_.OnPremisesSynced }).Count
    $cloudonly   = $total - $onprem

    Write-LogFile -Message "`nSummary:" -Color "Cyan" -Level Standard
    Write-LogFile -Message " - Total role assignments: $total" -Level Standard
    Write-LogFile -Message " - PIM Active: $pimActive" -Level Standard
    Write-LogFile -Message " - PIM Eligible: $pimEligible" -Level Standard
    Write-LogFile -Message " - Direct: $direct" -Level Standard
    Write-LogFile -Message " - Group: $group" -Level Standard
    Write-LogFile -Message " - On-prem synced users: $onprem" -Level Standard
    Write-LogFile -Message " - Cloud-only users: $cloudonly" -Level Standard
    Write-LogFile -Message "`nExported file:`n - $out" -Level Standard
}
