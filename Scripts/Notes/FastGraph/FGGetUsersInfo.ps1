# ================================================================
# Get-AdminUsers — FAST (per-role CSVs + merged file; user-only)
# ================================================================
function Get-AdminUsersFast {
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Admins",
        [string]$Encoding = "UTF8",
        [ValidateSet('None','Minimal','Standard','Debug')] [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    $date = (Get-Date).ToString('yyyyMMddHHmm')
    Write-LogFile -Message "=== Starting Admin Users Collection (fast) ===" -Color "Cyan" -Level Standard
    UpsertOutputDirectory $OutputDir
    $null = Get-GraphAuthType -RequiredScopes @('User.Read.All','Directory.Read.All')

    # Get roles
    $roles = @()
    $uri = "$($script:BaseGraphUri)/v1.0/directoryRoles?`$select=id,displayName&`$top=999"
    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement; $val = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e = $val[$i]
                    $roles += [pscustomobject]@{
                        id = J-GetStr -E $e -Name 'id'
                        name = J-GetStr -E $e -Name 'displayName'
                    }
                }
            }
            $next=$null; foreach($p in $root.EnumerateObject()){ if($p.Name -eq '@odata.nextLink'){ $next=$p.Value.GetString(); break } }
            $uri = $next
        } finally { $doc.Dispose() }
    } while ($uri)

    $rolesWithUsers = @()
    $rolesWithoutUsers = @()

    foreach ($r in $roles) {
        if ($r.name -notlike '*Admin*') { continue }   # match your “Administrator roles” intent
        if ($isDebug) { Write-LogFile -Message "[DEBUG] Processing role: $($r.name)" -Level Debug }

        # Fetch members
        $members = @()
        $muri = "$($script:BaseGraphUri)/v1.0/directoryRoles/$($r.id)/members?`$select=id,displayName,userPrincipalName,@odata.type&`$top=999"
        do {
            $doc = Invoke-GraphGet -Uri $muri
            try {
                $root=$doc.RootElement; $val=J-GetElem -E $root -Name 'value'
                if ($val -and $val.ValueKind -eq 'Array') {
                    for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                        $e=$val[$i]
                        $typ=$null; foreach($p in $e.EnumerateObject()){ if($p.Name -eq '@odata.type'){ $typ=$p.Value.GetString(); break } }
                        if ($typ -match '\.user$') {
                            $members += [pscustomobject]@{
                                id  = J-GetStr -E $e -Name 'id'
                                upn = J-GetStr -E $e -Name 'userPrincipalName'
                                dn  = J-GetStr -E $e -Name 'displayName'
                            }
                        }
                    }
                }
                $next=$null; foreach($p in $root.EnumerateObject()){ if($p.Name -eq '@odata.nextLink'){ $next=$p.Value.GetString(); break } }
                $muri = $next
            } finally { $doc.Dispose() }
        } while ($muri)

        if (-not $members.Count) { $rolesWithoutUsers += $r.name; continue }

        # Batch pull signInActivity etc. for members
        $rows = New-Object System.Collections.Generic.List[object]
        for ($i=0; $i -lt $members.Count; $i+=20) {
            $chunk = $members[$i..([Math]::Min($i+19,$members.Count-1))]
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
                    $rows.Add([pscustomobject]@{
                        UserName                = $b.userPrincipalName
                        UserId                  = $uid
                        Role                    = $r.name
                        DisplayName             = $b.displayName
                        Department              = $b.department
                        JobTitle                = $b.jobTitle
                        AccountEnabled          = $b.accountEnabled
                        CreatedDateTime         = $b.createdDateTime
                        LastInteractiveSignIn   = $li
                        LastNonInteractiveSignIn= $ln
                        DaysSinceLastSignIn     = $days
                    }) | Out-Null
                }
            }
        }

        if ($rows.Count) {
            $rolesWithUsers += "$($r.name) ($($rows.Count) users)"
            $file = Join-Path $OutputDir "$date-$($r.name.Replace(' ','_')).csv"
            $rows | Export-Csv -Path $file -NoTypeInformation -Encoding $Encoding
        } else {
            $rolesWithoutUsers += $r.name
        }
    }

    # Merge “*Administrator*.csv” into Merged\…-All-Administrators.csv (to match your script)
    $mergedDir = Join-Path $OutputDir 'Merged'
    UpsertOutputDirectory $mergedDir
    $mergedFile = Join-Path $mergedDir "$date-All-Administrators.csv"
    Get-ChildItem $OutputDir -Filter "*Administrator*.csv" |
        Select-Object -ExpandProperty FullName |
        Import-Csv |
        Export-Csv $mergedFile -NoTypeInformation -Encoding $Encoding

    Write-LogFile -Message "`nRoles with users:" -Color "Green" -Level Standard
    foreach ($role in $rolesWithUsers) { Write-LogFile -Message "  + $role" -Level Standard }
    Write-LogFile -Message "`nEmpty roles:" -Color "Yellow" -Level Standard
    foreach ($role in $rolesWithoutUsers) { Write-LogFile -Message "  - $role" -Level Standard }

    Write-LogFile -Message "`nExported files:" -Color "Cyan" -Level Standard
    Write-LogFile -Message "  Individual role files: $OutputDir" -Level Standard
    Write-LogFile -Message "  Merged file: $mergedFile" -Level Standard
}
