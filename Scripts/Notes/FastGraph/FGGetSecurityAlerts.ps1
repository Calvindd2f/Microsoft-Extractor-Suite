# ================================================================
# Get-SecurityAlerts — FAST (v1.0 alerts or beta alerts_v2)
# ================================================================
function Get-SecurityAlertsFast {
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\SecurityAlerts",
        [string]$Encoding = "UTF8",
        [string]$AlertId,
        [int]$DaysBack = 90,
        [string]$Filter,
        [ValidateSet('None','Minimal','Standard')] [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $date = (Get-Date).ToString('yyyyMMddHHmm')
    Write-LogFile -Message "=== Starting Security Alerts Collection (fast) ===" -Color "Cyan" -Level Standard
    UpsertOutputDirectory $OutputDir
    $graphAuth = Get-GraphAuthType -RequiredScopes @('SecurityEvents.Read.All')

    # choose API surface like your cmdlet chooser
    $useV2 = ($graphAuth.AuthType -eq 'Application') # mirror your “V2 when app auth” choice
    $root  = if ($useV2) { "$($script:BaseGraphUri)/beta/security/alerts_v2" } else { "$($script:BaseGraphUri)/v1.0/security/alerts" }

    # build filter
    $flt = $null
    if ($AlertId) {
        $uri = "$root/$AlertId"
    } else {
        $clauses = @()
        if ($DaysBack -gt 0) {
            $since = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddT00:00:00Z")
            $clauses += "createdDateTime ge $since"
        }
        if ($Filter) { $clauses += "($Filter)" }
        if ($clauses.Count) { $flt = $clauses -join ' and ' }
        $uri = if ($flt) { "$root?`$filter=$([System.Web.HttpUtility]::UrlEncode($flt))&`$top=999" } else { "$root?`$top=999" }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    $summary = @{
        TotalAlerts=0; SeverityHigh=0; SeverityMedium=0; SeverityLow=0; SeverityInformational=0;
        StatusNew=0; StatusInProgress=0; StatusResolved=0; StatusDismissed=0; StatusUnknown=0
    }

    if ($AlertId) {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $a = $doc.RootElement
            $rows.Add( (ConvertTo-AlertRow $a -UseV2:$useV2 -Summary $summary) ) | Out-Null
        } finally { $doc.Dispose() }
    } else {
        do {
            $doc = Invoke-GraphGet -Uri $uri
            try {
                $rootEl = $doc.RootElement
                $val = J-GetElem -E $rootEl -Name 'value'
                if ($val -and $val.ValueKind -eq 'Array') {
                    for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                        $rows.Add( (ConvertTo-AlertRow $val[$i] -UseV2:$useV2 -Summary $summary) ) | Out-Null
                    }
                }
                $next=$null; foreach($p in $rootEl.EnumerateObject()){ if($p.Name -eq '@odata.nextLink'){ $next=$p.Value.GetString(); break } }
                $uri = $next
            } finally { $doc.Dispose() }
        } while ($uri)
    }

    $out = Join-Path $OutputDir "$date-SecurityAlerts.csv"
    $rows | Export-Csv -Path $out -NoTypeInformation -Encoding $Encoding

    Write-LogFile -Message "`nSecurity Alert Analysis Results:" -Color "Cyan" -Level Standard
    Write-LogFile -Message "Total Alerts: $($summary.TotalAlerts)" -Level Standard
    Write-LogFile -Message "`nSeverity Distribution:" -Level Standard
    Write-LogFile -Message "  - High: $($summary.SeverityHigh)" -Level Standard
    Write-LogFile -Message "  - Medium: $($summary.SeverityMedium)" -Level Standard
    Write-LogFile -Message "  - Low: $($summary.SeverityLow)" -Level Standard
    Write-LogFile -Message "  - Informational: $($summary.SeverityInformational)" -Level Standard
    Write-LogFile -Message "`nStatus Distribution:" -Level Standard
    Write-LogFile -Message "  - New: $($summary.StatusNew)" -Level Standard
    Write-LogFile -Message "  - In Progress: $($summary.StatusInProgress)" -Level Standard
    Write-LogFile -Message "  - Resolved: $($summary.StatusResolved)" -Level Standard
    Write-LogFile -Message "  - Dismissed: $($summary.StatusDismissed)" -Level Standard
    Write-LogFile -Message "  - Unknown: $($summary.StatusUnknown)" -Level Standard
    Write-LogFile -Message "`nExported File:`n  - $out" -Color "Cyan" -Level Standard
}

# Helper used by Get-SecurityAlertsFast
function ConvertTo-AlertRow {
    param(
        [Parameter(Mandatory)] $E,  # JsonElement
        [switch]$UseV2,
        [Parameter(Mandatory)] [ref]$Summary
    )
    $get = { param($n) $s = $E.GetProperty($n); if($s.ValueKind -eq 'Null'){ $null } else { $s.GetString() } } # quick getter

    $severity = & $get 'severity'
    switch ($severity) {
        'high' {'SeverityHigh'; $Summary.Value.SeverityHigh++}
        'medium' {'SeverityMedium'; $Summary.Value.SeverityMedium++}
        'low' {'SeverityLow'; $Summary.Value.SeverityLow++}
        'informational' {'SeverityInformational'; $Summary.Value.SeverityInformational++}
        default {}
    } | Out-Null

    $status = & $get 'status'
    switch ($status) {
        'new'        { $Summary.Value.StatusNew++ }
        'inProgress' { $Summary.Value.StatusInProgress++ }
        'resolved'   { $Summary.Value.StatusResolved++ }
        'dismissed'  { $Summary.Value.StatusDismissed++ }
        default      { $Summary.Value.StatusUnknown++ }
    } | Out-Null

    $Summary.Value.TotalAlerts++

    # UserStates/HostStates materialization (if arrays exist)
    function Join-UserStates($el){
        try {
            $us = $el.GetProperty('userStates'); if($us.ValueKind -ne 'Array'){ return '' }
            $acc=@()
            for($i=0;$i -lt $us.GetArrayLength();$i++){
                $u=$us[$i]
                $upn = if($u.TryGetProperty('userPrincipalName',[ref]$null)){ $u.GetProperty('userPrincipalName').GetString() } else { $null }
                $ip  = if($u.TryGetProperty('logonIp',[ref]$null)){ $u.GetProperty('logonIp').GetString() } else { $null }
                if($upn){ $acc+= "$upn/$($ip ?? 'null')" }
            }
            $acc -join '; '
        } catch { '' }
    }
    function Join-HostStates($el){
        try {
            $hs = $el.GetProperty('hostStates'); if($hs.ValueKind -ne 'Array'){ return '' }
            $acc=@()
            for($i=0;$i -lt $hs.GetArrayLength();$i++){
                $h=$hs[$i]
                $name = if($h.TryGetProperty('netBiosName',[ref]$null)){ $h.GetProperty('netBiosName').GetString() }
                        elseif($h.TryGetProperty('privateHostName',[ref]$null)){ $h.GetProperty('privateHostName').GetString() }
                        else { 'Unknown' }
                $ip = if($h.TryGetProperty('privateIpAddress',[ref]$null)){ $h.GetProperty('privateIpAddress').GetString() } else { $null }
                $acc+= "$name/$($ip ?? 'null')"
            }
            $acc -join '; '
        } catch { '' }
    }
    function Join-Strings($el,$name){
        try {
            $arr = $el.GetProperty($name); if($arr.ValueKind -ne 'Array'){ return '' }
            $list=@(); for($i=0;$i -lt $arr.GetArrayLength();$i++){ $list += $arr[$i].GetString() }
            $list -join '; '
        } catch { '' }
    }
    function Join-CloudApps($el){
        try {
            $arr = $el.GetProperty('cloudAppStates'); if($arr.ValueKind -ne 'Array'){ return '' }
            $list=@()
            for($i=0;$i -lt $arr.GetArrayLength();$i++){
                $x=$arr[$i]
                $n = if($x.TryGetProperty('name',[ref]$null)){ $x.GetProperty('name').GetString() } else { '' }
                $ins= if($x.TryGetProperty('instanceName',[ref]$null)){ $x.GetProperty('instanceName').GetString() } else { '' }
                $list += "$n: $ins"
            }
            $list -join '; '
        } catch { '' }
    }
    function Join-Comments($el){
        try {
            $arr = $el.GetProperty('comments'); if($arr.ValueKind -ne 'Array'){ return '' }
            $list=@()
            for($i=0;$i -lt $arr.GetArrayLength();$i++){
                $c=$arr[$i]
                $txt = if($c.TryGetProperty('comment',[ref]$null)){ $c.GetProperty('comment').GetString() } else { '' }
                $by  = if($c.TryGetProperty('createdBy',[ref]$null) -and $c.GetProperty('createdBy').TryGetProperty('user',[ref]$null)){
                        $c.GetProperty('createdBy').GetProperty('user').GetProperty('displayName').GetString()
                      } else { $null }
                if($by){ $list += "$txt - $by" } else { $list += $txt }
            }
            $list -join '; '
        } catch { '' }
    }

    [pscustomobject]@{
        Id                     = (&$get 'id')
        Title                  = (&$get 'title')
        Category               = (&$get 'category')
        Severity               = $severity
        Status                 = $status
        CreatedDateTime        = (&$get 'createdDateTime')
        EventDateTime          = (&$get 'eventDateTime')
        LastModifiedDateTime   = (&$get 'lastModifiedDateTime')
        AssignedTo             = (&$get 'assignedTo')
        Description            = (&$get 'description')
        DetectionSource        = (&$get 'detectionSource')
        AffectedUser           = (Join-UserStates $E)
        AffectedHost           = (Join-HostStates $E)
        AzureTenantId          = (&$get 'azureTenantId')
        AzureSubscriptionId    = (&$get 'azureSubscriptionId')
        Confidence             = (&$get 'confidence')
        ActivityGroupName      = (&$get 'activityGroupName')
        ClosedDateTime         = (&$get 'closedDateTime')
        Feedback               = (&$get 'feedback')
        LastEventDateTime      = (&$get 'lastEventDateTime')
        SourceURL              = (Join-Strings $E 'sourceMaterials')
        CloudAppStates         = (Join-CloudApps $E)
        Comments               = (Join-Comments $E)
        Tags                   = (Join-Strings $E 'tags')
        Vendor                 = try { $E.GetProperty('vendorInformation').GetProperty('vendor').GetString() } catch { $null }
        Provider               = try { $E.GetProperty('vendorInformation').GetProperty('provider').GetString() } catch { $null }
        SubProvider            = try { $E.GetProperty('vendorInformation').GetProperty('subProvider').GetString() } catch { $null }
        ProviderVersion        = try { $E.GetProperty('vendorInformation').GetProperty('providerVersion').GetString() } catch { $null }
        IncidentIds            = (Join-Strings $E 'incidentIds')
    }
}
