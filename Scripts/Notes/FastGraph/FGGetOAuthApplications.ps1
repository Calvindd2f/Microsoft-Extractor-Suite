# OAuthPermissions.Fast.psm1
# High-throughput OAuth permission inventory via Microsoft Graph (no Graph PS SDK/AzureAD module).
# - Single shared HttpClient + token cache
# - $select/$filter/$top everywhere
# - Streams pages; optional direct-to-CSV writer (no giant arrays)
# - Typed lists; no array +=
# - Honors Retry-After on 429/503; gzip enabled

using namespace System.Net
using namespace System.Net.Http
using namespace System.Text
using namespace System.Text.Json

# =========================
# Module-scope singletons
# =========================
$script:HttpClient = $null
$script:TokenInfo = [pscustomobject]@{ AccessToken = $null; ExpiresOn = (Get-Date 0) }
$script:GraphRoot = 'https://graph.microsoft.com'
$script:GraphVer = 'v1.0'

# =========================
# Core: Client + Auth
# =========================
function New-HttpClient {
    if ($script:HttpClient) { return $script:HttpClient }
    $handler = [SocketsHttpHandler]::new()
    $handler.AutomaticDecompression = [DecompressionMethods]::GZip -bor [DecompressionMethods]::Deflate
    $handler.PooledConnectionLifetime = [TimeSpan]::FromMinutes(10)
    $handler.MaxConnectionsPerServer = 32
    $client = [HttpClient]::new($handler)
    $client.DefaultRequestHeaders.TryAddWithoutValidation('Accept', 'application/json') | Out-Null
    $client.DefaultRequestHeaders.TryAddWithoutValidation('Accept-Encoding', 'gzip, deflate') | Out-Null
    $script:HttpClient = $client
    return $client
}

function Get-AppToken {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret,
        [string]$Scope = 'https://graph.microsoft.com/.default'
    )
    if ($script:TokenInfo.AccessToken -and (Get-Date) -lt $script:TokenInfo.ExpiresOn.AddSeconds(-90)) {
        return $script:TokenInfo.AccessToken
    }
    $uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = "client_id=$ClientId&scope=$([Uri]::EscapeDataString($Scope))&client_secret=$([Uri]::EscapeDataString($ClientSecret))&grant_type=client_credentials"
    $content = [StringContent]::new($body, [Encoding]::UTF8, 'application/x-www-form-urlencoded')
    $c = New-HttpClient
    $resp = $c.PostAsync($uri, $content).GetAwaiter().GetResult()
    if (-not $resp.IsSuccessStatusCode) {
        throw "Token request failed: $($resp.StatusCode) $( $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() )"
    }
    $doc = [JsonDocument]::Parse($resp.Content.ReadAsStream())
    $root = $doc.RootElement
    $script:TokenInfo = [pscustomobject]@{
        AccessToken = $root.GetProperty('access_token').GetString()
        ExpiresOn   = (Get-Date).AddSeconds($root.GetProperty('expires_in').GetInt32())
    }
    $doc.Dispose()
    return $script:TokenInfo.AccessToken
}

function Initialize-GraphFastClient {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret,
        [ValidateSet('v1.0', 'beta')][string]$Version = 'v1.0'
    )
    $null = New-HttpClient
    $script:GraphVer = $Version
    $token = Get-AppToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    $script:HttpClient.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
}

# =========================
# Core: GET + Paging
# =========================
function Invoke-GraphGet {
    param(
        [Parameter(Mandatory)][string]$Uri,       # absolute or relative (e.g., 'servicePrincipals?...')
        [hashtable]$Headers
    )
    $client = New-HttpClient
    if ($Uri -notmatch '^https?://') { $Uri = "$($script:GraphRoot)/$($script:GraphVer)/$Uri" }
    $attempt = 0
    while ($true) {
        $req = [HttpRequestMessage]::new([HttpMethod]::Get, $Uri)
        if ($Headers) { foreach ($k in $Headers.Keys) { $req.Headers.TryAddWithoutValidation($k, [string]$Headers[$k]) | Out-Null } }
        $resp = $client.SendAsync($req, [HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        if ($resp.IsSuccessStatusCode) {
            return [JsonDocument]::Parse($resp.Content.ReadAsStream())
        }
        if ($resp.StatusCode -in ([HttpStatusCode]::TooManyRequests, [HttpStatusCode]::ServiceUnavailable, [HttpStatusCode]::GatewayTimeout)) {
            $retry = 0
            if ($resp.Headers.RetryAfter -and $resp.Headers.RetryAfter.Delta) { $retry = [int][math]::Ceiling($resp.Headers.RetryAfter.Delta.Value.TotalSeconds) }
            if ($retry -le 0) { $attempt++; $retry = [Math]::Min(60, [Math]::Pow(2, $attempt)) + (Get-Random -Minimum 0 -Maximum 250) / 1000.0 }
            Start-Sleep -Seconds $retry
            continue
        }
        throw "GET $Uri failed: $($resp.StatusCode) $( $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() )"
    }
}

function Get-GraphPaged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,   # e.g., 'servicePrincipals'
        [string[]]$Select,
        [string]$Filter,
        [switch]$Count,
        [int]$Top = 999,
        [string]$ToCsv
    )
    # Build query (StringBuilder, no string concatenation)
    $sb = [StringBuilder]::new()
    [void]$sb.Append($Path)
    $q = $false
    function AddQ { param([string]$k, [string]$v) if (-not $script:q) { [void]$sb.Append('?'); $script:q = $true }else { [void]$sb.Append('&') }; [void]$sb.Append($k); [void]$sb.Append('='); [void]$sb.Append($v) }
    if ($Select -and $Path -notmatch '\$select=') { AddQ '$select' ([string]::Join(',', $Select)) }
    if ($Filter) { AddQ '$filter' ([Uri]::EscapeDataString($Filter)) }
    if ($Count) { AddQ '$count' 'true' }
    if ($Top -gt 0 -and $Path -notmatch '\$top=') { AddQ '$top' $Top }
    $headers = @{}
    if ($Count) { $headers['ConsistencyLevel'] = 'eventual' }
    $uri = $sb.ToString()

    $list = [System.Collections.Generic.List[object]]::new()
    $csv = $null
    if ($ToCsv) {
        $csv = @{
            Stream        = [IO.StreamWriter]::new($ToCsv, $false, [Text.Encoding]::UTF8)
            HeaderWritten = $false
            Headers       = $null
        }
    }

    while ($uri) {
        $doc = Invoke-GraphGet -Uri $uri -Headers $headers
        try {
            $root = $doc.RootElement
            $arr = $root.GetProperty('value')
            for ($i = 0; $i -lt $arr.GetArrayLength(); $i++) {
                $e = $arr[$i]
                $ht = [ordered]@{}
                foreach ($p in $e.EnumerateObject()) {
                    $ht[$p.Name] = switch ($p.Value.ValueKind) {
                        'String' { $p.Value.GetString() }
                        'Number' { try { $p.Value.GetInt64() } catch { $p.Value.GetDouble() } }
                        'True' { $true }
                        'False' { $false }
                        default { $p.Value.ToString() }
                    }
                }
                if ($csv) {
                    if (-not $csv.HeaderWritten) {
                        $csv.Headers = @($ht.Keys)
                        $csv.Stream.WriteLine(($csv.Headers -join ','))
                        $csv.HeaderWritten = $true
                    }
                    $line = ($csv.Headers | ForEach-Object { ($ht[$_]) -replace '"', '""' }) -join ','
                    $csv.Stream.WriteLine($line)
                }
                else {
                    [void]$list.Add([pscustomobject]$ht)
                }
            }
            $next = $null
            if ($root.TryGetProperty('@odata.nextLink', [ref]$next)) { $uri = $next.GetString() } else { $uri = $null }
        }
        finally { $doc.Dispose() }
    }
    if ($csv) { $csv.Stream.Flush(); $csv.Stream.Dispose() | Out-Null; return }
    return $list
}

# =========================
# Domain helpers (cache)
# =========================
$script:ObjectCache = @{}  # id -> object

function Get-CachedSp {
    param([Parameter(Mandatory)][string]$Id)
    if ($script:ObjectCache.ContainsKey($Id)) { return $script:ObjectCache[$Id] }
    # Minimal projection for SP lookups
    $sel = 'id,appId,displayName,publisherName,replyUrls,homepage,accountEnabled,appOwnerOrganizationId,servicePrincipalType,signInAudience,tags,appRoleAssignmentRequired,verifiedPublisher'
    $doc = Invoke-GraphGet -Uri ("servicePrincipals/$Id`?$select=$sel")
    try {
        $sp = $doc.RootElement
        if ($sp.ValueKind -ne 'Object') { return $null }
        $obj = [pscustomobject]@{
            id                        = $sp.GetProperty('id').GetString()
            appId                     = if ($sp.TryGetProperty('appId', [ref]([Text.Json.JsonElement]$null))) { $sp.GetProperty('appId').GetString() } else { $null }
            displayName               = $sp.GetProperty('displayName').GetString()
            publisherName             = if ($sp.TryGetProperty('publisherName', [ref]([Text.Json.JsonElement]$null))) { $sp.GetProperty('publisherName').GetString() } else { $null }
            replyUrls                 = @()
            homepage                  = if ($sp.TryGetProperty('homepage', [ref]([Text.Json.JsonElement]$null))) { $sp.GetProperty('homepage').GetString() } else { $null }
            accountEnabled            = if ($sp.TryGetProperty('accountEnabled', [ref]([Text.Json.JsonElement]$null))) { $sp.GetProperty('accountEnabled').GetBoolean() } else { $null }
            appOwnerOrganizationId    = if ($sp.TryGetProperty('appOwnerOrganizationId', [ref]([Text.Json.JsonElement]$null))) { $sp.GetProperty('appOwnerOrganizationId').GetString() } else { $null }
            servicePrincipalType      = if ($sp.TryGetProperty('servicePrincipalType', [ref]([Text.Json.JsonElement]$null))) { $sp.GetProperty('servicePrincipalType').GetString() } else { $null }
            signInAudience            = if ($sp.TryGetProperty('signInAudience', [ref]([Text.Json.JsonElement]$null))) { $sp.GetProperty('signInAudience').GetString() } else { $null }
            tags                      = @()
            appRoleAssignmentRequired = if ($sp.TryGetProperty('appRoleAssignmentRequired', [ref]([Text.Json.JsonElement]$null))) { $sp.GetProperty('appRoleAssignmentRequired').GetBoolean() } else { $false }
            verifiedPublisher         = if ($sp.TryGetProperty('verifiedPublisher', [ref]([Text.Json.JsonElement]$null))) { $sp.GetProperty('verifiedPublisher').ToString() } else { $null }
        }
        if ($sp.TryGetProperty('replyUrls', [ref]([Text.Json.JsonElement]$null))) {
            $urls = $sp.GetProperty('replyUrls')
            $arr = New-Object System.Collections.Generic.List[string]
            foreach ($u in $urls.EnumerateArray()) { [void]$arr.Add($u.GetString()) }
            $obj.replyUrls = $arr.ToArray()
        }
        if ($sp.TryGetProperty('tags', [ref]([Text.Json.JsonElement]$null))) {
            $tags = $sp.GetProperty('tags'); $arr2 = New-Object System.Collections.Generic.List[string]
            foreach ($t in $tags.EnumerateArray()) { [void]$arr2.Add($t.GetString()) }
            $obj.tags = $arr2.ToArray()
        }
        $script:ObjectCache[$Id] = $obj
        return $obj
    }
    finally { $doc.Dispose() }
}

function Get-CachedUserDisplayName {
    param([string]$Id)
    if (-not $Id) { return "" }
    if ($script:ObjectCache.ContainsKey($Id)) {
        $obj = $script:ObjectCache[$Id]
        if ($obj -and $obj.PSObject.Properties.Match('displayName').Count) { return $obj.displayName }
    }
    $doc = Invoke-GraphGet -Uri ("users/$Id`?$select=id,displayName")
    try {
        $root = $doc.RootElement
        if ($root.ValueKind -ne 'Object') { return "" }
        $dn = $root.GetProperty('displayName').GetString()
        $script:ObjectCache[$Id] = [pscustomobject]@{ id = $Id; displayName = $dn }
        return $dn
    }
    finally { $doc.Dispose() }
}

# =========================
# Inventory routines
# =========================

function Get-ServicePrincipalsFast {
    [CmdletBinding()]
    param(
        [int]$Top = 999,
        [string]$ToCsv
    )
    $select = @(
        'id', 'appId', 'displayName', 'publisherName', 'replyUrls', 'homepage',
        'accountEnabled', 'appOwnerOrganizationId', 'servicePrincipalType',
        'signInAudience', 'tags', 'appRoleAssignmentRequired', 'verifiedPublisher'
    )
    return Get-GraphPaged -Path 'servicePrincipals' -Select $select -Top $Top -ToCsv $ToCsv
}

function Get-OAuth2PermissionGrantsFast {
    [CmdletBinding()]
    param([int]$Top = 999)
    # Minimal set; scope string parsed client-side
    $select = @('id', 'clientId', 'resourceId', 'consentType', 'principalId', 'scope')
    return Get-GraphPaged -Path 'oauth2PermissionGrants' -Select $select -Top $Top
}

function Get-AppRoleAssignmentsForSpFast {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServicePrincipalId, [int]$Top = 999)
    $select = @('id', 'principalId', 'resourceId', 'appRoleId', 'createdDateTime')
    return Get-GraphPaged -Path "servicePrincipals/$ServicePrincipalId/appRoleAssignments" -Select $select -Top $Top
}

# =========================
# Public: Main report
# =========================

function Get-OAuthPermissionsFast {
    <#
    .SYNOPSIS
        High-performance export of delegated (OAuth2PermissionGrants) and application (AppRoleAssignments) permissions via Graph REST.

    .EXAMPLE
        Initialize-GraphFastClient -TenantId $env:AZ_TENANT_ID -ClientId $env:AZ_CLIENT_ID -ClientSecret $env:AZ_CLIENT_SECRET
        Get-OAuthPermissionsFast -OutputDir .\Output\OAuthPermissions
    #>
    [CmdletBinding()]
    param(
        [switch]$DelegatedPermissions,
        [switch]$ApplicationPermissions,
        [string]$OutputDir = "Output\OAuthPermissions",
        [string]$Encoding = "UTF8",
        [switch]$ShowProgress
    )

    if (-not (Test-Path $OutputDir)) { $null = New-Item -ItemType Directory -Force -Path $OutputDir }

    $summary = [pscustomobject]@{
        TotalPermissions           = 0
        DelegatedCount             = 0
        ApplicationCount           = 0
        ServicePrincipalsProcessed = 0
        DelegatedGrantsProcessed   = 0
        StartTime                  = (Get-Date)
        ProcessingTime             = $null
    }

    $date = Get-Date -Format "ddMMyyyyHHmmss"
    $out = Join-Path $OutputDir "$date-OAuthPermissions.csv"

    # Collector with typed list (unless we stream direct to CSV at the end)
    $rows = [System.Collections.Generic.List[object]]::new()

    # Pull + cache all SPs once (fast, minimal projection, single pass)
    $allSps = Get-ServicePrincipalsFast
    $summary.ServicePrincipalsProcessed = $allSps.Count
    foreach ($sp in $allSps) { $script:ObjectCache[$sp.id] = $sp }

    # Delegated permissions (OAuth2PermissionGrants)
    if ($DelegatedPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {
        $grants = Get-OAuth2PermissionGrantsFast
        $summary.DelegatedGrantsProcessed = $grants.Count
        $i = 0
        foreach ($g in $grants) {
            $i++
            if ($ShowProgress -and ($i % 100 -eq 0)) {
                Write-Progress -Activity "Delegated permissions" -Status "Grants processed: $i / $($grants.Count)" -PercentComplete (($i / $grants.Count) * 100)
            }
            $clientSp = Get-CachedSp -Id $g.clientId
            $resourceSp = Get-CachedSp -Id $g.resourceId
            if (-not $g.scope) { continue }
            foreach ($scope in ($g.scope -split ' ')) {
                if ([string]::IsNullOrWhiteSpace($scope)) { continue }
                $summary.DelegatedCount++

                # Derive helpful flags (mirror your original script’s intent)
                $publisherName = if ($clientSp.publisherName) { $clientSp.publisherName } elseif ($clientSp.displayName -like 'Microsoft*') { 'Microsoft' } else { '' }
                $applicationStatus = $(if ($clientSp.accountEnabled) { 'Enabled' } else { 'Disabled' })
                $applicationVisibility = $(if ($clientSp.tags -contains 'HideApp') { 'Hidden' } else { 'Visible' })
                $isAppProxy = $(if ($clientSp.tags -contains 'WindowsAzureActiveDirectoryOnPremApp') { 'Yes' } else { 'No' })
                $assignmentRequired = $(if ($clientSp.appRoleAssignmentRequired) { 'Yes' } else { 'No' })
                $types = New-Object System.Collections.Generic.List[string]
                if ($clientSp.appOwnerOrganizationId -in @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')) { [void]$types.Add('Microsoft Application') }
                if ($clientSp.servicePrincipalType -eq 'ManagedIdentity') { [void]$types.Add('Managed Identity') }
                if ($clientSp.tags -contains 'WindowsAzureActiveDirectoryIntegratedApp') { [void]$types.Add('Enterprise Application') }
                $applicationType = ($types -join ' & ')

                $principalDisplayName = if ($g.principalId) { Get-CachedUserDisplayName -Id $g.principalId } else { "" }

                $row = [pscustomobject]@{
                    PermissionType         = 'Delegated'
                    AppId                  = $clientSp.appId
                    ClientObjectId         = $g.clientId
                    AppDisplayName         = $clientSp.displayName
                    ResourceObjectId       = $g.resourceId
                    ResourceDisplayName    = $resourceSp.displayName
                    Permission             = $scope
                    ConsentType            = $g.consentType
                    PrincipalObjectId      = $g.principalId
                    PrincipalDisplayName   = $principalDisplayName
                    Homepage               = $clientSp.homepage
                    PublisherName          = $publisherName
                    ReplyUrls              = ($clientSp.replyUrls -join ', ')
                    ExpiryTime             = $g.expiryTime
                    AppOwnerOrganizationId = $clientSp.appOwnerOrganizationId
                    ApplicationStatus      = $applicationStatus
                    ApplicationVisibility  = $applicationVisibility
                    AssignmentRequired     = $assignmentRequired
                    IsAppProxy             = $isAppProxy
                    SignInAudience         = $clientSp.signInAudience
                    ApplicationType        = $applicationType
                }
                [void]$rows.Add($row)
            }
        }
    }

    # Application permissions (AppRoleAssignments where principals are SPs)
    if ($ApplicationPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {
        $j = 0
        foreach ($sp in $allSps) {
            $j++
            if ($ShowProgress -and ($j % 50 -eq 0)) {
                Write-Progress -Activity "Application permissions" -Status "Apps processed: $j / $($allSps.Count)" -PercentComplete (($j / $allSps.Count) * 100)
            }
            $assignments = Get-AppRoleAssignmentsForSpFast -ServicePrincipalId $sp.id
            foreach ($a in $assignments) {
                # Only service->service assignments matter here; principal is an SP
                # (Graph endpoint already scoped to SP; principal could be user/group in other contexts, but keep parity with original)
                $resourceSp = Get-CachedSp -Id $a.resourceId

                # Lookup matching appRole value by ID (cheap local search)
                $appRoleValue = $null
                if ($resourceSp -and $resourceSp.PSObject.Properties.Match('appRoles').Count) {
                    # If you later extend Get-CachedSp to include appRoles, resolve here.
                }
                # Fallback: fetch minimal appRoles only when needed
                if (-not $appRoleValue) {
                    $doc = Invoke-GraphGet -Uri ("servicePrincipals/$($a.resourceId)?`$select=id,appRoles")
                    try {
                        $roles = $doc.RootElement.GetProperty('appRoles')
                        for ($r = 0; $r -lt $roles.GetArrayLength(); $r++) {
                            $role = $roles[$r]
                            $rid = [Guid]$role.GetProperty('id').GetString()
                            if ($rid -eq [Guid]$a.appRoleId) {
                                $appRoleValue = $role.GetProperty('value').GetString()
                                break
                            }
                        }
                    }
                    finally { $doc.Dispose() }
                }

                $publisherName = if ($sp.publisherName) { $sp.publisherName } elseif ($sp.displayName -like 'Microsoft*') { 'Microsoft' } else { '' }
                $applicationStatus = $(if ($sp.accountEnabled) { 'Enabled' } else { 'Disabled' })
                $applicationVisibility = $(if ($sp.tags -contains 'HideApp') { 'Hidden' } else { 'Visible' })
                $isAppProxy = $(if ($sp.tags -contains 'WindowsAzureActiveDirectoryOnPremApp') { 'Yes' } else { 'No' })
                $assignmentRequired = $(if ($sp.appRoleAssignmentRequired) { 'Yes' } else { 'No' })
                $types2 = New-Object System.Collections.Generic.List[string]
                if ($sp.appOwnerOrganizationId -in @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')) { [void]$types2.Add('Microsoft Application') }
                if ($sp.servicePrincipalType -eq 'ManagedIdentity') { [void]$types2.Add('Managed Identity') }
                if ($sp.tags -contains 'WindowsAzureActiveDirectoryIntegratedApp') { [void]$types2.Add('Enterprise Application') }
                $applicationType2 = ($types2 -join ' & ')

                $row2 = [pscustomobject]@{
                    PermissionType         = 'Application'
                    AppId                  = $sp.appId
                    ClientObjectId         = $a.principalId
                    AppDisplayName         = $sp.displayName
                    ResourceObjectId       = $a.resourceId
                    ResourceDisplayName    = $resourceSp.displayName
                    Permission             = $appRoleValue
                    ConsentType            = 'AllPrincipals'
                    PrincipalObjectId      = $null
                    PrincipalDisplayName   = ''
                    Homepage               = $sp.homepage
                    PublisherName          = $publisherName
                    ReplyUrls              = ($sp.replyUrls -join ', ')
                    IsEnabled              = $null      # not returned by assignment, only by role; keep column for parity
                    Description            = $null
                    CreationTimestamp      = $a.createdDateTime
                    AppOwnerOrganizationId = $sp.appOwnerOrganizationId
                    ApplicationStatus      = $applicationStatus
                    ApplicationVisibility  = $applicationVisibility
                    AssignmentRequired     = $assignmentRequired
                    IsAppProxy             = $isAppProxy
                    SignInAudience         = $sp.signInAudience
                    ApplicationType        = $applicationType2
                }
                [void]$rows.Add($row2)
                $summary.ApplicationCount++
            }
        }
    }

    $summary.TotalPermissions = $summary.DelegatedCount + $summary.ApplicationCount
    $summary.ProcessingTime = (Get-Date) - $summary.StartTime

    # Export once (no mid-loop pipeline)
    $props = $rows.ForEach({ $_.PSObject.Properties.Name }) | Select-Object -Unique
    $rows | Select-Object $props | Export-Csv -NoTypeInformation -Path $out -Encoding $Encoding

    Write-Host ""
    Write-Host "=== OAuth Permissions Analysis Summary ==="
    Write-Host "Service Principals Processed: $($summary.ServicePrincipalsProcessed)"
    Write-Host "Delegated Grants Processed : $($summary.DelegatedGrantsProcessed)"
    Write-Host "Total Permissions Found     : $($summary.TotalPermissions)"
    Write-Host "  - Delegated              : $($summary.DelegatedCount)"
    Write-Host "  - Application            : $($summary.ApplicationCount)"
    Write-Host "Output File                : $out"
    Write-Host "Processing Time            : $($summary.ProcessingTime.ToString('mm\:ss'))"
}

Export-ModuleMember -Function Initialize-GraphFastClient, Get-OAuthPermissionsFast
