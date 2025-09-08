using namespace System.Net
using namespace System.Net.Http
using namespace System.Net.Http.Headers
using namespace System.Net.Http.SocketsHttpHandler
using namespace System.Net.Http.HttpClient
using namespace System.Net.Security
using namespace System.Security.Authentication
using namespace System.Text
using namespace System.Text.Json
using namespace System.Text.Json.Serialization
using namespace System.IO;
using namespace System.Collections.Generic;

# Load required assemblies
Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.Text.Json
Add-Type -AssemblyName System.Net.Http.SocketsHttpHandler
Add-Type -AssemblyName System.Security.Cryptography.X509Certificates

# ----------------------------
# Module-scope singletons
# ----------------------------
$script:BaseGraphUri = 'https://graph.microsoft.com'
$script:GraphVersion = 'v1.0' # change to 'beta' when required
$script:HttpClient = $null
$script:TokenInfo = [pscustomobject]@{ AccessToken = $null; ExpiresOn = Get-Date 0 }

# ----------------------------
# Helpers
# ----------------------------

function New-HttpClient {
    if ($script:HttpClient) { return $script:HttpClient }

    $handler = [system.Net.Http.SocketsHttpHandler]::new()
    $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate

    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.DefaultRequestHeaders.TryAddWithoutValidation('Accept', 'application/json') | Out-Null
    $client.DefaultRequestHeaders.TryAddWithoutValidation('Accept-Encoding', 'gzip, deflate') | Out-Null
    $script:HttpClient = $client
    return $client
}

function Get-AppToken {
    param(
        [Parameter(Mandatory)][string]$TenantId = $env:TenantId,
        [Parameter(Mandatory)][string]$ClientId = $env:ClientId,
        [Parameter(Mandatory)][string]$Thumbprint = $env:Thumbprint,
        [string]$Resource = 'https://graph.microsoft.com/.default'
    )
    # Reuse until ~90 seconds before expiry
    if ($script:TokenInfo.AccessToken -and (Get-Date) -lt $script:TokenInfo.ExpiresOn.AddSeconds(-90)) {
        return $script:TokenInfo.AccessToken
    }

    # Find certificate in local machine or current user store by thumbprint
    $cert = Get-ChildItem -Path Cert:\CurrentUser\My, Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1
    if (-not $cert) {
        throw "Certificate with thumbprint $Thumbprint not found in Cert:\CurrentUser\My or Cert:\LocalMachine\My"
    }

    # Build JWT assertion for client_credentials flow
    $now = [DateTimeOffset]::UtcNow
    $exp = $now.AddMinutes(10)
    $jti = [Guid]::NewGuid().ToString()
    $aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $header = @{
        alg = "RS256"
        typ = "JWT"
        x5t = [Convert]::ToBase64String($cert.GetCertHash()).TrimEnd('=') -replace '\+', '-' -replace '/', '_'
    }
    $payload = @{
        aud = $aud
        iss = $ClientId
        sub = $ClientId
        jti = $jti
        nbf = [int][double]::Parse(($now.ToUnixTimeSeconds()))
        exp = [int][double]::Parse(($exp.ToUnixTimeSeconds()))
    }
    $headerJson = [System.Text.Json.JsonSerializer]::Serialize($header, [System.Text.Json.JsonSerializerOptions]::new())
    $payloadJson = [System.Text.Json.JsonSerializer]::Serialize($payload, [System.Text.Json.JsonSerializerOptions]::new())
    function To-Base64Url([string]$str) {
        [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($str)).TrimEnd('=') -replace '\+', '-' -replace '/', '_'
    }
    $headerB64 = To-Base64Url $headerJson
    $payloadB64 = To-Base64Url $payloadJson
    $jwtToSign = "$headerB64.$payloadB64"

    # Sign JWT with certificate private key
    $rsa = $cert.PrivateKey
    $bytesToSign = [System.Text.Encoding]::UTF8.GetBytes($jwtToSign)
    $signature = [Convert]::ToBase64String($rsa.SignData($bytesToSign, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1))
    $signatureB64 = $signature.TrimEnd('=') -replace '\+', '-' -replace '/', '_'
    $clientAssertion = "$jwtToSign.$signatureB64"

    $uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id             = $ClientId
        scope                 = $Resource
        grant_type            = "client_credentials"
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = $clientAssertion
    }
    $formData = ($body.GetEnumerator() | ForEach-Object { $_.Key + "=" + [Uri]::EscapeDataString($_.Value) }) -join "&"
    $content = [System.Net.Http.StringContent]::new($formData, [System.Text.Encoding]::UTF8, 'application/x-www-form-urlencoded')

    $client = New-HttpClient
    $resp = $client.PostAsync($uri, $content).GetAwaiter().GetResult()
    if (-not $resp.IsSuccessStatusCode) {
        $msg = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        throw "Token request failed: $($resp.StatusCode) $msg"
    }

    $doc = [System.Text.Json.JsonDocument]::Parse($resp.Content.ReadAsStream())
    $root = $doc.RootElement
    $accessToken = $root.GetProperty('access_token').GetString()
    $expiresIn = $root.GetProperty('expires_in').GetInt32()

    $script:TokenInfo = [pscustomobject]@{
        AccessToken = $accessToken
        ExpiresOn   = (Get-Date).AddSeconds($expiresIn)
    }
    return $accessToken
}

function Set-GraphAuthHeader {
    param([string]$AccessToken)
    $c = New-HttpClient
    # overwrite safely without creating a new client
    $c.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $AccessToken)
}

function Invoke-GraphGet {
    <#
      .SYNOPSIS
        Low-level GET with retry/backoff. Returns [System.Text.Json.JsonDocument] (caller must Dispose()).
      .PARAMETER Uri
        Absolute or relative Graph path.
      .PARAMETER ExtraHeaders
        Hashtable of additional headers (e.g., ConsistencyLevel=eventual)
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$ExtraHeaders
    )
    $client = New-HttpClient
    # Relative handling
    if ($Uri -notmatch '^https?://') {
        $Uri = "$($script:BaseGraphUri)/$($script:GraphVersion)/$Uri"
    }

    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Uri)
    if ($ExtraHeaders) {
        foreach ($k in $ExtraHeaders.Keys) {
            $req.Headers.Remove($k) | Out-Null
            $req.Headers.TryAddWithoutValidation($k, [string]$ExtraHeaders[$k]) | Out-Null
        }
    }

    $attempt = 0
    while ($true) {
        $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        if ($resp.IsSuccessStatusCode) {
            return [System.Text.Json.JsonDocument]::Parse($resp.Content.ReadAsStream())
        }

        # Throttle / transient
        if ($resp.StatusCode -in ([System.Net.HttpStatusCode]::TooManyRequests, [System.Net.HttpStatusCode]::ServiceUnavailable, [System.Net.HttpStatusCode]::GatewayTimeout)) {
            $retryAfter = 0
            if ($resp.Headers.RetryAfter -and $resp.Headers.RetryAfter.Delta) {
                $retryAfter = [int][Math]::Ceiling($resp.Headers.RetryAfter.Delta.Value.TotalSeconds)
            }
            elseif ($resp.Headers.RetryAfter -and $resp.Headers.RetryAfter.Date) {
                $retryAfter = [int][Math]::Max(1, [int]((($resp.Headers.RetryAfter.Date.Value - (Get-Date)).TotalSeconds)))
            }
            $attempt++
            if ($retryAfter -le 0) { $retryAfter = [Math]::Min(60, [Math]::Pow(2, $attempt)) + (Get-Random -Minimum 0 -Maximum 250) / 1000.0 }
            Start-Sleep -Seconds $retryAfter
            # recreate request message after send (HttpRequestMessage is single-use for content)
            $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Uri)
            if ($ExtraHeaders) { foreach ($k in $ExtraHeaders.Keys) { $req.Headers.TryAddWithoutValidation($k, [string]$ExtraHeaders[$k]) | Out-Null } }
            continue
        }

        $err = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        throw "GET $Uri failed: $($resp.StatusCode) $err"
    }
}

function Get-GraphPaged {
    <#
      .SYNOPSIS
        Streams a collection endpoint following @odata.nextLink.
      .DESCRIPTION
        Returns a typed List[object] OR writes CSV as it goes (no huge in-memory arrays).
      .PARAMETER Path
        Relative path like 'users' or 'users?$select=id,displayName'
      .PARAMETER Select
        Fields projection; appended as $select if not present in Path.
      .PARAMETER Filter
        $filter expression (set ConsistencyLevel automatically if used with $count).
      .PARAMETER Count
        Switch to add $count=true + header ConsistencyLevel:eventual.
      .PARAMETER Top
        Page size hint (API-specific caps).
      .PARAMETER ToCsv
        Optional file path to stream results to CSV.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Select,
        [string]$Filter,
        [switch]$Count,
        [int]$Top = 999,
        [string]$ToCsv
    )

    # Build query efficiently (StringBuilder, no string +)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append($Path)
    $script:qAdded = $Path.Contains('?')
    function AddQ { param([string]$k, [string]$v) if (-not $script:qAdded) { [void]$sb.Append('?'); $script:qAdded = $true } else { [void]$sb.Append('&') }; [void]$sb.Append($k); [void]$sb.Append('='); [void]$sb.Append($v) }

    if ($Select -and $Path -notmatch '\$select=') { AddQ '$select' ([string]::Join(',', $Select)) }
    if ($Filter) { AddQ '$filter' ([Uri]::EscapeDataString($Filter)) }
    if ($Count) { AddQ '$count' 'true' }
    if ($Top -gt 0 -and $Path -notmatch '\$top=') { AddQ '$top' $Top }

    $headers = @{}
    if ($Count) { $headers['ConsistencyLevel'] = 'eventual' }

    $uri = $sb.ToString()

    # CSV writer setup (optional)
    $csvWriter = $null
    if ($ToCsv) {
        $stream = [System.IO.StreamWriter]::new($ToCsv, $false, [System.Text.Encoding]::UTF8)
        $csvWriter = @{
            Stream        = $stream
            HeaderWritten = $false
            Headers       = $null
        }
    }

    # Collector (typed list, not array +=)
    $list = [System.Collections.Generic.List[object]]::new()

        while ($uri) {
        $doc = Invoke-GraphGet -Uri $uri -ExtraHeaders $headers
        try {
            $root = $doc.RootElement
            $arr  = $root.GetProperty('value')

            for ($i = 0; $i -lt $arr.GetArrayLength(); $i++) {
                $e  = $arr[$i]
                $ht = [ordered]@{}
                foreach ($prop in $e.EnumerateObject()) {
                    $ht[$prop.Name] = switch ($prop.Value.ValueKind) {
                        'String' { $prop.Value.GetString() }
                        'Number' { try { $prop.Value.GetInt64() } catch { $prop.Value.GetDouble() } }
                        'True'   { $true }
                        'False'  { $false }
                        default  { $prop.Value.ToString() }
                    }
                }
                $obj = [pscustomobject]$ht

                if ($csvWriter) {
                    if (-not $csvWriter.HeaderWritten) {
                        $csvWriter.Headers = @($ht.Keys)
                        $csvWriter.Stream.WriteLine(($csvWriter.Headers -join ','))
                        $csvWriter.HeaderWritten = $true
                    }
                    $line = ($csvWriter.Headers | ForEach-Object { ($ht[$_]) -replace '"','""' }) -join ','
                    $csvWriter.Stream.WriteLine($line)
                } else {
                    [void]$list.Add($obj)
                }
            }

            # --- PS5.1-safe nextLink detection (no TryGetProperty) ---
            $nextLink = $null
            foreach ($p in $root.EnumerateObject()) {
                if ($p.Name -eq '@odata.nextLink') {
                    # nextLink is always a string
                    $nextLink = $p.Value.GetString()
                    break
                }
            }
            if ($nextLink) { $uri = $nextLink } else { $uri = $null }
            # ----------------------------------------------------------
        }
        finally { $doc.Dispose() }
    }


    if ($csvWriter) { $csvWriter.Stream.Flush(); $csvWriter.Stream.Dispose() | Out-Null; return } # no huge arrays, file already written
    return $list
}

# ---------- Helpers for POST + PS5.1-safe JSON prop access ----------

function Invoke-GraphPost {
    param(
        [Parameter(Mandatory)][string]$Uri,     # absolute or relative to /{version}/
        [Parameter(Mandatory)][string]$BodyJson,
        [hashtable]$ExtraHeaders
    )
    $client = New-HttpClient
    if ($Uri -notmatch '^https?://') {
        $Uri = "$($script:BaseGraphUri)/$($script:GraphVersion)/$Uri"
    }

    $attempt = 0
    while ($true) {
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $Uri)
        $req.Content = [System.Net.Http.StringContent]::new($BodyJson, [System.Text.Encoding]::UTF8, 'application/json')
        if ($ExtraHeaders) { foreach ($k in $ExtraHeaders.Keys) { [void]$req.Headers.TryAddWithoutValidation($k,[string]$ExtraHeaders[$k]) } }

        $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        if ($resp.IsSuccessStatusCode) {
            return [System.Text.Json.JsonDocument]::Parse($resp.Content.ReadAsStream())
        }

        if ($resp.StatusCode -in ([System.Net.HttpStatusCode]::TooManyRequests, [System.Net.HttpStatusCode]::ServiceUnavailable, [System.Net.HttpStatusCode]::GatewayTimeout)) {
            $retryAfter = 0
            if ($resp.Headers.RetryAfter -and $resp.Headers.RetryAfter.Delta) {
                $retryAfter = [int][math]::Ceiling($resp.Headers.RetryAfter.Delta.Value.TotalSeconds)
            }
            $attempt++
            if ($retryAfter -le 0) { $retryAfter = [Math]::Min(60,[Math]::Pow(2,$attempt)) + (Get-Random -Minimum 0 -Maximum 250)/1000.0 }
            Start-Sleep -Seconds $retryAfter
            continue
        }

        $err = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        throw "POST $Uri failed: $($resp.StatusCode) $err"
    }
}

function Get-JsonPropString {
    param([System.Text.Json.JsonElement]$Element,[string]$Name)
    foreach ($p in $Element.EnumerateObject()) {
        if ($p.Name -eq $Name) {
            if ($p.Value.ValueKind -eq 'String') { return $p.Value.GetString() }
            return $p.Value.ToString()
        }
    }
    return $null
}

function Get-JsonPropElement {
    param([System.Text.Json.JsonElement]$Element,[string]$Name)
    foreach ($p in $Element.EnumerateObject()) { if ($p.Name -eq $Name) { return $p.Value } }
    return $null
}

# ----------------------------
# Public entry points
# ----------------------------

function Initialize-GraphFastClient {
    <#
      .SYNOPSIS
        Initializes and caches the HttpClient + token for subsequent calls.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId = $env:TenantId,
        [Parameter(Mandatory)][string]$ClientId = $env:ClientId,
        [Parameter(Mandatory)][string]$Thumbprint = $env:Thumbprint,
        [ValidateSet('v1.0', 'beta')][string]$Version = 'v1.0'
    )
    $null = New-HttpClient
    $script:GraphVersion = $Version
    $token = Get-AppToken -TenantId $TenantId -ClientId $ClientId -Thumbprint $Thumbprint
    Set-GraphAuthHeader -AccessToken $token
}

function Get-GffUsersFast {
    <#
      .SYNOPSIS
        Example: fast users export with minimal fields, server-side projection, paging, optional CSV stream.
      .EXAMPLE
        Get-GffUsersFast -Select id,userPrincipalName,displayName -ToCsv .\users.csv
    #>
    [CmdletBinding()]
    param(
        [string[]]$Select = @('id', 'userPrincipalName', 'displayName', 'accountEnabled'),
        [int]$Top = 999,
        [string]$Filter,
        [switch]$Count,
        [string]$ToCsv
    )
    if (-not $script:HttpClient -or -not $script:TokenInfo.AccessToken) {
        throw 'Call Initialize-GraphFastClient first.'
    }
    # no pipeline writes in loops — Get-GraphPaged handles streaming
    return Get-GraphPaged -Path 'users' -Select $Select -Top $Top -Filter $Filter -Count:$Count -ToCsv $ToCsv
}

function Invoke-GffBatch {
    <#
      .SYNOPSIS
        Sends a Graph $batch payload (up to 20 sub-requests). Caller supplies ready-made batch body.
      .PARAMETER Requests
        Array of hashtables with id, method, url (relative to /{version}/)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Requests
    )
    if (-not $script:HttpClient -or -not $script:TokenInfo.AccessToken) {
        throw 'Call Initialize-GraphFastClient first.'
    }
    if ($Requests.Count -gt 20) { throw 'Graph $batch supports at most 20 sub-requests.' }

    $payload = @{ requests = $Requests } | ConvertTo-Json -Depth 6
    $uri = "$($script:BaseGraphUri)/$($script:GraphVersion)/`$batch"
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $uri)
    $req.Content = [System.Net.Http.StringContent]::new($payload, [System.Text.Encoding]::UTF8, 'application/json')

    $client = New-HttpClient
    $resp = $client.SendAsync($req).GetAwaiter().GetResult()
    if (-not $resp.IsSuccessStatusCode) {
        $msg = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        throw "Batch failed: $($resp.StatusCode) $msg"
    }
    # Return parsed JSON as PSObject (single conversion, not per-item in loops)
    $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    return $text | ConvertFrom-Json -Depth 8
}

<# Usage #>
<#
    Import-Module .\Graph.Fast.psm1 -Force

1) Initialize once per session (reuses HttpClient + token)
Initialize-GraphFastClient -TenantId $env:AZ_TENANT_ID -ClientId $env:AZ_CLIENT_ID -Thumbprint $env:AZ_THUMBPRINT -Version v1.0

2) Stream a tenant-wide users export to CSV (no huge arrays, minimal fields)
Get-GffUsersFast -Select id, userPrincipalName, displayName, accountEnabled -ToCsv .\users.csv

3) Or get as an in-memory typed list (still efficient; returned once at the end)
$users = Get-GffUsersFast -Select id, userPrincipalName -Top 999
$users.Count

4) Example $batch: fetch two users by id in one round-trip
$reqs = @(
    @{ id = '1'; method = 'GET'; url = 'users?$select=id,displayName&$top=1' },
    @{ id = '2'; method = 'GET'; url = 'groups?$select=id,displayName&$top=1' }
)
$batch = Invoke-GffBatch -Requests $reqs
#>
#initialize-GraphFastClient -TenantId $env:TenantId -ClientId $env:ClientId -Thumbprint $env:Thumbprint -Version v1.0
#Get-GffUsersFast -Select id, userPrincipalName, displayName, accountEnabled -ToCsv .\users.csv
