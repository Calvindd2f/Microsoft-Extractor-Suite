Function Connect-M365
{
    versionCheck
    try {
        Connect-ExchangeOnline > $null
    } catch {
        Write-Error $_
    }
}

Function Connect-Azure
{
    versionCheck
    try {
        Connect-AzureAD > $null
    } catch {
        Write-Error $_
    }
}

Function Connect-AzureAZ
{
    versionCheck
    try {
        Connect-AzAccount > $null
    } catch {
        Write-Error $_
    }
}

Function Connect-ExtractorSuite
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$Application,

        [Parameter(Mandatory = $false)]
        [bool]$DeviceCode,

        [Parameter(Mandatory = $false)]
        [bool]$Delegate
    )

    if ($Application) {
        $appId = $env:AppId
        $appSecret = $env:AppSecret
        $tenantId = $env:TenantId

        Get-Token -Scope 'https://graph.microsoft.com/.default'
        Check-Token -Token $token
    } elseif ($DeviceCode) {
        Connect-DeviceCode
    } elseif ($Delegate) {
        $delegateScopes = @(
            'AuditLogsQuery.Read.All',
            'UserAuthenticationMethod.Read.All',
            'User.Read.All',
            'Mail.ReadBasic.All',
            'Mail.ReadWrite',
            'Mail.Read',
            'Mail.ReadBasic',
            'Policy.Read.All',
            'Directory.Read.All'
        )

        Connect-MgGraph -Scopes $delegateScopes
    } else {
        Connect-DeviceCode
    }
}

function Get-Token {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$UseExchangeOnline,

        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,

        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )
    
    $scope = if ($UseExchangeOnline) {
        'https://outlook.office365.com/.default'
    } else {
        'https://graph.microsoft.com/.default'
    }

    $body = @{
        Grant_Type    = 'client_credentials'
        Client_Id     = $ClientId
        Client_Secret = $ClientSecret
        Scope         = $scope
    }

    $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method Post -Body $body

    if ($UseExchangeOnline) {
        $exo_token = $response.access_token
        return $exo_token
    } else {
        $msgraph_token = $response.access_token
        return $msgraph_token
    }
}

Function Check-Token($Token)
{
    try
    {
        $Request = [System.Net.HttpWebRequest]::Create('https://graph.microsoft.com/v1.0/me')

        $Request.Method = 'GET'
        $Request.ContentType = 'application/json;odata.metadata=minimal'
        $Request.Headers['Authorization'] = "Bearer $Token"

        $Response = $Request.GetResponse()
        $Reader = New-Object System.IO.StreamReader $Response.GetResponseStream()
        $JsonResult = $Reader.ReadToEnd()
        $Response.Dispose()

        Write-Host 'MS Graph Token is valid.'
        return $true
    }
    catch
    {
        Write-Warning 'MS Graph Token is invalid'
        return $false
    }
}

Function Connect-DeviceCode
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $False)]
        [string]$ClientId = '00000003-0000-0000-c000-000000000000',
        [Parameter(Mandatory = $False)]
        [String]$Resource = 'https://graph.microsoft.com',
        [Parameter(Mandatory = $False)]
        [ValidateSet('Outlook', 'MSTeams', 'Graph', 'AzureCoreManagement', 'AzureManagement', 'MSGraph', 'DODMSGraph', 'Custom', 'Substrate')]
        [String[]]$Client = 'MSGraph'
    )

    $Body = @{
        'client_id' = $ClientId
        'resource'  = $Resource
    }

    $AuthResponse = Invoke-RestMethod `
        -UseBasicParsing `
        -Method Post `
        -Uri 'https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0' `
        -Body $Body

    Write-Host -ForegroundColor Yellow $AuthResponse.Message

    $Continue = 'authorization_pending'

    while ($Continue)
    {
        $Body = @{
            'client_id'  = $ClientId
            'grant_type' = 'urn:ietf:params:oauth:grant-type:device_code'
            'code'       = $AuthResponse.device_code
            'scope'      = 'openid'
        }

        try
        {
            $Tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri 'https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0' -Body $Body

            if ($Tokens)
            {
                $TenantId = $Tokens.access_token.Split('.')[1].Replace('-', '+').Replace('_', '/')
                while ($TenantId.Length % 4) { $TenantId += '=' }
                $TenantByteArray = [System.Convert]::FromBase64String($TenantId)
                $TenantArray = [System.Text.Encoding]::ASCII.GetString($TenantByteArray)
                $Tokens.tenant_id = $TenantArray | ConvertFrom-Json | Select-Object -ExpandProperty tid
                $Continue = $null
            }
        }
        catch
        {
            $Details = $_.ErrorDetails.Message | ConvertFrom-Json
            $Continue = $Details.error -eq 'authorization_pending'
        }
    }

    if ($Continue)
    {
        Start-Sleep -Seconds 3
    }
    else
    {
        $script:Tokens = $Tokens
    }
}

Function Connect-ExtractorSuite
{
    switch ($x) {
        delegate {}
        applicaiton {}
        Default {}
    }
    $GraphScopes = @(
        'User.Read.All',
        'Policy.Read.All',
        'Organization.Read.All',
        'RoleManagement.Read.Directory',
        'GroupMember.Read.All',
        'Directory.Read.All',
        'PrivilegedEligibilitySchedule.Read.AzureADGroup',
        'PrivilegedAccess.Read.AzureADGroup',
        'RoleManagementPolicy.Read.AzureADGroup'
    )
    $GraphParams = @{
        'ErrorAction' = 'Stop'
    }
    if ($ServicePrincipalParams.CertThumbprintParams)
    {
        $GraphParams += @{
            CertificateThumbprint = $ServicePrincipalParams.CertThumbprintParams.CertificateThumbprint
            ClientID              = $ServicePrincipalParams.CertThumbprintParams.AppID
            TenantId              = $ServicePrincipalParams.CertThumbprintParams.Organization
        }
    }
    else
    {
        $GraphParams += @{Scopes = $GraphScopes; }
    }
    Connect-MgGraph @GraphParams | Out-Null
}

