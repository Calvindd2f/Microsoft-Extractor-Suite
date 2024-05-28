using module "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

Function Connect-M365
{
    versionCheck
    Connect-ExchangeOnline > $null
}

Function Connect-Azure
{
    versionCheck
    Connect-AzureAD > $null
}

Function Connect-AzureAZ
{
    versionCheck
    Connect-AzAccount > $null
}

Function Connect-ExtractorSuite([bool]$Application = $false, [bool]$DeviceCode = $false, [bool]$Delegate = $false)
{
    versionCheck

    if ($Application)
    {
        $appID = "$env:AppId"
        $appSecret = "$env:AppSecret"
        $appThumbprint = "$env:AppThumbprint"
        $tenantID = "$env:TenantId"

        $token = Get-Token -scope 'https://graph.microsoft.com/.default' -appID $appID -appSecret $appSecret -tenantID $tenantID
        Check-Token -token $token
    }
    elseif ($DeviceCode)
    {
        Connect-DeviceCode
    }
    elseif ($Delegate)
    {
        $delegate_scopes = @('AuditLogsQuery.Read.All', 'UserAuthenticationMethod.Read.All', 'User.Read.All', 'Mail.ReadBasic.All', 'Mail.ReadWrite', 'Mail.Read', 'Mail.ReadBasic', 'Policy.Read.All', 'Directory.Read.All')

        Connect-MgGraph -Scopes $delegate_scopes
    }
    else
    {
        Connect-DeviceCode
    }
}

Function Get-Token($scope, [string]$appID, [string]$appSecret, [string]$tenantID)
{
    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $appID
        client_secret = $appSecret
        scope         = $scope
    }

    $tokenEndpoint = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"
    $res = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body

    $token = $res.access_token
    return $token
}

Function Check-Token($token)
{
    try
    {
        $request = [System.Net.HttpWebRequest]::Create('https://graph.microsoft.com/v1.0/me')

        $request.Method = 'GET'
        $request.ContentType = 'application/json;odata.metadata=minimal'
        $request.Headers['Authorization'] = "Bearer $token"

        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader $response.GetResponseStream()
        $jsonResult = $reader.ReadToEnd()
        $response.Dispose()

        Write-Host 'MS Graph Token is valid.'
        return $true
    }
    catch
    {
        Write-Warning 'MS Graph Token is invalid'
        return $false
    }
}

function Connect-DeviceCode
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $False)]
        [string]$ClientID = '00000003-0000-0000-c000-000000000000',
        [Parameter(Mandatory = $False)]
        [String]$Resource = 'https://graph.microsoft.com',
        [Parameter(Mandatory = $False)]
        [ValidateSet('Outlook', 'MSTeams', 'Graph', 'AzureCoreManagement', 'AzureManagement', 'MSGraph', 'DODMSGraph', 'Custom', 'Substrate')]
        [String[]]$Client = 'MSGraph'
    )

    $body = @{
        'client_id' = $ClientID
        'resource'  = $Resource
    }

    $authResponse = Invoke-RestMethod `
        -UseBasicParsing `
        -Method Post `
        -Uri 'https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0' `
        -Body $body

    Write-Host -ForegroundColor yellow $authResponse.Message

    $continue = 'authorization_pending'

    while ($continue)
    {

        $body = @{
            'client_id'  = $ClientID
            'grant_type' = 'urn:ietf:params:oauth:grant-type:device_code'
            'code'       = $authResponse.device_code
            'scope'      = 'openid'
        }

        try
        {
            $tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri 'https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0' -Body $body

            if ($tokens)
            {
                $tokenPayload = $tokens.access_token.Split('.')[1].Replace('-', '+').Replace('_', '/')
                while ($tokenPayload.Length % 4) { Write-Verbose 'Invalid length for a Base-64 char array or string, adding ='; $tokenPayload += '=' }
                $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
                $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
                $tokobj = $tokenArray | ConvertFrom-Json
                $global:tenantid = $tokobj.tid
                Write-Output 'Decoded JWT payload:'
                $tokobj
                $baseDate = Get-Date -Date '01-01-1970'
                $tokenExpire = $baseDate.AddSeconds($tokobj.exp).ToLocalTime()
                Write-Host -ForegroundColor Green '["*"] Successful authentication. Access and refresh tokens have been written to the global $tokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)'
                Write-Host -ForegroundColor Yellow "[!] Your access token is set to expire on: $tokenExpire"
                $continue = $null
            }
        }
        catch
        {
            $details = $_.ErrorDetails.Message | ConvertFrom-Json
            $continue = $details.error -eq 'authorization_pending'
            Write-Output $details.error
        }
    }

    if ($continue)
    {
        Start-Sleep -Seconds 3
    }
    else
    {
        $global:tokens = $tokens
    }
}

Function Connect-AquisitonGraph
{
    $GraphScopes = (
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
            TenantId              = $ServicePrincipalParams.CertThumbprintParams.Organization; # Organization also works here
        }
    }
    else
    {
        $GraphParams += @{Scopes = $GraphScopes; }
    }
    Connect-MgGraph @GraphParams | Out-Null
    $EntraAuthRequired = $false
}

Function Connect-AquisitonExo
{
    $EXOParams = @{
        ErrorAction = 'Stop'
        ShowBanner  = $false
    }

    if ($ServicePrincipalParams.CertThumbprintParams)
    {
        $EXOParams += $ServicePrincipalParams.CertThumbprintParams
    }

    Connect-ExchangeOnline @EXOParams > Out-Null
}

function Get-AquisitionServicePrincipalParams
{
    <#
    .Description
    Returns a valid a hastable of parameters for authentication via
    Service Principal. Throws an error if there are none.
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $BoundParameters
    )

    $ServicePrincipalParams = @{}

    $CheckThumbprintParams = ($BoundParameters.CertificateThumbprint) `
        -and ($BoundParameters.AppID) -and ($BoundParameters.Organization)

    if ($CheckThumbprintParams)
    {
        $CertThumbprintParams = @{
            CertificateThumbprint = $BoundParameters.CertificateThumbprint
            AppID                 = $BoundParameters.AppID
            Organization          = $BoundParameters.Organization
        }
        $ServicePrincipalParams += @{CertThumbprintParams = $CertThumbprintParams }
    }
    else
    {
        throw 'Missing parameters required for authentication with Service Principal Auth; Run Get-Help Invoke-Scuba for details on correct arguments'
    }
    $ServicePrincipalParams
}

# Authentications parameters use below
#$SPparams = 'AppID', 'CertificateThumbprint', 'Organization'

Export-ModuleMember -Function '*' -Cmdlet '*' -Alias '*' -Variable '*'
