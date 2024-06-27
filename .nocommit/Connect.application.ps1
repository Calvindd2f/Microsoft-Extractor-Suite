function constants {}
function interop {
    if([switch]::IsPresent($IsApplication)) {
        New-Alias -Name Invoke-MgGraphRequest -Value Invoke-RestMethod -Option Constant -Force
    } else { break}
}
function Get-Token {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$ExchangeOnline,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    $scope = if ($ExchangeOnline) {
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

    return $response.access_token
    #$exo_token=Get-Token -ExchangeOnline
    #$mg_token=Get-Token `or` $token=Get-Token
}

function Test-Token {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $request = [System.Net.HttpWebRequest]::Create('https://graph.microsoft.com/v1.0/me')
    $request.Method = 'GET'
    $request.ContentType = 'application/json;odata.metadata=minimal'
    $request.Headers['Authorization'] = "Bearer $Token"

    try {
        $response = $request.GetResponse()
        $response.Dispose()
        return $true
    } catch {
        return $false
    }
}
function execute()
{
    constants;
    interop;
    get-token;
    get-token -ExchangeOnline;
}