#region Input::Output variables
$variableProps = @{msgraph_token = $null;exo_token     = $null;appID         = $env:AppId;appSecret     = $env:AppSecret;appCertThumb  = $env:Appthumbprint;tenantID      = $env:TenantId;}
$outputProps = @{out     = $(New-Object psobject -Property $variableProps);success = $false;}
$activityOutput = New-Object psobject -Property $outputProps;
#endregion

#region Get-Token
try {
    $body = @{
        'grant_type'    = 'client_credentials'
        'client_id'     = $env:AppId
        'client_secret' = $env:AppSecret
        'scope'         = 'https://graph.microsoft.com/.default'
    }
    $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$env:tenantID/oauth2/v2.0/token" -Method Post -Body $body
    $MSGRAPH_Api_Token_Client = $response.access_token
    $msgraph_token = $response.access_token
} catch {
    Write-Warning "Unable to get token. Check input variables more than likely the AppId, AppSecret, and TenantId. Error: $($_.Exception.Message)"
}
#endregion

#region Get-Test - Testing for function interop instead of having to create a function for both delegate powershell sdk and for application.
function Get-Test
{
    param (
        [switch]$Application,
        [string]$Uri,
        [string]$Method = "GET",
        $Headers,
        $Body
    )

    # Create an alias if the -IsApplication switch is present
    if ($Application)
    {
        try {
            New-Alias -Name Invoke-MgGraphRequest -Value Invoke-RestMethod -Force
        } catch { 
            Write-Warning "Unable to create alias Invoke-MgGraphRequest. Verify you have run 'Microsoft.Graph' installed , even though these are API calls."
        }

        # Since Application, verifying token
        if ([string]::IsNullOrEmpty($msgraph_token)){}
        elseif ([string]::IsNullOrEmpty($exo_token)){}
        elseif ([string]::IsNullOrEmpty($token)){}
        elseif ([string]::IsNullOrEmpty($tokens)){}
        # Either call a function to check environment variables for make IsApplication $false then force delegated.
       
        # Delegated can use headers if needed, but API calls require the headers.
        $headers = @{Authorization = "Bearer $($msgraph_token)"}
    } # The else is not here because the default configuration (as in, switch is not used) will call Invoke-MgGraphRequest via Delegated permission and the genuine CMDlet.

    if ($Headers)
    {
        # Construct the body for the request api where the headers contain authorization token stuff.
        Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/me" -Method "GET" -ContentType "application/json" -Headers $Headers
    } else {
        # Delegated API call using powershell SDK, headers is null as it works and using $headers without $headers throws term err.
        Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/me" -Method "GET" -ContentType "application/json" -Headers $null
    }  
}
