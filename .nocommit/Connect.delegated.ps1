using module Microsoft.Graph.Authentication;
using module ExchangeOnlineManagement;
using module Az;

function Connect-Mg($ClientId, $Scopes) {
    Connect-MgGraph -NoWelcome -UseDeviceCode  > $null
}
function Connect-Exo($ClientId) {
    Connect-ExchangeOnline -NoWelcome -UseDeviceCode  > $null 
}
function Connect-Az {
    Connect-AzAccount -NoWelcome -UseDeviceCode  > $null
}
function Execute 
{
    $commands = @(
        { Connect-Mg @PSBoundParameters },
        { Connect-Exo @PSBoundParameters },
        { Connect-Az @PSBoundParameters }
    )
    $commands | ForEach-Object -ThrottleLimit 5 -Parallel {
        & $_
    }

    $isConnected = @{
       mg = (Get-MgContext -ErrorAction SilentlyContinue) -ne $null
       exo = (Get-ConnectionInformation -ErrorAction SilentlyContinue) -ne $null
       az = (Get-AzContext -ErrorAction SilentlyContinue) -eq $null
       status = $null
    }
    if ($isConnected.mg -eq $false -And $isConnected.exo -eq $false -And $isConnected.az -eq $false) { $isConnected.status='false'}
    else { $isConnected.status="true"}
    
    return $isConnected
}
Execute