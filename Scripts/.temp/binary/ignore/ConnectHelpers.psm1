function Get-M365EnvironmentParams {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $M365Environment
    )

    $params = @{}

    switch ($M365Environment) {
        "gcchigh" {
            $params += @{'ExchangeEnvironmentName' = "O365USGovGCCHigh";
                          'ConnectionUri' = "https://ps.compliance.protection.office365.us/powershell-liveid";
                          'AzureADAuthorizationEndpointUri' = "https://login.microsoftonline.us/common";}
        }
        "dod" {
            $params += @{'ExchangeEnvironmentName' = "O365USGovDoD";
                          'ConnectionUri' = "https://l5.ps.compliance.protection.office365.us/powershell-liveid";
                          'AzureADAuthorizationEndpointUri' = "https://login.microsoftonline.us/common";}
        }
        default {
            $params += @{'ExchangeEnvironmentName' = $M365Environment}
        }
    }

    return $params
}

function Connect-EXOHelper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $M365Environment,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $ServicePrincipalParams
    )

    $EXOParams = Get-M365EnvironmentParams -M365Environment $M36
