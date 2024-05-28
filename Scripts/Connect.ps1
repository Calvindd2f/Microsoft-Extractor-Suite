function Global:VersionCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PSScriptRoot
    )

    [OutputType([System.Management.Automation.PSObject])]

    $ErrorActionPreference = 'Stop'

    if (-not (Get-Variable PSVersionTable -ErrorAction SilentlyContinue)) {
        Write-Error -Message 'This script requires PowerShell version 5.0 or higher.'
    }

    $psVersion = $PSVersionTable.Value.PSVersion

    if ($psVersion.Major -lt 5) {
        Write-Error -Message 'This script requires PowerShell version 5.0 or higher.'
    }
}

function Global:Connect-M365 {
    [CmdletBinding()]
    param()

    [OutputType([System.Management.Automation.PSObject])]

    $ErrorActionPreference = 'Stop'

    Connect-ExchangeOnline -ErrorAction SilentlyContinue
}

function Global:Connect-Azure {
    [CmdletBinding()]
    param()

    [OutputType([System.Management.Automation.PSObject])]

    $ErrorActionPreference = 'Stop'

    Connect-AzureAD -ErrorAction SilentlyContinue
}

function Global:Connect-AzureAZ {
    [CmdletBinding()]
    param()

    [OutputType([System.Management.Automation.PSObject])]

    $ErrorActionPreference = 'Stop'

    Connect-AzAccount -ErrorAction SilentlyContinue
}

function Global:Connect-ExtractorSuite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [bool]$Application,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [bool]$DeviceCode,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [bool]$Delegate
    )

    [OutputType([System.Management.Automation.PSObject])]

    $ErrorActionPreference = 'Stop'

    if ($Application) {
        $appID = $env:AppId
        $appSecret = $env:AppSecret
        $appThumbprint = $env:AppThumbprint
        $tenantID = $env:TenantId

        $token = Get-Token -scope 'https://graph.microsoft.com/.default' -appID $appID -appSecret $appSecret -tenantID $tenantID
    }
}

function Global:Get-Token {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$scope,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$appID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$appSecret,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$tenantID
    )

    [OutputType([string])]

    $ErrorActionPreference = 'Stop'

    $body = @{
        'grant_type'    = 'client_credentials'
        'client_id'     = $appID
        'client_secret' = $appSecret
        'scope'         = $scope
    }

    $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token" -Method Post -Body $body

    $response.access_token
}
