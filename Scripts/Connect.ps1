function versionCheck
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PSScriptRoot
    )

    [OutputType([System.Management.Automation.PSObject])]

    $ErrorActionPreference = 'Stop'

    $PSVersionTable = Get-Variable PSVersionTable -ErrorAction SilentlyContinue

    if ($PSVersionTable)
    {
        $PSVersion = $PSVersionTable.Value.PSVersion

        if ($PSVersion.Major -lt 5)
        {
            Write-Error -Message 'This script requires PowerShell version 5.0 or higher.'
        }
    }
    else
    {
        Write-Error -Message 'This script requires PowerShell version 5.0 or higher.'
    }
}

function Connect-M365
{
    [CmdletBinding()]
    param()

    [OutputType([System.Management.Automation.PSObject])]

    $ErrorActionPreference = 'Stop'

    Connect-ExchangeOnline > $null
}

function Connect-Azure
{
    [CmdletBinding()]
    param()

    [OutputType([System.Management.Automation.PSObject])]

    $ErrorActionPreference = 'Stop'

    Connect-AzureAD > $null
}

function Connect-AzureAZ
{
    [CmdletBinding()]
    param()

    [OutputType([System.Management.Automation.PSObject])]

    $ErrorActionPreference = 'Stop'

    Connect-AzAccount > $null
}

function Connect-ExtractorSuite
{
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

    if ($Application)
    {
        $appID = $env:AppId
        $appSecret = $env:AppSecret
        $appThumbprint = $env:AppThumbprint
        $tenantID = $env:TenantId

        $token = Get-Token -scope 'https://graph.microsoft.com/.default' -appID $appID -appSecret $appSecret -tenantID $tenantID
