####################################
# Pull Request Ideas below

#Connection.psm1

function Connect-Tenant {
    <#
    .Description
    This function uses the various PowerShell modules to establish
    a connection to an M365 Tenant associated with provided
    credentials
    .Functionality
    Internal
    #>
    [CmdletBinding(DefaultParameterSetName='Manual')]
    param (
        [Parameter(ParameterSetName = 'Auto')]
        [Parameter(ParameterSetName = 'Manual')]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("teams", "exo", "defender", "aad", "powerplatform", "sharepoint", IgnoreCase = $false)]
        [string[]]
        $ProductNames,

        [Parameter(ParameterSetName = 'Auto')]
        [Parameter(ParameterSetName = 'Manual')]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $false)]
        [string]
        $M365Environment,

        [Parameter(ParameterSetName = 'Auto')]
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable]
        $ServicePrincipalParams
    )
    # Check if required for any product
    if ($null -eq $ServicePrincipalParams) {
        $ServicePrincipalParams = @{}
    }

    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "ConnectHelpers.psm1")

    # Prevent duplicate sign ins
    $EXOAuthRequired = $true
    $SPOAuthRequired = $true
    $AADAuthRequired = $true

    $ProdAuthFailed = @()

    $N = 0
    $Len = $ProductNames.Length

    foreach ($Product in $ProductNames) {
        $N += 1
        $Percent = $N*100/$Len
        $ProgressParams = @{
            'Activity' = "Authenticating to each Product";
            'Status' = "Authenticating to $($Product); $($N) of $($Len) Products authenticated to.";
            'PercentComplete' = $Percent;
        }
        Write-Progress @ProgressParams
        try {
            switch ($Product) {
                "aad" {
                    # ...
                }
                {($_ -eq "exo") -or ($_ -eq "defender")} {
                    # ...
                }
                "powerplatform" {
                    # ...
                }
                "sharepoint" {
                    # ...
                }
                "teams" {
                    # ...
                }
                default {
                    throw "Invalid ProductName argument: $Product"
                }
            }
        }
        catch {
            Write-Error "Error establishing a connection with $($Product). $($_)"
            $ProdAuthFailed += $Product
            Write-Warning "$($Product) will be omitted from the output because of failed authentication"
        }
    }
    Write-Progress -Activity "Authenticating to each service" -Status "Ready" -Completed
    $ProdAuthFailed
}

function Disconnect-Tenant {
    <#
    .SYNOPSIS
        Disconnect all active M365 connection sessions made by Microsoft-Extractor-Suite
    .DESCRIPTION
        Forces disconnect of all outstanding open sessions associated with
        M365 product APIs within the current PowerShell session.
        Best used after an Microsoft-Extractor-Suite run to ensure a new tenant connection is
        used for future Microsoft-Extractor-Suite runs.
    .Parameter ProductNames
        A list of one or more M365 shortened product names this function will disconnect from. By default this function will disconnect from all possible products Microsoft-Extractor-Suite can run against.
    .EXAMPLE
        Disconnect-Tenant
    .EXAMPLE
        Disconnect-Tenant -ProductNames teams
    .EXAMPLE
        Disconnect-Tenant -ProductNames aad, exo
    .Functionality
        Public
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("aad", "defender", "exo","powerplatform", "sharepoint", "teams", IgnoreCase = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ProductNames = @("aad", "defender", "exo", "powerplatform", "sharepoint", "teams"),

        [Parameter(Mandatory=$false)]
        [switch]
        $WhatIf
    )
    $ErrorActionPreference = "SilentlyContinue"

    try {
        $N = 0
        $Len = $ProductNames.Length

        foreach ($Product in $ProductNames) {
            $N += 1
            $Percent = $N*100/$Len
            Write-Progress -Activity "Disconnecting from each service" -Status "Disconnecting from $($Product); $($n) of $($Len) disconnected." -PercentComplete $Percent
            Write-Verbose "Disconnecting from $Product."

            if (-not (Get-Module -Name "Teams" -ErrorAction SilentlyContinue)) {
                Write-Warning "Module Teams not found. Using Connect-MicrosoftTeams will fail."
            }

            if (-not (Get-Module -Name "ExchangeOnlineManagement" -ErrorAction SilentlyContinue)) {
                Write-Warning "Module ExchangeOnlineManagement not found. Using Connect-ExchangeOnline will fail."
            }

            if (-not (Get-Module -Name "Microsoft.PowerApps.Administration.PowerShell" -ErrorAction SilentlyContinue)) {
                Write-Warning "Module Microsoft.PowerApps.Administration.PowerShell not found. Using Add-PowerAppsAccount will fail."
            }

            if (-not (Get-Module -Name "PnP.PowerShell" -ErrorAction SilentlyContinue)) {
                Write-Warning "Module PnP.PowerShell not found. Using Connect-PnPOnline will fail."
            }

            if (-not (Get-Module -Name "MSOnline.Management.Automation" -ErrorAction SilentlyContinue)) {
                Write-Warning "Module MSOnline.Management.Automation not found. Using Connect-MsolService will fail."
            }

            if (($Product -eq "aad") -or ($Product -eq "sharepoint")) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

                if($Product -eq "sharepoint") {
                    Disconnect-SPOService -ErrorAction SilentlyContinue
                    Disconnect-PnPOnline -ErrorAction SilentlyContinue
                }
            }
            elseif ($Product -eq "teams") {
                if ($WhatIf) {
                    Write-Verbose "WhatIf: Disconnect-MicrosoftTeams -Confirm:$false"
                } else {
                    Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
            elseif ($Product -eq "powerplatform") {
                Remove-PowerAppsAccount -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }
            elseif (($Product -eq "exo") -or ($Product -eq "defender")) {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
            }
            else {
                Write-Warning "Product $Product not recognized, skipping..."
            }
        }
        Write-Progress -Activity "Disconnecting from each service" -Status "Done" -Completed

    } catch [System.InvalidOperationException] {
        # Suppress error due to disconnect from service with no active connection
        continue
    } catch {
        Write-Error "ERRROR: Could not disconnect from $Product`n$($Error[0]): "
    } finally {
        $ErrorActionPreference = "Continue"
    }

}

Export-ModuleMember -Function @(
    'Connect-Tenant',
    'Disconnect-Tenant'
)
