<#
.SYNOPSIS
Retrieves the conditional access policies from Microsoft Graph API

.DESCRIPTION
This command retrieves all the conditional access policies from Microsoft Graph API.

.PARAMETER OutputDir
Specifies the output directory for the CSV/JSON file. Default is 'UserInfo' directory within the 'Output' directory.

.PARAMETER Encoding
Specifies the encoding of the CSV/JSON output file. Default is UTF8.

.PARAMETER Application
Specifies App-only access (access without a user) or Delegated access (access on behalf a user) for authentication and authorization. Default is Delegated access.

.OUTPUTS
The output will be saved to the specified output directory.

.EXAMPLE
Get-ConditionalAccessPolicies -OutputDir 'C:\MyOutput' -Encoding UTF8 -Application 'App-only'
#>

function Get-ConditionalAccessPolicies {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputDir = "UserInfo",

        [Parameter(Mandatory=$false)]
        [string]$Encoding = "UTF8",

        [Parameter(Mandatory=$false)]
        [string]$Application = "Delegated"
    )

    # Check if the output directory exists, if not create it
    if (!(Test-Path -Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir
    }

    # Connect to Microsoft Graph API with the specified authentication and authorization method
    $connectionName = "Microsoft Graph"
    if ($Application -eq "App-only") {
        Connect-MgGraph -Scopes "Policy.Read.All" -ClientSecret $clientSecret -TenantId $tenantId
    } else {
        Connect-MgGraph -Scopes "Policy.Read.All"
    }

    # Get the conditional access policies
    $policies = Get-MgConditionalAccessPolicy

    # Export the policies to a CSV/JSON file
    $outputFile = $OutputDir + "\" + "ConditionalAccessPolicies_" + (Get-Date -Format yyyy-MM-dd_HH-mm-ss) + "." + $Encoding
    $policies | Export-Csv -Path $outputFile -Encoding $Encoding -NoTypeInformation

    Write-Host "Conditional access policies have been saved to $outputFile"
}

# Connect to Microsoft Graph API with App-only access
$clientSecret = "your_client_secret"
$tenantId = "your_tenant_id"
Connect-MgGraph -Scopes "Policy.Read.All" -ClientSecret $clientSecret -TenantId $tenantId

# Get and export the conditional access policies
Get-ConditionalAccessPolicies
