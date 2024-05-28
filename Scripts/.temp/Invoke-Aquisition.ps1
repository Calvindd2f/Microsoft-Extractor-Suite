using namespace System.Net
using namespace System.Collections.Generic

# Dot sourcing the required scripts
. "$PSScriptRoot\Microsoft-Extractor-Suite.psm1"
. "$PSScriptRoot\Scripts\*.ps1"

function Invoke-Aquisition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$user,

        [Parameter(Mandatory=$true)]
        [string]$OutputDir,

        [Parameter(Mandatory=$true)]
        [string]$Encoding
    )

    $jobs = @()

    # Creating a custom object
    $response = [PSCustomObject]@{
        Body = "The name passed was [$($global:Name)] with value of [$($global:Value)]"
    }

    # Setting the query parameters as global variables
    $QueryParams = $Request.Query.GetEnumerator()
    foreach ($param in $QueryParams) {
        New-Variable -Name $param.Key -Value $param.Value -Force -Scope Global
    }
}

# Calling the function
Invoke-Aquisition -user "testUser" -OutputDir "C:\temp" -Encoding "UTF8"
