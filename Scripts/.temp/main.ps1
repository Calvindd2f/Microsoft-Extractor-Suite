using namespace System.Net
using namespace System.Collections.Generic

# Dot sourcing the required scripts
#. "$PSScriptRoot\Microsoft-Extractor-Suite.psm1"
#. "$PSScriptRoot\Scripts\*.ps1"

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
    if ($null -ne $global:Request) {
        $global:Name = $global:Request.Query.Get("Name")
        $global:Value = $global:Request.Query.Get("Value")
    } else {
        Write-Warning "Global variable 'Request' is not set."
    }
}

# Creating a custom object
$params = [PSCustomObject]@{
    Name = 'thing1'
    Value = 'value1'
}

# Displaying the query parameters
if ($null -ne $global:Request) {
    $global:Request.Query.GetEnumerator() | ForEach-Object {
        Write-Output "Key: $($_.Key), Value: $($_.Value)"
    }
} else {
    Write-Warning "Global variable 'Request' is not set."
}

# Calling the function
Invoke-Aquisition -user "testUser" -OutputDir "C:\Output" -Encoding "UTF-8"

# Displaying the response
Write-Output $response.Body
