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
    $global:Name = $Request.Query.Get("Name")
    $global:Value = $Request.Query.Get("Value")
}

# Creating a custom object
[PSCustomObject]@{
    Name = 'thing1'
    Value = 'value1'
}

# Displaying the query parameters
$Request.Query.GetEnumerator() | ForEach-Object {
    Write-Output "Key: $($_.Key), Value: $($_.Value)"
}

# Calling the function
Invoke-Aquisition -user "testUser" -OutputDir "C:\Output" -Encoding "UTF-8"

# Displaying the response
Write-Output $response.Body
