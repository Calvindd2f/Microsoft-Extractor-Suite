using namespace System.Net
using namespace System.Collections.Generic

# Dot sourcing the required scripts
. "$PSScriptRoot\Microsoft-Extractor-Suite.psm1"
. "$PSScriptRoot\Scripts\*.ps1"

function Invoke-Acquisition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$user,

        [Parameter(Mandatory=$true)]
        [string]$outputDir,

        [Parameter(Mandatory=$true)]
        [string]$encoding
    )

    # Creating a custom object
    $response = [PSCustomObject]@{
        Body = "The user name is $user, output directory is $outputDir and encoding is $encoding."
    }

    # No need to set query parameters as global variables
    # Setting the query parameters as local variables instead
    $queryParams = $Request.Query.GetEnumerator()
    foreach ($param in $queryParams) {
        Write-Verbose "Setting variable $($param.Key) to $($param.Value)"
        Set-Variable -Name $param.Key -Value $param.Value -Force -Scope Local
    }

    # Starting a job to perform some long-running operation
    $jobs += Start-Job -ScriptBlock {
        # Simulating long-running operation
        Start-Sleep -Seconds 10
        # Returning the result
        [PSCustomObject]@{
            Message = "Long-running operation completed."
        }
    }

    # Returning the response object
    $response
}

# Calling the function
$acquisitionResponse = Invoke-Acquisition -user "testUser" -outputDir "C:\temp" -encoding "UTF8"

# Displaying the response
Write-Output "Acquisition response: $($acquisitionResponse.Body)"

# Displaying the jobs started
Write-Output "Jobs started: $($jobs.Count)"

# Getting the results of the jobs
$jobResults = Receive-Job -Job $jobs

# Displaying the results of the jobs
Write-Output "Job results: $($jobResults.Message)"
