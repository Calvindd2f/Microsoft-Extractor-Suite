using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

# This contains a function to collect the Message Trace logging.
Function StartDateMTL
{
    [CmdletBinding()]
    param()

    if ([string]::IsNullOrEmpty($script:StartDate))
    {
        $script:StartDate = [datetime]::UtcNow.AddDays(-10)
        Write-LogFile -Message "[INFO] No start date provided by user. Setting the start date to: $($script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
    }
    else
    {
        $script:StartDate = Validate-Date $startDate
        if ($null -eq $script:StartDate) { Write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"} 
    }
}

function EndDateMTL
{
    [CmdletBinding()]
    param()

    if ([string]::IsNullOrEmpty($script:EndDate))
    {
        $script:EndDate = [datetime]::UtcNow
        Write-LogFile -Message "[INFO] No end date provided by user. Setting the end date to: $($script:EndDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
    }
    else
    {
        $script:EndDate = Validate-Date $endDate
        if ($null -eq $script:EndDate) {Write-LogFile -Message "[WARNING] Not A valid end date and time, make sure to use YYYY-MM-DD" -Color "Red"} 
    }
}

Function Validate-Date
{
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)] [string]$Date)

    if ($Date -match "^\d{4}-\d{2}-\d{2}$")
    {
        return [datetime]::ParseExact($Date, "yyyy-MM-dd", $null)
    }

    return $null
}

Function Validate-UserIds
{
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)] [string]$UserIds)

    if ($UserIds -match "^\*@.*")
    {
        return $UserIds.Replace("*@","")
    }

    if ($UserIds -match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    {
        return $UserIds
    }

    if ($UserIds -match "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(,\s*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})*$")
    {
        return $UserIds.Split(',') | ForEach-Object { $_.Trim() }
    }

    return $null
}

Function Test-Connection
{
    [CmdletBinding()]
    param()

    try {
        $null = Get-MessageTrace -ErrorAction stop
        return $true
    }
    catch {
        return $false
    }
}

Function Write-LogFile
{
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)] [string]$Message, [string]$Color = "White")

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $message = "$timestamp [$Color]$Message[/Color]"
    $message | Out-File -FilePath ".\log.txt" -Append
}

Function Test-Directory
{
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)] [string]$Directory)

    if (-not (Test-Path $Directory))
    {
        New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    }
}

Function Get-MessageTraceLog
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
