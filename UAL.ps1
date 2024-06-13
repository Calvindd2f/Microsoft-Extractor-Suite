function Get-UALAll
{
    [CmdletBinding()]
    param(
        [string]$StartDate,
        [string]$EndDate,
        [string]$UserIds,
        [string]$Interval
        [string]$Output="CSV","JSON"
        [switch]$MergeOutput,
        [string]$OutputDir="Output\UnifiedAuditLog",
        [string]$Encoding= "UTF8",
        [switch]$Application
    )
    
    if(!$Application){#Connect-MgGraph -Scopes AuditLogsQuery.Read.All -NoWelcome}
    }
    else{#validate token
    }


    $UALQueryParams=@{
        StartDateSearch = (Get-Date $StartDate -format s) + "Z"
        EndDateSearch = (Get-Date $EndDate -format s) + "Z"
        Operations = $null
        SearchName = ("Extractor Suite : Audit Search {0}" -f (Get-Date -format 'dd-MMM-yyyy HH:mm'))
        SearchParameters = @{
            "displayName"           = $SearchName
            "filterStartDateTime"   = $StartDateSearch
            "filterEndDateTime"     = $EndDateSearch
            "operationFilters"      = $Operations
        }
    }

    $AdditionalFilters=@{
        keywordFilter = $null
        administrativeUnitIdFilters = $null
        operationFilters = $Operations
        objectIdFilters = $null
        recordTypeFilters = $null
        ipAddressFilters = $null
        userPrincipalNameFilters = $null
        serviceFilters = $null
    }


    #"Creating an audit search query..."
    $Uri = "https://graph.microsoft.com/beta/security/auditLog/queries"
    $SearchQuery = Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $SearchParameters
    $SearchId = $SearchQuery.Id
    If ($null -eq $SearchId) 
    {
        Write-Host "Search not created"
        Break
    } 
    Else 
    {
        $SearchId = $SearchQuery.Id
        Write-Host ("Audit log search created with id: {0} and name {1}" -f $SearchId, $SearchQuery.displayname)
    }


    #"Checking audit query status..."
    [int]$i = 1
    [int]$SleepSeconds = 20
    $SearchFinished = $false; [int]$SecondsElapsed = 20
    Write-Host "Checking audit query status..."
    Start-Sleep -Seconds 20
    $Uri = ("https://graph.microsoft.com/beta/security/auditLog/queries/{0}" -f $SearchId)
    $SearchStatus = Invoke-MgGraphRequest -Uri $Uri -Method GET
    While ($SearchFinished -eq $false) 
    {
        $i++
        Write-Host ("Waiting for audit search to complete. Check {0} after {1} seconds. Current state {2}" -f $i, $SecondsElapsed, $SearchStatus.status)
        If ($SearchStatus.status -eq 'succeeded') 
        {
            $SearchFinished = $true
        } 
        Else 
        {
            Start-Sleep -Seconds $SleepSeconds
            $SecondsElapsed = $SecondsElapsed + $SleepSeconds
            $SearchStatus = Invoke-MgGraphRequest -Uri $Uri -Method GET
        }
    }


   #"Fetching audit records found by the search..."
   $Uri = ("https://graph.microsoft.com/beta/security/auditLog/queries/{0}/records?`$Top=999" -f $SearchId)
   [array]$SearchRecords = Invoke-MgGraphRequest -Uri $Uri -Method GET
   [array]$AuditRecords = $SearchRecords.value
   # Paginate to fetch all available audit records
   $NextLink = $SearchRecords.'@odata.NextLink'
   While ($null -ne $NextLink)
   {
    $SearchRecords = $null
    [array]$SearchRecords = Invoke-MgGraphRequest -Uri $NextLink -Method GET 
    $AuditRecords += $SearchRecords.value
    Write-Host ("{0} audit records fetched so far..." -f $AuditRecords.count)
    $NextLink = $SearchRecords.'@odata.NextLink' 
    }


    #("Total of {0} audit records found" -f $AuditRecords.count)
    <#
        Do Processing Here
    #>
}
