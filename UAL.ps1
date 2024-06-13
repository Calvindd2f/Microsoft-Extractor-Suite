function Get-UALAll
{
    [CmdletBinding()]
    param(
        [string]$StartDate,
        [string]$EndDate,
        [string]$UserIds,
        [string]$OutputDir = "Output\UnifiedAuditLog",
        [string]$OutFormat = "CSV",
        [string]$OutEncoding = "UTF8",
        [AllowNull()]
        [int]$Interval,
        [switch]$MergeOutput,
        [switch]$Application
    )
    
    begin 
    {
        $script:OutputDir = $OutputDir
        ###############################################
        
        $UALQueryParams = @{
            StartDateSearch  = (Get-Date $StartDate -format s) + "Z"
            EndDateSearch    = (Get-Date $EndDate -format s) + "Z"
            Operations       = $null
            SearchName       = ("Extractor Suite : Audit Search {0}" -f (Get-Date -format 'dd-MMM-yyyy HH:mm'))
            SearchParameters = @{
                "displayName"         = $SearchName
                "filterStartDateTime" = $StartDateSearch
                "filterEndDateTime"   = $EndDateSearch
                "operationFilters"    = $Operations
            }
        }

        $AdditionalFilters = @{
            keywordFilter               = $null
            administrativeUnitIdFilters = $null
            operationFilters            = $Operations
            objectIdFilters             = $null
            recordTypeFilters           = $null
            ipAddressFilters            = $null
            userPrincipalNameFilters    = $null
            serviceFilters              = $null
        }

        $UALQueryParams.SearchParameters.Add("additionalFilters", $AdditionalFilters)
    }
    process
    {
        Log "Creating an audit search query..."
        try 
        {
            $Uri = "https://graph.microsoft.com/beta/security/auditLog/queries"
            $SearchQuery = Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $SearchParameters
            $SearchId = $SearchQuery.Id
            If ([string]::IsNullOrEmpty($SearchId)) { Log "Search not created"; Break }
            Else { $SearchId = $SearchQuery.Id; Log ("Audit log search created with id: {0} and name {1}" -f $SearchId, $SearchQuery.displayname)}
        }
        catch 
        {  
            <#Do this if a terminating exception happens#>
        }


        Log "Checking audit query status..."
        try 
        {
            [int]$i = 1;
            do 
            {
                $Uri = "https://graph.microsoft.com/beta/security/auditLog/queries/$Search"
                $SearchStatus = Invoke-MgGraphRequest -Method GET -Uri $Uri
                $Status = $SearchStatus.status
                Log ("Audit log search status: {0}" -f $Status)
                Start-Sleep -s 10
                $i++;
            } 
            while ($Status -ne "completed" -and $i -le 30);
            $SearchFinished = $true;
        }
        catch 
        {
            <#Do this if a terminating exception happens#>
        }


        Log "Fetching audit records found by the search..."
        try
        {
            $Uri = "https://graph.microsoft.com/beta/security/auditLog/queries/$Search"
            $AuditRecords = Invoke-MgGraphRequest -Method GET -Uri $Uri
            $AuditRecords.value | ForEach-Object { $AuditRecordsList.Add($_) }

            # Paginate to fetch all available audit records
            $NextLink = $AuditRecords.'@odata.nextLink'
            while ($NextLink -ne $null) {
                $Uri = $NextLink
                $AuditRecords = Invoke-MgGraphRequest -Method GET -Uri $Uri
                $AuditRecords.value | ForEach-Object { $AuditRecordsList.Add($_) }
                $NextLink = $AuditRecords.'@odata.nextLink'
                }
        }
        catch
        {
            <#Do this if a terminating exception happens#>
        }


        #Log ("Total of {0} audit records found" -f $AuditRecords.count)
        <#
            Do Processing Here
        #>
    }
    end
    {
        Log "Audit log search finished"
    }

}
