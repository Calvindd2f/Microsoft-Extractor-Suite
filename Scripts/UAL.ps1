<#
Audit.AzureActiveDirectory
Audit.Exchange
Audit.SharePoint
Audit.General (includes all other workloads not included in the previous content types)
DLP.All 

Connect to the Microsoft 365 Management APIs using Azure AD app 


You will need a Azure AD and a Client Id and Secret to connect to the APIs. So you will have to create a new Azure Ad App



Register an App: To start working with the Microsoft 365 Management API, you will need to register an app in Azure Active Directory. This app will be used to authenticate and authorize your API calls.
Go to API Permissions and add Office 365 Management APIs -> Application -> ActivityFeed.Read permission
Once you close the window find and click on the Grant admin consent button
Then go to the certificates and secrets and create a new client secret
Copy the secret value so you can use it with powershell or rest api
Go to the Overview panel and copy the Client Id so you can use it with powershell or rest api

#>




function Get-UALAll {
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$StartDate,
        [string]$EndDate,
        [int]$Interval = 1440, # Increased interval to reduce API calls
        [string]$Output = "CSV",
        [string]$OutputDir = "Output\UnifiedAuditLog",
        [string]$Encoding = "UTF8",
        [int]$MaxConcurrency = 5 # Maximum number of concurrent threads
    )

    # If no access token specific call a function here to get the exo_token

    # Convert dates to the correct format
    $startDate = [datetime]::Parse($StartDate)
    $endDate = [datetime]::Parse($EndDate)

    # Ensure the output directory exists
    if (-not (Test-Path -Path $OutputDir)) {
        [void](New-Item -ItemType Directory -Force -Path $OutputDir)
    }

    # Acquire the access token
    $exo_token = Get-AccessToken

    # Set the Office 365 Management Activity API URL
    $apiUrl = "https://manage.office.com/api/v1.0/$TenantId/activity/feed/subscriptions/content"

    # Generate time intervals
    $intervals = while ($startDate -lt $endDate) {
        $currentEnd = $startDate.AddMinutes($Interval)
        if ($currentEnd -gt $endDate) { $currentEnd = $endDate }
        [PSCustomObject]@{
            Start = $startDate
            End   = $currentEnd
        }
        $startDate = $currentEnd
    }
    
    # Process each interval in parallel
    $intervals | ForEach-Object -Parallel {
        $currentStart = $_.Start
        $currentEnd = $_.End
        $contentUri = "$using:apiUrl?startTime={0}&endTime={1}" -f `
            $currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"), `
            $currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
        do {
            # Invoke the API call
            $response = Invoke-RestMethod -Headers @{Authorization = "Bearer $using:exo_token"} -Uri $contentUri -Method Get -ContentType "application/json"

            # Stream the results directly to the file
            $outputFile = Join-Path -Path $using:OutputDir -ChildPath "UAL-$($currentStart.ToString('yyyyMMddHHmmss')).$using:Output"
            Add-Content -Path $outputFile -Value ($response.value | ConvertTo-Csv -NoTypeInformation) -Encoding $using:Encoding

            # Check if there is another page of data
            if ($response.'@odata.nextLink') {
                $contentUri = $response.'@odata.nextLink'
            } else {
                $contentUri = $null
            }
        } while ($contentUri -ne $null)
    } -ThrottleLimit $MaxConcurrency

    Write-Host "Acquisition complete, check the Output directory for your files."
}

# Note: The processing and outputting of the logs are not included in the snippet above.
# You would need to fill in that part, similar to the CSV or JSON streaming in the previous example.





# Current Search-UAL self-hatred

$conn_id = $([guid]::NewGuid().Guid).ToString()
[int]$defaultTimeout = 30;
Function VerifyActivity()
{
    # Put code here to verify the command will work given the variables 
    return $true;
}

 
   

Function ExoCommand($conn, $command, [HashTable]$cargs, $retryCount = 5)
{
    $success = $false
    $count = 0
    
    $body = @{
         CmdletInput = @{
              CmdletName="$command"
         }
    }

    if($cargs -ne $null){
        $body.CmdletInput += @{Parameters= [HashTable]$cargs}
    }

    $json = $body | ConvertTo-Json -Depth 5 -Compress
    [string]$commandFriendly = $($body.CmdletInput.CmdletName)

    for([int]$x = 0 ; $x -le $($body.CmdletInput.Parameters.Count - 1); $x++){
        try{$param = " -$([Array]$($body.CmdletInput.Parameters.Keys).Item($x))"}catch{$param = ''}
        try{$value = "`"$([Array]$($body.CmdletInput.Parameters.Values).Item($x) -join ',')`""}catch{$value = ''}
        $commandFriendly += $("$param $value").TrimEnd()
    }
    Write-Host "Executing: $commandFriendly"
    Write-Host $json
    
    [string]$url = $("https://outlook.office365.com/adminapi/beta/$tenant_name/InvokeCommand")
    if(![string]::IsNullOrEmpty($Properties)){
        $url = $url + $('?%24select='+$($Properties.Trim().Replace(' ','')))
    }
    [Array]$Data = @()
    do{
        try{
            do{
           

                ## Using HTTPWebRequest library

                $request = [System.Net.HttpWebRequest]::Create($url)
        	    $request.Method = "POST";
	            $request.ContentType =  "application/json";
	            $request.Headers["Authorization"] = "Bearer $($exo_token)"
                $request.Headers["x-serializationlevel"] = "Partial"
                #$request.Headers["x-clientmoduleversion"] = "2.0.6-Preview6"
                $request.Headers["X-AnchorMailbox"] = $("UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$tenant_name")
                $request.Headers["X-prefer"] = "odata.maxpagesize=1000"
                #$request.Headers["Prefer"] = 'odata.include-annotations="display.*"' v
                $request.Headers["X-ResponseFormat"] = "json" ## Can also be 'clixml'
                $request.Headers["connection-id"] = "$conn_id"
                #$request.Headers["accept-language"] = "en-GB"
                $request.Headers["accept-charset"] = "UTF-8"
                #$request.Headers["preference-applied"] = ''
                $request.Headers["warningaction"] = ""
                $request.SendChunked = $true;
                $request.TransferEncoding = "gzip"
                $request.UserAgent = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-AU) WindowsPowerShell/5.1.19041.1682"
                #$request.Host = "outlook.office365.com"
                $request.Accept = 'application/json'
        	    $request.Timeout = $($defaultTimeout*1000)

        	    $requestWriter = New-Object System.IO.StreamWriter $request.GetRequestStream();
	            $requestWriter.Write($json);
	            $requestWriter.Flush();
	            $requestWriter.Close();
	            $requestWriter.Dispose()

                $response = $request.GetResponse();
                $reader = new-object System.IO.StreamReader $response.GetResponseStream();
                $jsonResult = $reader.ReadToEnd();
                $result = $(ConvertFrom-Json $jsonResult)
                $response.Dispose();

                if(@($result.value).Count -ne 0){
                    $Data += $($result.value)
                    Write-Host "Got $($result.value.Count) items"
                }
                try{$url = $result.'@odata.nextLink'}catch{$url = ''}
                if(![string]::IsNullOrEmpty($url)){
                    Write-Host "Getting next page..."
                }
            }while(![string]::IsNullOrEmpty($url))
            $success = $true
            $count = $retry
        	return @($Data)
        } catch {
            if($($_.Exception.Message) -like "*timed out*" -or $($_.Exception.Message) -like "*Unable to connect to the remote server*"){
                $count++
                Write-Warning "TIMEOUT: Will retry in 10 seconds."
                Start-Sleep -seconds 10
                if($count -gt $retry){throw "Timeout retry limit reached"}
            }else{
                Write-Warning "Failed to execute Exchange command: $commandFriendly"
                Write-Warning $($_.Exception.Message)
                throw;
            }
        }
    }while($count -lt $retry -or $success -eq $false)
    return $null
}

Function CheckSuccess($dl, $conn, $user)
{
    $members = ExoCommand -conn $conn -Command "Get-DistributionGroupMember" -cargs @{ Identity = $dl }
            
    foreach($mem in $members)
    {
        if($mem.WindowsLiveID -eq $user)
        {
            Write-Host "Success!"
            return $true;
        }
    }

    return $false;
}























$conn_id = $([guid]::NewGuid().Guid).ToString()
$conn=$conn_id
$tenant_name='lvin.ie'
$exo_token='eyJ0eXAiOiJKV1QiLCJub25jZSI6ImRfTXhFdjA3bmY3ZHRuNTZpOE9md09OdG1pYUx0RUk5alpKcWg5YmVyRUkiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL291dGxvb2sub2ZmaWNlMzY1LmNvbSIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2ZhZmI0NmIxLTRiNjQtNDFlZi04ZjUyLTY4ZWQwY2NhZTMwZi8iLCJpYXQiOjE3MTYzOTM4NzYsIm5iZiI6MTcxNjM5Mzg3NiwiZXhwIjoxNzE2Mzk3Nzc2LCJhaW8iOiJFMk5nWU1oWjNUMUZxdmJTNzdNQlI3aG41RitJQmdBPSIsImFwcF9kaXNwbGF5bmFtZSI6IkF1dGhlbnRpY2F0ZSBhcyBVc2Ugb3IgQXBwIiwiYXBwaWQiOiI2YTQ3OGFhYi04NmQ2LTQxZmEtYWFjYi1lOTM2NTVjMjdiNzUiLCJhcHBpZGFjciI6IjEiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9mYWZiNDZiMS00YjY0LTQxZWYtOGY1Mi02OGVkMGNjYWUzMGYvIiwib2lkIjoiZWY4ZjliOTktYTI0NS00MzBhLTk1ODMtNGFjYWZmYTVlNmY0IiwicmgiOiIwLkFYa0FzVWI3LW1STDcwR1BVbWp0RE1yakR3SUFBQUFBQVBFUHpnQUFBQUFBQUFDVUFBQS4iLCJyb2xlcyI6WyJmdWxsX2FjY2Vzc19hc19hcHAiLCJPcmdhbml6YXRpb24uUmVhZFdyaXRlLkFsbCIsIk1haWwuUmVhZFdyaXRlIiwiTWFpbGJveFNldHRpbmdzLlJlYWRXcml0ZSIsIlVzZXIuUmVhZEJhc2ljLkFsbCIsIk1haWxib3guTWlncmF0aW9uIiwiU01UUC5TZW5kQXNBcHAiLCJFeGNoYW5nZS5NYW5hZ2VBc0FwcCJdLCJzaWQiOiJmOWRiMTAwZS0xMDBjLTQ3NTctOTdiYS0yMDg3ZWFkNjRiMTMiLCJzdWIiOiJlZjhmOWI5OS1hMjQ1LTQzMGEtOTU4My00YWNhZmZhNWU2ZjQiLCJ0aWQiOiJmYWZiNDZiMS00YjY0LTQxZWYtOGY1Mi02OGVkMGNjYWUzMGYiLCJ1dGkiOiJGejVBQk53RmUwZVZLd19Tb2Q4dUFBIiwidmVyIjoiMS4wIiwid2lkcyI6WyIwOTk3YTFkMC0wZDFkLTRhY2ItYjQwOC1kNWNhNzMxMjFlOTAiXX0.iGIkQv9UGoi3pzq8ZtDQWmKsT602nl37YYHb2Co8-Re9G-EStUOXQvtVup210ifRs3cEs6eck8uck4LEsy3Bb2lKG77FpG_XCw2-4bTU7qSCoUcgCke_KW2xhJqQ7BRQeQCxbiC3tY2JbtF-CCnr6yTCkpY1OQZi3vG4nZz2SHIZmd3m0CSdui6NTYj84Y8pTMSzUiSPUGpULv69sjsMVTV4ZIIbP9cO4h7coV_0NRQ56kiTHgCduHlIEoR3S_s_0_YtvUdy1fLZ21M2KmjAFoVMZIoxnmvzQnl6bd9L9rEy7GUVNYxbF2MQfZouqBAERV0F-xUrSBbFbrbwVW5bjg'
$exo_token=(ConvertTo-SecureString -String $exo_token -AsPlainText -Force )


#DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}@vdbdx.onmicrosoft.com
#UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@vdbdx.onmicrosoft.com

Function ExoCommand($conn, $command, [HashTable]$cargs, [int]$retry = 5,[int]$PageSize = 1000)
{
    
    [int]$defaultTimeout = 30;
    [int]$MaxRetries = 5         # In total we try 6 times. 1 original try, 5 retry attempts.
    $success = $false
    $count = 0
    
    $body = @{
         CmdletInput = @{
              CmdletName="$command"
         }
    }

    if($null -ne $cargs){
        $body.CmdletInput += @{Parameters= [HashTable]$cargs}
    }

    $json = $body | ConvertTo-Json -Depth 5 -Compress
    [string]$commandFriendly = $($body.CmdletInput.CmdletName)

    for([int]$x = 0 ; $x -le $($body.CmdletInput.Parameters.Count - 1); $x++){
        try{$param = " -$([Array]$($body.CmdletInput.Parameters.Keys).Item($x))"}catch{$param = ''}
        try{$value = "`"$([Array]$($body.CmdletInput.Parameters.Values).Item($x) -join ',')`""}catch{$value = ''}
        $commandFriendly += $("$param $value").TrimEnd()
    }
    Write-Host "Executing: $commandFriendly"
    Write-Host $json
    
    [string]$url = $("https://outlook.office365.com/adminapi/beta/$tenant_name/InvokeCommand")
    if(![string]::IsNullOrEmpty($Properties)){
        $url = $url + $('?%24select='+$($Properties.Trim().Replace(' ','')))
    }
    [Array]$Data = @()
    do{
        try{
            do{
           

                ## Using HTTPWebRequest library

                $request = [System.Net.HttpWebRequest]::Create($url)
        	    $request.Method = "POST";
	            $request.ContentType =  "application/json";
	            $request.Headers["Authorization"] = "Bearer $($exo_token)"
                $request.Headers["x-serializationlevel"] = "Partial"
                #$request.Headers["x-clientmoduleversion"] = "2.0.6-Preview6"
                $request.Headers["X-AnchorMailbox"] = $("UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$tenant_name")
                $request.Headers["X-prefer"] = "odata.maxpagesize=1000"
                #$request.Headers["Prefer"] = 'odata.include-annotations="display.*"' v
                $request.Headers["X-ResponseFormat"] = "json" ## Can also be 'clixml'
                $request.Headers["connection-id"] = "$conn_id"
                #$request.Headers["accept-language"] = "en-GB"
                $request.Headers["accept-charset"] = "UTF-8"
                #$request.Headers["preference-applied"] = ''
                $request.Headers["warningaction"] = ""
                $request.SendChunked = $true;
                $request.TransferEncoding = "gzip"
                $request.UserAgent = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-IE) WindowsPowerShell/5.1.19041.1682"
                #$request.Host = "outlook.office365.com"
                $request.Accept = 'application/json'
        	    $request.Timeout = $($defaultTimeout*1000)

        	    $requestWriter = New-Object System.IO.StreamWriter $request.GetRequestStream();
	            $requestWriter.Write($json);
	            $requestWriter.Flush();
	            $requestWriter.Close();
	            $requestWriter.Dispose()

                $response = $request.GetResponse();
                $reader = new-object System.IO.StreamReader $response.GetResponseStream();
                $jsonResult = $reader.ReadToEnd();
                $result = $(ConvertFrom-Json $jsonResult)
                $response.Dispose();

                if(@($result.value).Count -ne 0){
                    $Data += $($result.value)
                    Write-Host "Got $($result.value.Count) items"
                }
                try{$url = $result.'@odata.nextLink'}catch{$url = ''}
                if(![string]::IsNullOrEmpty($url)){
                    Write-Host "Getting next page..."
                }
            }while(![string]::IsNullOrEmpty($url))
            $success = $true
            $count = $retry
        	return @($Data)
        } catch {
            if($($_.Exception.Message) -like "*timed out*" -or $($_.Exception.Message) -like "*Unable to connect to the remote server*"){
                $count++
                Write-Warning "TIMEOUT: Will retry in 10 seconds."
                Start-Sleep -seconds 10
                if($count -gt $retry){throw "Timeout retry limit reached"}
            }else{
                Write-Warning "Failed to execute Exchange command: $commandFriendly"
                Write-Warning $($_.Exception.Message)
                throw;
            }
        }
    }while($count -lt $retry -or $success -eq $false)
    return $null
}



$user="c@lvin.ie"

Function CheckSuccess($dl, $conn, $user)
{
    $members = ExoCommand -conn $conn -Command "Get-Mailbox" -cargs @{ Identity = $user }
            
    foreach($mem in $members)
    {
        if($mem.WindowsLiveID -eq $user)
        {
            Write-Host "Success!"
            return $true;
        }
    }

    return $false;
}
<# BURP SUITE OF ExoCommand

POST /adminapi/beta/vdbdx.onmicrosoft.com/InvokeCommand HTTP/2
Host: outlook.office.com
Cookie: ClientId=C3BAFCA2FFF24681AA6A3EBCA407EA1E; OIDC=1
Sec-Ch-Ua: "Not_A Brand";v="8", "Chromium";v="120"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-IE) WindowsPowerShell/5.1.19041.1682
Accept: application/json
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
Content-Type: application/json
Authorization: Bearer _______________________.
X-Serializationlevel: Partial
X-Anchormailbox: UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@vdbdx.onmicrosoft.com
X-Prefer: odata.maxpagesize=1000
X-Responseformat: json
Connection-Id: a55728cf-c8b7-422a-82ad-3df81224d95a
Accept-Charset: UTF-8
Content-Length: 82

{"CmdletInput":{"CmdletName":"get-mailbox","Parameters":{"Identity":"c@lvin.ie"}}}

#>


<#

HTTP/2 200 OK
Cache-Control: no-cache
Content-Length: 15491
Content-Type: application/json;odata.metadata=minimal;odata.streaming=true;IEEE754Compatible=false;charset=utf-8
Vary: Accept-Encoding
Server: Microsoft-HTTPAPI/2.0
X-Nanoproxy: 1,1
Request-Id: cad3d16d-d10f-d607-b925-0ef6e74bf2df
X-Request-Processing-Service-Version: Core
X-Calculatedfetarget: PA7P264CU009.internal.outlook.com
Organizationstatus: Active
X-Feserver: DUZPR01CA0311
Preference-Applied: odata.include-annotations="*"
Access-Control-Allow-Origin: *
Odata-Version: 4.0
Rate-Limit-Limit: 30000
Alt-Svc: h3=":443";ma=2592000,h3-29=":443";ma=2592000
Ms-Cv: bdHTyg/RB9a5JQ7250vy3w.1.1
Rate-Limit-Remaining: 29997
Rate-Limit-Reset: 2024-05-22T16:52:26.365Z
Restrict-Access-Confirm: 1
X-Backendhttpstatus: 200,200
X-Calculatedbetarget: PAXPR07MB8842.eurprd07.PROD.OUTLOOK.COM
X-Combinedapponlyconcurrencycount: 0
X-Concurrencycount: 0
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Exchangeversion: Version 15.20 (Build 7587.36)
X-Feefzinfo: CDG
X-Usertype: Business
X-Feproxyinfo: PA7P264CA0121
X-Ms-Appid: c701980f-e49e-47ec-9528-2fc7cae77bea
X-Proxy-Backendserverstatus: 200
X-Proxy-Routingcorrectness: 1
X-Rum-Notupdatequeriedpath: 1
X-Rum-Notupdatequerieddbcopy: 1
X-Rum-Validated: 1
X-Firsthopcafeefz: DUB
Date: Wed, 22 May 2024 16:52:10 GMT

{"@odata.context":"https://outlook.office.com/adminapi/beta/vdbdx.onmicrosoft.com/$metadata#Collection(Exchange.GenericHashTable)","adminapi.warnings@odata.type":"#Collection(String)","@adminapi.warnings":[],"value":[{"AcceptMessagesOnlyFromWithDisplayNames@odata.type":"#Collection(String)","AcceptMessagesOnlyFromWithDisplayNames":[],"AcceptMessagesOnlyFromSendersOrMembersWithDisplayNames@odata.type":"#Collection(String)","AcceptMessagesOnlyFromSendersOrMembersWithDisplayNames":[],"AcceptMessagesOnlyFromDLMembersWithDisplayNames@odata.type":"#Collection(String)","AcceptMessagesOnlyFromDLMembersWithDisplayNames":[],"Database":"EURPR07DG224-db024","DatabaseGuid@data.type":"System.Guid","DatabaseGuid@odata.type":"#Guid","DatabaseGuid":"ae0627d4-b741-4f5e-bbc8-afde04ef72d2","MailboxProvisioningConstraint":null,"IsMonitoringMailbox":false,"MailboxRegion":null,"MailboxRegionLastUpdateTime":null,"MailboxRegionSuffix":"None","MessageRecallProcessingEnabled":true,"MessageCopyForSentAsEnabled":true,"MessageCopyForSendOnBehalfEnabled":false,"MailboxProvisioningPreferences@odata.type":"#Collection(String)","MailboxProvisioningPreferences":[],"UseDatabaseRetentionDefaults":false,"RetainDeletedItemsUntilBackup":false,"DeliverToMailboxAndForward":true,"IsExcludedFromServingHierarchy":false,"IsHierarchyReady":true,"IsHierarchySyncEnabled":true,"IsPublicFolderSystemMailbox":false,"HasSnackyAppData":false,"LitigationHoldEnabled":false,"SingleItemRecoveryEnabled":true,"RetentionHoldEnabled":false,"EndDateForRetentionHold":null,"StartDateForRetentionHold":null,"RetentionComment":"","RetentionUrl":"","LitigationHoldDate":null,"LitigationHoldOwner":"","ElcProcessingDisabled":false,"ComplianceTagHoldApplied":false,"WasInactiveMailbox":false,"DelayHoldApplied":false,"DelayReleaseHoldApplied":false,"PitrEnabled":false,"PitrCopyIntervalInSeconds@data.type":"System.Int16","PitrCopyIntervalInSeconds@odata.type":"#Int16","PitrCopyIntervalInSeconds":0,"PitrPaused":false,"PitrPausedTimestamp":null,"PitrOffboardedTimestamp":null,"PitrState":"None","InactiveMailboxRetireTime":null,"OrphanSoftDeleteTrackingTime":null,"LitigationHoldDuration":"Unlimited","ManagedFolderMailboxPolicy":null,"RetentionPolicy":"Default MRM Policy","AddressBookPolicy":null,"CalendarRepairDisabled":false,"ExchangeGuid@data.type":"System.Guid","ExchangeGuid@odata.type":"#Guid","ExchangeGuid":"2be92a50-7cc5-4a40-8471-b7ce9c2e3426","MailboxContainerGuid":null,"UnifiedMailbox":null,"MailboxLocations@odata.type":"#Collection(String)","MailboxLocations":["1;2be92a50-7cc5-4a40-8471-b7ce9c2e3426;Primary;eurprd07.prod.outlook.com;ae0627d4-b741-4f5e-bbc8-afde04ef72d2"],"AggregatedMailboxGuids@odata.type":"#Collection(String)","AggregatedMailboxGuids":[],"ExchangeSecurityDescriptor":"System.Security.AccessControl.RawSecurityDescriptor","ExchangeUserAccountControl":"None","AdminDisplayVersion":"Version 15.20 (Build 7587.36)","MessageTrackingReadStatusEnabled":true,"ExternalOofOptions":"External","ForwardingAddress":null,"ForwardingSmtpAddress":"smtp:calvinbergin212@gmail.com","RetainDeletedItemsFor":"00:00:00","IsMailboxEnabled":true,"Languages@odata.type":"#Collection(String)","Languages":["en-US"],"OfflineAddressBook":null,"ProhibitSendQuota":"99 GB (106,300,440,576 bytes)","ProhibitSendReceiveQuota":"100 GB (107,374,182,400 bytes)","RecoverableItemsQuota":"30 GB (32,212,254,720 bytes)","RecoverableItemsWarningQuota":"20 GB (21,474,836,480 bytes)","CalendarLoggingQuota":"6 GB (6,442,450,944 bytes)","DowngradeHighPriorityMessagesEnabled":false,"ProtocolSettings@odata.type":"#Collection(String)","ProtocolSettings":["MAPI\u00a71\u00a70\u00a7\u00a7\u00a70\u00a7\u00a7\u00a7\u00a7\u00a70","PublicFolderClientAccess\u00a70","IMAP4\u00a71\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7","POP3\u00a71\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7\u00a71","ECP\u00a71","HTTP\u00a71\u00a71\u00a7\u00a7\u00a7\u00a7\u00a7\u00a7","OWA\u00a71"],"RecipientLimits":"500","ImListMigrationCompleted":false,"SiloName":null,"IsResource":false,"IsLinked":false,"IsShared":false,"IsRootPublicFolderMailbox":false,"LinkedMasterAccount":"","ResetPasswordOnNextLogon":false,"ResourceCapacity":null,"ResourceCustom@odata.type":"#Collection(String)","ResourceCustom":[],"ResourceType":null,"RoomMailboxAccountEnabled":null,"SamAccountName":"$MFU660-9GR5ES1E7RJ5","SCLDeleteThreshold":null,"SCLDeleteEnabled":null,"SCLRejectThreshold":null,"SCLRejectEnabled":null,"SCLQuarantineThreshold":null,"SCLQuarantineEnabled":null,"SCLJunkThreshold":null,"SCLJunkEnabled":null,"AntispamBypassEnabled":false,"ServerLegacyDN":"/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=DB8PR07MB6409","ServerName":"db8pr07mb6409","UseDatabaseQuotaDefaults":false,"IssueWarningQuota":"98 GB (105,226,698,752 bytes)","RulesQuota":"256 KB (262,144 bytes)","Office":"","UserPrincipalName":"C@lvin.ie","UMEnabled":false,"MaxSafeSenders":null,"MaxBlockedSenders":null,"NetID":"100320020AE72C2C","ReconciliationId":null,"WindowsLiveID":"C@lvin.ie","MicrosoftOnlineServicesID":"C@lvin.ie","ThrottlingPolicy":null,"RoleAssignmentPolicy":"Default Role Assignment Policy","DefaultPublicFolderMailbox":null,"EffectivePublicFolderMailbox":"Public","SharingPolicy":"Default Sharing Policy","RemoteAccountPolicy":null,"MailboxPlan":"ExchangeOnlineEnterprise-e05f79cd-d532-4d81-85bf-7813a7124b77","ArchiveDatabase":null,"ArchiveDatabaseGuid@data.type":"System.Guid","ArchiveDatabaseGuid@odata.type":"#Guid","ArchiveDatabaseGuid":"00000000-0000-0000-0000-000000000000","ArchiveGuid@data.type":"System.Guid","ArchiveGuid@odata.type":"#Guid","ArchiveGuid":"00000000-0000-0000-0000-000000000000","ArchiveName@odata.type":"#Collection(String)","ArchiveName":[],"JournalArchiveAddress":"","ArchiveQuota":"100 GB (107,374,182,400 bytes)","ArchiveWarningQuota":"90 GB (96,636,764,160 bytes)","ArchiveDomain":null,"ArchiveStatus":"None","ArchiveState":"None","AutoExpandingArchiveEnabled":false,"DisabledMailboxLocations":false,"RemoteRecipientType":"None","DisabledArchiveDatabase":null,"DisabledArchiveGuid@data.type":"System.Guid","DisabledArchiveGuid@odata.type":"#Guid","DisabledArchiveGuid":"00000000-0000-0000-0000-000000000000","QueryBaseDN":null,"QueryBaseDNRestrictionEnabled":false,"MailboxMoveTargetMDB":null,"MailboxMoveSourceMDB":null,"MailboxMoveFlags":"None","MailboxMoveRemoteHostName":"","MailboxMoveBatchName":"","MailboxMoveStatus":"None","MailboxRelease":"E15","ArchiveRelease":"","IsPersonToPersonTextMessagingEnabled":false,"IsMachineToPersonTextMessagingEnabled":false,"UserSMimeCertificate@odata.type":"#Collection(String)","UserSMimeCertificate":[],"UserCertificate@odata.type":"#Collection(String)","UserCertificate":[],"CalendarVersionStoreDisabled":false,"ImmutableId":"","PersistedCapabilities@odata.type":"#Collection(String)","PersistedCapabilities":["M365AuditPlatform","InformationGovernance","InsiderRiskManagement","RecordsManagement","GRAPH_CONNECTORS_SEARCH_INDEX","BPOS_S_EquivioAnalytics","BPOS_S_Analytics","BPOS_S_ThreatIntelligenceAddOn","BPOS_S_O365PAM","BPOS_S_CustomerLockbox","CustomerKey","M365Auditing","CommunicationsCompliance","MIP_S_CLP2","BPOS_S_BookingsAddOn","BPOS_S_Enterprise"],"SKUAssigned":true,"AuditEnabled":true,"AuditLogAgeLimit":"90.00:00:00","AuditAdmin@odata.type":"#Collection(String)","AuditAdmin":["Update","MoveToDeletedItems","SoftDelete","HardDelete","SendAs","SendOnBehalf","Create","UpdateFolderPermissions","UpdateInboxRules","UpdateCalendarDelegation","ApplyRecord","MailItemsAccessed","Send"],"AuditDelegate@odata.type":"#Collection(String)","AuditDelegate":["Update","MoveToDeletedItems","SoftDelete","HardDelete","SendAs","SendOnBehalf","Create","UpdateFolderPermissions","UpdateInboxRules","ApplyRecord","MailItemsAccessed"],"AuditOwner@odata.type":"#Collection(String)","AuditOwner":["Update","MoveToDeletedItems","SoftDelete","HardDelete","UpdateFolderPermissions","UpdateInboxRules","UpdateCalendarDelegation","ApplyRecord","MailItemsAccessed","Send"],"DefaultAuditSet@odata.type":"#Collection(String)","DefaultAuditSet":["Admin","Delegate","Owner"],"WhenMailboxCreated@data.type":"System.DateTime","WhenMailboxCreated":"2022-09-21T08:07:47.0000000+00:00","SourceAnchor":"","UsageLocation":"Ireland","IsSoftDeletedByRemove":false,"IsSoftDeletedByDisable":false,"IsInactiveMailbox":false,"IncludeInGarbageCollection":false,"WhenSoftDeleted":null,"RecipientSoftDeletedStatus@data.type":"System.Int32","RecipientSoftDeletedStatus":0,"InPlaceHolds@odata.type":"#Collection(String)","InPlaceHolds":[],"GeneratedOfflineAddressBooks@odata.type":"#Collection(String)","GeneratedOfflineAddressBooks":[],"AccountDisabled":false,"StsRefreshTokensValidFrom@data.type":"System.DateTime","StsRefreshTokensValidFrom":"2023-09-01T17:48:55.0000000+00:00","NonCompliantDevices@odata.type":"#Collection(String)","NonCompliantDevices":[],"EnforcedTimestamps":"[{\"EventTimestamp\":\"2024-01-23T15:15:06.5823793Z\",\"EnforcedUntilTimestamp\":\"2024-01-23T15:10:06.5823793Z\",\"EventType\":16},{\"EventTimestamp\":\"2023-12-31T18:11:51.5398195Z\",\"EnforcedUntilTimestamp\":\"2023-12-31T18:06:51.5398195Z\",\"EventType\":15},{\"EventTimestamp\":\"2023-12-31T18:11:51.5363567Z\",\"EnforcedUntilTimestamp\":\"2023-12-31T18:06:51.5363567Z\",\"EventType\":15},{\"EventTimestamp\":\"2023-12-31T18:11:51.5292824Z\",\"EnforcedUntilTimestamp\":\"2023-12-31T18:06:51.5292824Z\",\"EventType\":15},{\"EventTimestamp\":\"2023-12-31T18:11:51.5254411Z\",\"EnforcedUntilTimestamp\":\"2023-12-31T18:06:51.5254411Z\",\"EventType\":15}]","DataEncryptionPolicy":null,"MessageCopyForSMTPClientSubmissionEnabled":true,"RecipientThrottlingThreshold":"Standard","SharedEmailDomainTenant":"","SharedEmailDomainState":"None","SharedWithTargetSmtpAddress":"","SharedEmailDomainStateLastModified":null,"EmailAddressDisplayNames@odata.type":"#Collection(String)","EmailAddressDisplayNames":[],"ResourceProvisioningOptions@odata.type":"#Collection(String)","ResourceProvisioningOptions":[],"Extensions@odata.type":"#Collection(String)","Extensions":[],"HasPicture":false,"HasSpokenName":false,"IsDirSynced":false,"AcceptMessagesOnlyFrom@odata.type":"#Collection(String)","AcceptMessagesOnlyFrom":[],"AcceptMessagesOnlyFromDLMembers@odata.type":"#Collection(String)","AcceptMessagesOnlyFromDLMembers":[],"AcceptMessagesOnlyFromSendersOrMembers@odata.type":"#Collection(String)","AcceptMessagesOnlyFromSendersOrMembers":[],"AddressListMembership@odata.type":"#Collection(String)","AddressListMembership":["\\All Users","\\Offline Global Address List","\\Mailboxes(VLV)","\\All Mailboxes(VLV)","\\All Recipients(VLV)","\\Default Global Address List"],"AdministrativeUnits@odata.type":"#Collection(String)","AdministrativeUnits":["219d2b6b-bed4-40ac-a970-3814b314315d","3e35303d-f6a1-4100-bce4-8bccea86614b","47044bb3-116e-48e4-b207-6aadf966836a","668906c6-4fea-422b-a78b-fd88a7930285","af038413-55f2-4486-a6ae-b9fc0399b0ff","a4b5f478-eedf-4c17-91bf-6d1bb3ae2591","1706f91f-d4a2-4167-b8c5-466a8e990215","51496a0c-e95d-4f2a-bfb0-fc008de8a1b4","007bac9c-91f9-489e-85ee-78c165777107","1dfb4257-650d-4f1f-ad90-c580dee5eb27","92d45aad-084a-4bea-89f9-aff1286584d4","c134d732-df0d-46a4-adb9-679725e92083","42a80353-64bd-460f-a04b-e59d0437059e"],"Alias":"CBergin","ArbitrationMailbox":null,"BypassModerationFromSendersOrMembers@odata.type":"#Collection(String)","BypassModerationFromSendersOrMembers":[],"OrganizationalUnit":"eurpr07a013.prod.outlook.com/Microsoft Exchange Hosted Organizations/vdbdx.onmicrosoft.com","CustomAttribute1":"","CustomAttribute10":"","CustomAttribute11":"","CustomAttribute12":"","CustomAttribute13":"","CustomAttribute14":"","CustomAttribute15":"","CustomAttribute2":"","CustomAttribute3":"","CustomAttribute4":"","CustomAttribute5":"","CustomAttribute6":"","CustomAttribute7":"","CustomAttribute8":"","CustomAttribute9":"","ExtensionCustomAttribute1@odata.type":"#Collection(String)","ExtensionCustomAttribute1":[],"ExtensionCustomAttribute2@odata.type":"#Collection(String)","ExtensionCustomAttribute2":[],"ExtensionCustomAttribute3@odata.type":"#Collection(String)","ExtensionCustomAttribute3":[],"ExtensionCustomAttribute4@odata.type":"#Collection(String)","ExtensionCustomAttribute4":[],"ExtensionCustomAttribute5@odata.type":"#Collection(String)","ExtensionCustomAttribute5":[],"DisplayName":"Calvin","EmailAddresses@odata.type":"#Collection(String)","EmailAddresses":["smtp:c@vdbdx.onmicrosoft.com","smtp:C@dread.ie","SPO:SPO_afdc2165-9c1e-4c14-9223-f02a033ec8cf@SPO_fafb46b1-4b64-41ef-8f52-68ed0ccae30f","SIP:c@lvin.ie","SMTP:C@lvin.ie"],"GrantSendOnBehalfTo@odata.type":"#Collection(String)","GrantSendOnBehalfTo":[],"ExternalDirectoryObjectId":"7cdbe897-3c7f-4fb6-a369-56408d68081f","HiddenFromAddressListsEnabled":false,"LastExchangeChangedTime":null,"LegacyExchangeDN":"/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=f9dfe54853d548349d2f1e4d919246b7-CBergin","MaxSendSize":"35 MB (36,700,160 bytes)","MaxReceiveSize":"36 MB (37,748,736 bytes)","ModeratedBy@odata.type":"#Collection(String)","ModeratedBy":[],"ModerationEnabled":false,"PoliciesIncluded@odata.type":"#Collection(String)","PoliciesIncluded":[],"PoliciesExcluded@odata.type":"#Collection(String)","PoliciesExcluded":["{26491cfc-9e50-4857-861b-0cb8df22b5d7}"],"EmailAddressPolicyEnabled":false,"PrimarySmtpAddress":"C@lvin.ie","RecipientType":"UserMailbox","RecipientTypeDetails":"UserMailbox","RejectMessagesFrom@odata.type":"#Collection(String)","RejectMessagesFrom":[],"RejectMessagesFromDLMembers@odata.type":"#Collection(String)","RejectMessagesFromDLMembers":[],"RejectMessagesFromSendersOrMembers@odata.type":"#Collection(String)","RejectMessagesFromSendersOrMembers":[],"RequireSenderAuthenticationEnabled":false,"SimpleDisplayName":"","SendModerationNotifications":"Always","UMDtmfMap@odata.type":"#Collection(String)","UMDtmfMap":["emailAddress:2","lastNameFirstName:237446225846","firstNameLastName:225846237446"],"WindowsEmailAddress":"C@lvin.ie","MailTip":null,"MailTipTranslations@odata.type":"#Collection(String)","MailTipTranslations":[],"Identity":"CBergin","Id":"CBergin","IsValid":true,"ExchangeVersion":"0.20 (15.0.0.0)","Name":"CBergin","DistinguishedName":"CN=CBergin,OU=vdbdx.onmicrosoft.com,OU=Microsoft Exchange Hosted Organizations,DC=EURPR07A013,DC=PROD,DC=OUTLOOK,DC=COM","ObjectCategory":"EURPR07A013.PROD.OUTLOOK.COM/Configuration/Schema/Person","ObjectClass@odata.type":"#Collection(String)","ObjectClass":["top","person","organizationalPerson","user"],"WhenChanged@data.type":"System.DateTime","WhenChanged":"2024-04-10T08:56:22.0000000+00:00","WhenCreated@data.type":"System.DateTime","WhenCreated":"2022-06-29T17:57:03.0000000+00:00","WhenChangedUTC@data.type":"System.DateTime","WhenChangedUTC":"2024-04-10T08:56:22.0000000Z","WhenCreatedUTC@data.type":"System.DateTime","WhenCreatedUTC":"2022-06-29T17:57:03.0000000Z","ExchangeObjectId@data.type":"System.Guid","ExchangeObjectId@odata.type":"#Guid","ExchangeObjectId":"2700871c-b807-4dc1-9887-1d1c93ecd5b5","OrganizationalUnitRoot":"vdbdx.onmicrosoft.com","OrganizationId":"EURPR07A013.PROD.OUTLOOK.COM/Microsoft Exchange Hosted Organizations/vdbdx.onmicrosoft.com - EURPR07A013.PROD.OUTLOOK.COM/ConfigurationUnits/vdbdx.onmicrosoft.com/Configuration","Guid@data.type":"System.Guid","Guid@odata.type":"#Guid","Guid":"9feb45ad-0cc9-43dc-a609-2110e2216c15","OriginatingServer":"AM0PR07A13DC001.EURPR07A013.PROD.OUTLOOK.COM"}]}

#>function Invoke-ExoCommandWithBackoff {
    param (
        [string]$CmdletName,
        [hashtable]$Parameters,
        [int]$MaxRetries = 5,
        [int]$PageSize = 1000
    )

    $conn_id = $([guid]::NewGuid().Guid).ToString()
    [int]$BaseDelay = 1000
    [Random]$Rnd = [Random]::new()
    $Results = @()

    $body = @{
        CmdletInput = @{
            CmdletName = "$CmdletName"
            Parameters = $Parameters
        }
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5 -Compress
    $encodedBody = [System.Text.Encoding]::UTF8.GetBytes($jsonBody)
    [string]$url = "https://outlook.office365.com/adminapi/beta/$tenant_name/InvokeCommand"
    [string]$nextPageUri = ''

    $Headers = @{
        'Accept'            = 'application/json'
        'Accept-Charset'    = 'UTF-8'
        'Content-Type'      = 'application/json'
        'X-CmdletName'      = $CmdletName
        'client-request-id' = [guid]::NewGuid().Guid
    }

    $nextPageSize = [Math]::min($PageSize, 1000)
    $anotherPagedQuery = $true

    while ($anotherPagedQuery) {
        $Headers['Prefer'] = "odata.maxpagesize=$nextPageSize"
        $isRetryHappening = $true
        $isQuerySuccessful = $false
        $retryCount = 0

        while ($isRetryHappening -and $retryCount -lt $MaxRetries) {
            try {
                $request = [System.Net.HttpWebRequest]::Create($url)
                $request.Method = 'POST'
                $request.ContentType = 'application/json;odata.metadata=minimal;odata.streaming=true;'
                $request.Headers['Authorization'] = "Bearer $($exo_token)"
                $request.Headers['x-serializationlevel'] = 'Partial'
                $request.Headers['X-AnchorMailbox'] = $("UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$tenant_name")
                $request.Headers['X-prefer'] = 'odata.maxpagesize=1000'
                $request.Headers['X-ResponseFormat'] = 'clixml'
                $request.Headers['connection-id'] = "$conn_id"
                $request.Headers['accept-charset'] = 'UTF-8'
                $request.Headers['warningaction'] = ''
                $request.SendChunked = $true
                $request.TransferEncoding = 'gzip'
                $request.UserAgent = 'Mozilla/5.0 (Windows NT; Windows NT 10.0; en-AU) WindowsPowerShell/5.1.19041.1682'
                $request.Accept = 'application/json'
                $request.Timeout = $defaultTimeout * 1000

                $requestWriter = New-Object System.IO.StreamWriter $request.GetRequestStream()
                $requestWriter.Write($encodedBody)
                $requestWriter.Flush()
                $requestWriter.Close()
                $requestWriter.Dispose()

                $response = $request.GetResponse()
                $reader = New-Object System.IO.StreamReader $response.GetResponseStream()
                $jsonResult = $reader.ReadToEnd()
                $result = $(ConvertFrom-Json $jsonResult)
                $response.Dispose()

                # Handle result as Clixml
                if (@([System.Management.Automation.PSSerializer]::Deserialize($result.value.'_clixml')).Count -ne 0) {
                    $Results += $([System.Management.Automation.PSSerializer]::Deserialize($result.value.'_clixml'))
                    Write-Host "Got $($result.value.Count) items"
                }

                try { $url = $result.'@odata.nextLink' } catch { $url = '' }

                if (![string]::IsNullOrEmpty($url)) {
                    Write-Host 'Getting next page...'
                }

                $isQuerySuccessful = $true
                $isRetryHappening = $false
            } catch {
                if ($retryCount -lt $MaxRetries) {
                    $delay = [Math]::Pow(2, $retryCount) * $BaseDelay + $Rnd.Next(0, 1000)
                    Write-Warning "Attempt $retryCount failed. Retrying in $($delay/1000) seconds."
                    Start-Sleep -Milliseconds $delay
                } else {
                    Write-Warning "Failed to execute Exchange command: $CmdletName after $MaxRetries attempts."
                    throw
                }
                $retryCount++
            }
        }
        if (!$isQuerySuccessful) {
            $anotherPagedQuery = $false
        }
    }
    return $Results
}

Function Search-UnifiedAuditLogWithBackoff {
    param (
        [datetime]$StartDate,
        [datetime]$EndDate,
        [string]$UserIds
    )

    $Parameters = @{
        StartDate = $StartDate
        EndDate   = $EndDate
        UserIds   = $UserIds
    }

    $results = Invoke-ExoCommandWithBackoff -CmdletName 'Search-UnifiedAuditLog' -Parameters $Parameters

    return $results
}



