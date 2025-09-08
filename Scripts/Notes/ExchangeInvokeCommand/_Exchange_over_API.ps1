$conn_id = $([guid]::NewGuid().Guid).ToString()
[int]$defaultTimeout = 30;

Function ExoCommand($conn, $command, [HashTable]$cargs, $retryCount = 5) {
    $success = $false
    $count = 0

    $body = @{
        CmdletInput = @{
            CmdletName = "$command"
        }
    }

    if ($cargs -ne $null) {
        $body.CmdletInput += @{Parameters = [HashTable]$cargs }
    }

    $json = $body | ConvertTo-Json -Depth 5 -Compress
    [string]$commandFriendly = $($body.CmdletInput.CmdletName)

    for ([int]$x = 0 ; $x -le $($body.CmdletInput.Parameters.Count - 1); $x++) {
        try { $param = " -$([Array]$($body.CmdletInput.Parameters.Keys).Item($x))" }catch { $param = '' }
        try { $value = "`"$([Array]$($body.CmdletInput.Parameters.Values).Item($x) -join ',')`"" }catch { $value = '' }
        $commandFriendly += $("$param $value").TrimEnd()
    }
    Write-Host "Executing: $commandFriendly"
    Write-Host $json

    [string]$url = $("https://outlook.office365.com/adminapi/beta/$tenant_name/InvokeCommand")
    if (![string]::IsNullOrEmpty($Properties)) {
        $url = $url + $('?%24select=' + $($Properties.Trim().Replace(' ', '')))
    }
    [Array]$Data = @()
    do {
        try {
            do {


                ## Using HTTPWebRequest library

                $request = [System.Net.HttpWebRequest]::Create($url)
                $request.Method = "POST";
                $request.ContentType = "application/json;odata.metadata=minimal;odata.streaming=true;";
                $request.Headers["Authorization"] = "Bearer $($exo_token)"
                $request.Headers["x-serializationlevel"] = "Partial"
                #$request.Headers["x-clientmoduleversion"] = "2.0.6-Preview6"
                $request.Headers["X-AnchorMailbox"] = $("UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$tenant_name")
                $request.Headers["X-prefer"] = "odata.maxpagesize=1000"
                #$request.Headers["Prefer"] = 'odata.include-annotations="display.*"'
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
                $request.Timeout = $($defaultTimeout * 1000)

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

                if (@($result.value).Count -ne 0) {
                    $Data += $($result.value)
                    Write-Host "Got $($result.value.Count) items"
                }
                try { $url = $result.'@odata.nextLink' }catch { $url = '' }
                if (![string]::IsNullOrEmpty($url)) {
                    Write-Host "Getting next page..."
                }
            }while (![string]::IsNullOrEmpty($url))
            $success = $true
            $count = $retry
            return @($Data)
        }
        catch {
            if ($($_.Exception.Message) -like "*timed out*" -or $($_.Exception.Message) -like "*Unable to connect to the remote server*") {
                $count++
                Write-Warning "TIMEOUT: Will retry in 10 seconds."
                Start-Sleep -seconds 10
                if ($count -gt $retry) { throw "Timeout retry limit reached" }
            }
            else {
                Write-Warning "Failed to execute Exchange command: $commandFriendly"
                Write-Warning $($_.Exception.Message)
                throw;
            }
        }
    }while ($count -lt $retry -or $success -eq $false)
    return $null

}

Function GetLists($exoToken, $tenantId) {
    $senderList = @();
    $domainList = @();
    $success = $false;

    try {
        $defaultPolicy = ExoCommand -conn $conn -Command 'Get-HostedContentFilterPolicy' -cargs @{ Identity = 'Default' }

        <#
        $blockedSenderList = $defaultPolicy | Select -ExpandProperty BlockedSenders | Select -ExpandProperty Sender | Select -ExpandProperty Address
        $blockedDomainList = $defaultPolicy | Select -ExpandProperty BlockedSenderDomains | Select -ExpandProperty Domain
        $allowedSenderList = $defaultPolicy | Select -ExpandProperty AllowedSenders | Select -ExpandProperty Sender | Select -ExpandProperty Address
        $allowedDomainList = $defaultPolicy | Select -ExpandProperty AllowedSenderDomains | Select -ExpandProperty Domain
        #>
        $blockedSenderList = $defaultPolicy | Select -ExpandProperty BlockedSenders
        $blockedDomainList = $defaultPolicy | Select -ExpandProperty BlockedSenderDomains
        $allowedSenderList = $defaultPolicy | Select -ExpandProperty AllowedSenders
        $allowedDomainList = $defaultPolicy | Select -ExpandProperty AllowedSenderDomains



        $success = $true;
    }
    finally {

    }
    $resultBlocked = @{
        sender_list = $blockedSenderList;
        domain_list = $blockedDomainList;
    }

    $resultAllowed = @{
        sender_list = $allowedSenderList;
        domain_list = $allowedDomainList;
    }

    return $resultBlocked, $resultAllowed, $success;
}

Function ExecuteActivity() {
    Write-Host "Begin Get Blocked List on O365"
    $resultBlocked, $resultAllowed, $success = GetLists -exoToken $exo_token -tenantId $tenant_id

    # Set output variables
    $activityOutput.out.allowed = $resultAllowed;
    $activityOutput.out.blocked = $resultBlocked;

    # Set execution status
    $activityOutput.success = $success;
    return $activityOutput;
}
