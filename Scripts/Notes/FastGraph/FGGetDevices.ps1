function Get-DevicesFast {
    <#
        .SYNOPSIS
        High-throughput device inventory from Entra ID using Graph REST + a reusable HttpClient.

        .DESCRIPTION
        - Pulls /devices with $select paging (no pipeline churn).
        - Optional filter by one or more user UPNs/email: unions users/{id|upn}/ownedDevices and registeredDevices, then batches detail fetch.
        - Optional enrichment: registeredOwners/registeredUsers (UPNs) fetched via Graph $batch in chunks (bounded).
        - Exports CSV or JSON.

        .PARAMETER OutputDir
        Default: Output\Device Information

        .PARAMETER Encoding
        Default: UTF8

        .PARAMETER Output
        CSV or JSON (default CSV)

        .PARAMETER LogLevel
        None | Minimal | Standard | Debug (default Standard)

        .PARAMETER UserIds
        Comma- or space-separated list of UPNs/emails to limit devices to (owner/registered to).

        .PARAMETER IncludeOwners
        If set, also resolve RegisteredOwners/RegisteredUsers UPN lists via batched calls (slower; still efficient).
    #>
    [CmdletBinding()]
    param (
        [string]$OutputDir = "Output\Device Information",
        [string]$Encoding = "UTF8",
        [ValidateSet("CSV", "JSON")]
        [string]$Output = "CSV",
        [ValidateSet('None','Minimal','Standard','Debug')]
        [string]$LogLevel = 'Standard',
        [string]$UserIds,
        [switch]$IncludeOwners
    )

    # ---- Logging + setup ----
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    if (-not (Test-Path $OutputDir)) { $null = New-Item -ItemType Directory -Force -Path $OutputDir }

    $dateTag = Get-Date -Format "yyyyMMddHHmm"
    $outPath = Join-Path $OutputDir ("{0}-Devices.{1}" -f $dateTag, $Output.ToLower())

    $summary = [ordered]@{
        TotalDevices           = 0
        AzureADJoined          = 0
        WorkplaceJoined        = 0
        HybridJoined           = 0
        ActiveDevices30Days    = 0
        InactiveDevices90Days  = 0
        CompliantDevices       = 0
        ManagedDevices         = 0
        Windows                = 0
        MacOS                  = 0
        iOS                    = 0
        Android                = 0
        Other                  = 0
        StartTime              = Get-Date
        ProcessingTime         = $null
    }

    Write-LogFile -Message "=== Starting Device Collection (fast) ===" -Color "Cyan" -Level Standard
    if ($isDebug) {
        Write-LogFile -Message "[DEBUG] OutputDir: $OutputDir; Output: $Output; IncludeOwners: $IncludeOwners; UserIds: $UserIds" -Level Debug
    }

    # ---- Utility: flatten a device JsonElement to PSCustomObject (minimal allocations) ----
    function Convert-DeviceJson {
        param([System.Text.Json.JsonElement]$e)

        $ht = [ordered]@{}
        foreach ($p in $e.EnumerateObject()) {
            $name = $p.Name
            switch ($name) {
                'id'                              { $ht.ObjectId = $p.Value.GetString(); continue }
                'deviceId'                        { $ht.DeviceId = $p.Value.GetString(); continue }
                'accountEnabled'                  { $ht.AccountEnabled = $p.Value.GetBoolean(); continue }
                'deviceOwnership'                 { $ht.DeviceOwnership = $p.Value.GetString(); continue }
                'displayName'                     { $ht.DisplayName = $p.Value.GetString(); continue }
                'enrollmentType'                  { $ht.EnrollmentType = $p.Value.GetString(); continue }
                'isCompliant'                     { $ht.IsCompliant = $p.Value.GetBoolean(); continue }
                'isManaged'                       { $ht.IsManaged = $p.Value.GetBoolean(); continue }
                'isRooted'                        { $ht.IsRooted = if ($p.Value.ValueKind -eq 'True') { $true } elseif ($p.Value.ValueKind -eq 'False') { $false } else { $null }; continue }
                'managementType'                  { $ht.ManagementType = $p.Value.GetString(); continue }
                'deviceCategory'                  { $ht.DeviceCategory = $p.Value.GetString(); continue }
                'operatingSystem'                 { $ht.OperatingSystem = $p.Value.GetString(); continue }
                'operatingSystemVersion'          { $ht.OperatingSystemVersion = $p.Value.GetString(); continue }
                'manufacturer'                    { $ht.Manufacturer = $p.Value.GetString(); continue }
                'model'                           { $ht.Model = $p.Value.GetString(); continue }
                'approximateLastSignInDateTime'   { $ht.LastSignInDateTime = $p.Value.GetString(); continue }
                'trustType'                       { $ht.TrustType = $p.Value.GetString(); continue }
                'mdmAppId'                        { $ht.MDMAppId = $p.Value.GetString(); continue }
                'onPremisesSyncEnabled'           { $ht.OnPremisesSyncEnabled = if ($p.Value.ValueKind -eq 'True') { $true } elseif ($p.Value.ValueKind -eq 'False') { $false } else { $null }; continue }
                'profileType'                     { $ht.ProfileType = $p.Value.GetString(); continue }
                'securityIdentifier'              { $ht.SecurityIdentifier = $p.Value.GetString(); continue }
                'createdDateTime'                 { $ht.CreatedDateTime = $p.Value.GetString(); continue }
                default                           { }
            }
        }
        # Normalize date strings
        if ($ht.LastSignInDateTime) {
            try { $ht.LastSignInDateTime = (Get-Date $ht.LastSignInDateTime).ToString('yyyy-MM-dd HH:mm:ss') } catch { }
        }
        if ($ht.CreatedDateTime) {
            try { $ht.CreatedDateTime = (Get-Date $ht.CreatedDateTime).ToString('yyyy-MM-dd HH:mm:ss') } catch { }
        }
        if ($IncludeOwners) {
            if (-not $ht.Contains('RegisteredOwners')) { $ht.RegisteredOwners = '' }
            if (-not $ht.Contains('RegisteredUsers'))  { $ht.RegisteredUsers  = '' }
        }
        return [pscustomobject]$ht
    }

    # ---- Query helpers ----
    $deviceSelect = @(
        'id','deviceId','accountEnabled','deviceOwnership','displayName','enrollmentType','isCompliant',
        'isManaged','isRooted','managementType','deviceCategory','operatingSystem','operatingSystemVersion',
        'manufacturer','model','approximateLastSignInDateTime','trustType','mdmAppId','onPremisesSyncEnabled',
        'profileType','securityIdentifier','createdDateTime'
    )

    function Get-DevicesAllPages {
        param()
        $path = 'devices'
        return Get-GraphPaged -Path $path -Select $deviceSelect -Top 999
    }

    function Get-UserDeviceIds {
        param([string[]]$Upns)
        $ids = New-Object System.Collections.Generic.HashSet[string]
        foreach ($upn in $Upns) {
            $u = $upn.Trim()
            if (-not $u) { continue }
            # ownedDevices
            $owned = Get-GraphPaged -Path ("users/$u/ownedDevices") -Select @('id') -Top 999
            foreach ($o in $owned) { [void]$ids.Add($o.id) }
            # registeredDevices
            $regd = Get-GraphPaged -Path ("users/$u/registeredDevices") -Select @('id') -Top 999
            foreach ($r in $regd) { [void]$ids.Add($r.id) }
        }
        return $ids.ToArray()
    }

    function Get-DevicesByIds-Batched {
        param([string[]]$Ids)
        $result = [System.Collections.Generic.List[object]]::new()
        $i = 0
        while ($i -lt $Ids.Count) {
            $chunk = $Ids[$i..([Math]::Min($Ids.Count-1,$i+19))]   # 20 per $batch
            $reqs = @()
            $rid = 1
            foreach ($id in $chunk) {
                $url = "devices/$id?`$select=$([string]::Join(',', $deviceSelect))"
                $reqs += @{ id="$rid"; method='GET'; url=$url }
                $rid++
            }
            $batch = Invoke-GffBatch -Requests $reqs
            foreach ($resp in $batch.responses) {
                if ($resp.status -eq 200 -and $resp.body) {
                    # Convert body (single object) via Convert-DeviceJson
                    $json = $resp.body | ConvertTo-Json -Depth 10
                    $doc = [System.Text.Json.JsonDocument]::Parse([System.Text.Encoding]::UTF8.GetBytes($json))
                    try { [void]$result.Add( (Convert-DeviceJson -e $doc.RootElement) ) } finally { $doc.Dispose() }
                }
            }
            $i += $chunk.Count
        }
        return $result
    }

    function Enrich-OwnersUsers-Batched {
        param([System.Collections.Generic.List[object]]$Devices)
        # For each 20 devices, make up to 40 requests (owners + users) split into 2 batches of 20
        $index = 0
        while ($index -lt $Devices.Count) {
            $group = $Devices[$index..([Math]::Min($Devices.Count-1,$index+19))]
            # owners batch
            $reqs = @()
            $rid = 1
            foreach ($d in $group) {
                $reqs += @{ id="$rid"; method='GET'; url="devices/$($d.ObjectId)/registeredOwners?`$select=userPrincipalName&`$top=999" }
                $rid++
            }
            $ownersBatch = Invoke-GffBatch -Requests $reqs
            # users batch
            $reqs2 = @()
            $rid = 1
            foreach ($d in $group) {
                $reqs2 += @{ id="$rid"; method='GET'; url="devices/$($d.ObjectId)/registeredUsers?`$select=userPrincipalName&`$top=999" }
                $rid++
            }
            $usersBatch = Invoke-GffBatch -Requests $reqs2

            # map back
            for ($k=0; $k -lt $group.Count; $k++) {
                $dev = $group[$k]
                # owners
                $oResp = $ownersBatch.responses[$k]
                if ($oResp.status -eq 200 -and $oResp.body) {
                    $owners = @()
                    foreach ($el in $oResp.body.value) {
                        if ($el.userPrincipalName) { $owners += [string]$el.userPrincipalName }
                    }
                    $dev.RegisteredOwners = ($owners -join '; ')
                }
                # users
                $uResp = $usersBatch.responses[$k]
                if ($uResp.status -eq 200 -and $uResp.body) {
                    $users = @()
                    foreach ($el2 in $uResp.body.value) {
                        if ($el2.userPrincipalName) { $users += [string]$el2.userPrincipalName }
                    }
                    $dev.RegisteredUsers = ($users -join '; ')
                }
            }
            $index += $group.Count
        }
    }

    # ---- Acquire devices ----
    $devicesList = [System.Collections.Generic.List[object]]::new()

    if ($UserIds) {
        Write-LogFile -Message "[INFO] Filtering devices by user(s): $UserIds" -Level Standard
        $upns = ($UserIds -split '[,; ]+') | Where-Object { $_ }
        $ids = Get-UserDeviceIds -Upns $upns
        if ($isDebug) { Write-LogFile -Message "[DEBUG] Unique device IDs matched to users: $($ids.Count)" -Level Debug }
        if ($ids.Count -gt 0) {
            $details = Get-DevicesByIds-Batched -Ids $ids
            foreach ($d in $details) { [void]$devicesList.Add($d) }
        }
    } else {
        # Fast streaming of all devices
        $raw = Get-DevicesAllPages
        foreach ($row in $raw) {
            # row is PSCustomObject from Get-GraphPaged; convert schema
            $j = $row | ConvertTo-Json -Depth 5
            $doc = [System.Text.Json.JsonDocument]::Parse([System.Text.Encoding]::UTF8.GetBytes($j))
            try { [void]$devicesList.Add( (Convert-DeviceJson -e $doc.RootElement) ) } finally { $doc.Dispose() }
        }
    }

    $summary.TotalDevices = $devicesList.Count
    Write-LogFile -Message "[INFO] Devices collected: $($summary.TotalDevices)" -Level Standard

    # ---- Optional enrichment: registered owners/users (batched) ----
    if ($IncludeOwners -and $devicesList.Count -gt 0) {
        Write-LogFile -Message "[INFO] Enriching RegisteredOwners/RegisteredUsers (batched)..." -Level Standard
        Enrich-OwnersUsers-Batched -Devices $devicesList
    }

    # ---- Summaries ----
    foreach ($dev in $devicesList) {
        switch ($dev.TrustType) {
            'AzureAd'  { $summary.AzureADJoined++ }
            'Workplace'{ $summary.WorkplaceJoined++ }
            'ServerAd' { $summary.HybridJoined++ }
        }
        if ($dev.IsCompliant) { $summary.CompliantDevices++ }
        if ($dev.IsManaged)   { $summary.ManagedDevices++ }

        if ($dev.LastSignInDateTime) {
            try {
                $dt = Get-Date $dev.LastSignInDateTime
                if ($dt -gt (Get-Date).AddDays(-30)) { $summary.ActiveDevices30Days++ }
                if ($dt -lt (Get-Date).AddDays(-90)) { $summary.InactiveDevices90Days++ }
            } catch { }
        }

        switch -Wildcard ($dev.OperatingSystem) {
            'Windows*' { $summary.Windows++ }
            'Mac*'     { $summary.MacOS++ }
            'iOS*'     { $summary.iOS++ }
            'Android*' { $summary.Android++ }
            default    { $summary.Other++ }
        }
    }

    # ---- Export ----
    if ($Output -eq 'CSV') {
        $devicesList | Select-Object `
            CreatedDateTime,DeviceId,ObjectId,AccountEnabled,DeviceOwnership,DisplayName,EnrollmentType,IsCompliant,IsManaged,IsRooted,ManagementType,DeviceCategory,OperatingSystem,OperatingSystemVersion,Manufacturer,Model,LastSignInDateTime,TrustType,RegisteredOwners,RegisteredUsers,MDMAppId,OnPremisesSyncEnabled,ProfileType,SecurityIdentifier |
            Export-Csv -NoTypeInformation -Encoding $Encoding -Path $outPath
    } else {
        $devicesList | ConvertTo-Json -Depth 6 | Out-File -FilePath $outPath -Encoding $Encoding
    }

    $summary.ProcessingTime = (Get-Date) - $summary.StartTime

    # ---- Summary log ----
    Write-LogFile -Message "`n=== Device Analysis Summary ===" -Color "Cyan" -Level Standard
    Write-LogFile -Message "  Total Devices       : $($summary.TotalDevices)" -Level Standard
    Write-LogFile -Message "  Entra ID Joined     : $($summary.AzureADJoined)" -Level Standard
    Write-LogFile -Message "  Workplace Joined    : $($summary.WorkplaceJoined)" -Level Standard
    Write-LogFile -Message "  Hybrid Joined       : $($summary.HybridJoined)" -Level Standard
    Write-LogFile -Message "  Compliant           : $($summary.CompliantDevices)" -Level Standard
    Write-LogFile -Message "  Managed             : $($summary.ManagedDevices)" -Level Standard
    Write-LogFile -Message "  Active (<=30d)      : $($summary.ActiveDevices30Days)" -Level Standard
    Write-LogFile -Message "  Inactive (>=90d)    : $($summary.InactiveDevices90Days)" -Level Standard
    Write-LogFile -Message "  Windows/Mac/iOS/And : $($summary.Windows)/$($summary.MacOS)/$($summary.iOS)/$($summary.Android)" -Level Standard
    Write-LogFile -Message "  Other OS            : $($summary.Other)" -Level Standard
    Write-LogFile -Message "`nOutput File          : $outPath" -Level Standard
    Write-LogFile -Message "Processing Time       : $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
    Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}
