function Setup-ExchageRunspace {
    [CmdletBinding()]
    param ()
    
    begin {
        # Create runspace environment
        $ps=[PowerShell]::Create()
        $runspace=[runspacefactory]::CreateRunspace()
        $runspace.ApartmentState = "STA"
        $runspace.ThreadOptions = "ReuseThread"
        $ps.Runspace=$runspace

        # Add input variables
        $exo_token = $([Environment]::GetEnvironmentVariable('EXO_TOKEN'))
        $tenant_name = $([Environment]::GetEnvironmentVariable('TENANT_NAME'))
    }
    
    process {
        $runspace.Open();

        
    }
    
    end {
        
    }
}
$url
$exo_token
$tenant_name
$conn_id
$defaultTimeout

$conn_id = $([guid]::NewGuid().Guid).ToString()
[int]$defaultTimeout = 30;

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
	            $request.ContentType =  "application/json;odata.metadata=minimal;odata.streaming=true;";
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

Function Get-UALAll {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string[]]$UserIds,
        [Parameter(Mandatory=$false)]
        [DateTime]$StartDate = (Get-Date).AddDays(-90),
        [Parameter(Mandatory=$false)]
        [DateTime]$EndDate = (Get-Date),
        [Parameter(Mandatory=$false)]
        [int]$Interval = 60,
        [Parameter(Mandatory=$false)]
        [string]$Output = "CSV",
        [Parameter(Mandatory=$false)]
        [string]$OutputDir = "Output\UnifiedAuditLog",
        [Parameter(Mandatory=$false)]
        [string]$Encoding = "UTF8",
        [Parameter(Mandatory=$false)]
        [string]$RecordType,
        [Parameter(Mandatory=$false)]
        [string]$Keyword,
        [Parameter(Mandatory=$false)]
        [string]$Service,
        [Parameter(Mandatory=$false)]
        [string]$Operations,
        [Parameter(Mandatory=$false)]
        [string]$IPAddress,
        [Parameter(Mandatory=$false)]
        [string]$Name
    )

    $Data = @()
    $retryCount = 0;
    $success = $false
    $count = 0
    $apiVersion = "beta"
    $tenantName = $([regex]::Match(($conn.url).split("/")[-1],"^[a-zA-Z0-9]+")).Value
    $url = "https://outlook.office365.com/adminapi/$apiVersion/$tenantName/SearchUnifiedAuditLog"
    $retry = 3

    $SearchParameters = [PSCustomObject]@{}
    if($UserIds){$SearchParameters | Add-Member -MemberType NoteProperty -Name "UserIds" -Value $UserIds}
    if($StartDate){$SearchParameters | Add-Member -MemberType NoteProperty -Name "StartDate" -Value $StartDate.ToString("s")}
    if($EndDate){$SearchParameters | Add-Member -MemberType NoteProperty -Name "EndDate" -Value $EndDate.ToString("s")}
    if($Interval){$SearchParameters | Add-Member -MemberType NoteProperty -Name "Interval" -Value $Interval}
    if($RecordType){$SearchParameters | Add-Member -MemberType NoteProperty -Name "RecordType" -Value $RecordType}
    if($Keyword){$SearchParameters | Add-Member -MemberType NoteProperty -Name "Keyword" -Value $Keyword}
    if($Service){$SearchParameters | Add-Member -MemberType NoteProperty -Name "Service" -Value $Service}
    if($Operations){$SearchParameters | Add-Member -MemberType NoteProperty -Name "Operations" -Value $Operations}
    if($IPAddress){$SearchParameters | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value $IPAddress}
    if($Name){$SearchParameters | Add-Member -MemberType NoteProperty -Name "Name" -Value $Name}

    while($count -lt $retry -or $success -eq $false){
        if($count -gt 0){
            Write-Host "Retries: $count"
            Start-Sleep -Seconds ([math]::Pow(2, $count-1))
        }

        try{
            $body = @{
                CmdletInput = @{
                    CmdletName="SearchUnifiedAuditLog"
                    Parameters= @{}
                }
            }
            $body.CmdletInput.Parameters = $SearchParameters
            $result=ExoCommand -Command $body.CmdletInput.CmdletName -cargs $body.CmdletInput.Parameters

            if($result.Value.Length -gt 0) {
                $SearchParameters.StartDate = $result.Value[-1].CreationDate.ToString("s")
                $result.Value | ConvertTo-Csv -NoTypeInformation | Out-File -Append -Encoding UTF8 "UALData-$($SearchParameters.StartDate.ToString('yyyyMMddHHmmss')).csv"
            }
            else {
                $SearchParameters.StartDate = $result.Value[-1].CreationDate.ToString("s")
            }
        }catch{
            Write-Host $_.Exception.Message
        }
    }

    return $Data
}


function Get-UALStatistics {
    [CmdletBinding()]
    param(
        [string]$UserIds,
        [string]$StartDate,
        [string]$EndDate,
        [string]$OutputDir
    )

    $recordTypes = "ExchangeAdmin","ExchangeItem","ExchangeItemGroup","SharePoint","SyntheticProbe","SharePointFileOperation","OneDrive","AzureActiveDirectory","AzureActiveDirectoryAccountLogon","DataCenterSecurityCmdlet","ComplianceDLPSharePoint","Sway","ComplianceDLPExchange","SharePointSharingOperation","AzureActiveDirectoryStsLogon","SkypeForBusinessPSTNUsage","SkypeForBusinessUsersBlocked","SecurityComplianceCenterEOPCmdlet","ExchangeAggregatedOperation","PowerBIAudit","CRM","Yammer","SkypeForBusinessCmdlets","Discovery","MicrosoftTeams","ThreatIntelligence","MailSubmission","MicrosoftFlow","AeD","MicrosoftStream","ComplianceDLPSharePointClassification","ThreatFinder","Project","SharePointListOperation","SharePointCommentOperation","DataGovernance","Kaizala","SecurityComplianceAlerts","ThreatIntelligenceUrl","SecurityComplianceInsights","MIPLabel","WorkplaceAnalytics","PowerAppsApp","PowerAppsPlan","ThreatIntelligenceAtpContent","LabelContentExplorer","TeamsHealthcare","ExchangeItemAggregated","HygieneEvent","DataInsightsRestApiAudit","InformationBarrierPolicyApplication","SharePointListItemOperation","SharePointContentTypeOperation","SharePointFieldOperation","MicrosoftTeamsAdmin","HRSignal","MicrosoftTeamsDevice","MicrosoftTeamsAnalytics","InformationWorkerProtection","Campaign","DLPEndpoint","AirInvestigation","Quarantine","MicrosoftForms","ApplicationAudit","ComplianceSupervisionExchange","CustomerKeyServiceEncryption","OfficeNative","MipAutoLabelSharePointItem","MipAutoLabelSharePointPolicyLocation","MicrosoftTeamsShifts","SecureScore","MipAutoLabelExchangeItem","CortanaBriefing","Search","WDATPAlerts","PowerPlatformAdminDlp","PowerPlatformAdminEnvironment","MDATPAudit","SensitivityLabelPolicyMatch","SensitivityLabelAction","SensitivityLabeledFileAction","AttackSim","AirManualInvestigation","SecurityComplianceRBAC","UserTraining","AirAdminActionInvestigation","MSTIC","PhysicalBadgingSignal","TeamsEasyApprovals","AipDiscover","AipSensitivityLabelAction","AipProtectionAction","AipFileDeleted","AipHeartBeat","MCASAlerts","OnPremisesFileShareScannerDlp","OnPremisesSharePointScannerDlp","ExchangeSearch","SharePointSearch","PrivacyDataMinimization","LabelAnalyticsAggregate","MyAnalyticsSettings","SecurityComplianceUserChange","ComplianceDLPExchangeClassification","ComplianceDLPEndpoint","MipExactDataMatch","MSDEResponseActions","MSDEGeneralSettings","MSDEIndicatorsSettings","MS365DCustomDetection","MSDERolesSettings","MAPGAlerts","MAPGPolicy","MAPGRemediation","PrivacyRemediationAction","PrivacyDigestEmail","MipAutoLabelSimulationProgress","MipAutoLabelSimulationCompletion","MipAutoLabelProgressFeedback","DlpSensitiveInformationType","MipAutoLabelSimulationStatistics","LargeContentMetadata","Microsoft365Group","CDPMlInferencingResult","FilteringMailMetadata","CDPClassificationMailItem","CDPClassificationDocument","OfficeScriptsRunAction","FilteringPostMailDeliveryAction","CDPUnifiedFeedback","TenantAllowBlockList","ConsumptionResource","HealthcareSignal","DlpImportResult","CDPCompliancePolicyExecution","MultiStageDisposition","PrivacyDataMatch","FilteringEntityEvent","FilteringRuleHits","FilteringMailSubmission","LabelExplorer","MicrosoftManagedServicePlatform","PowerPlatformServiceActivity","ScorePlatformGenericAuditRecord","FilteringTimeTravelDocMetadata","Alert","AlertStatus","AlertIncident","IncidentStatus","Case","CaseInvestigation","RecordsManagement","PrivacyRemediation","DataShareOperation","CdpDlpSensitivity","EHRConnector","FilteringMailGradingResult","PublicFolder","PrivacyTenantAuditHistoryRecord","AipScannerDiscoverEvent","EduDataLakeDownloadOperation","M365ComplianceConnector","MicrosoftGraphDataConnectOperation","MicrosoftPurview","FilteringEmailContentFeatures","PowerPagesSite","PowerAppsResource","PlannerPlan","PlannerCopyPlan","PlannerTask","PlannerRoster","PlannerPlanList","PlannerTaskList","PlannerTenantSettings","ProjectForTheWebProject","ProjectForTheWebTask","ProjectForTheWebRoadmap","ProjectForTheWebRoadmapItem","ProjectForTheWebProjectSettings","ProjectForTheWebRoadmapSettings","QuarantineMetadata","MicrosoftTodoAudit","TimeTravelFilteringDocMetadata","TeamsQuarantineMetadata","SharePointAppPermissionOperation","MicrosoftTeamsSensitivityLabelAction","FilteringTeamsMetadata","FilteringTeamsUrlInfo","FilteringTeamsPostDeliveryAction","MDCAssessments","MDCRegulatoryComplianceStandards","MDCRegulatoryComplianceControls","MDCRegulatoryComplianceAssessments","MDCSecurityConnectors","MDADataSecuritySignal","VivaGoals","FilteringRuntimeInfo","AttackSimAdmin","MicrosoftGraphDataConnectConsent","FilteringAtpDetonationInfo","PrivacyPortal","ManagedTenants","UnifiedSimulationMatchedItem","UnifiedSimulationSummary","UpdateQuarantineMetadata","MS365DSuppressionRule","PurviewDataMapOperation","FilteringUrlPostClickAction","IrmUserDefinedDetectionSignal","TeamsUpdates","PlannerRosterSensitivityLabel","MS365DIncident","FilteringDelistingMetadata","ComplianceDLPSharePointClassificationExtended","MicrosoftDefenderForIdentityAudit","SupervisoryReviewDayXInsight","DefenderExpertsforXDRAdmin","CDPEdgeBlockedMessage","HostedRpa"

    $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
    $outputFile = "$($date)-Amount_Of_Audit_Logs.csv"

    $outputDirectory = Join-Path $OutputDir $outputFile

    try {
        $streamWriter = New-Object System.IO.StreamWriter($outputDirectory)
        $streamWriter.WriteLine("RecordType,Amount of log entries")
        $streamWriter.Close()
    }
    catch {
        log -Message "[ERROR] Failed to write to file: $_" -Color "Red"
    }

    log -Message "[INFO] Calculating the number of audit logs for each of the 236 Record Types between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Green"

    foreach ($record in $recordTypes) {
        log -Message "[INFO] Calculating $record logs"
        $specificResult = ExoCommand -Command "Search-UnifiedAuditLog" -cargs "-Userids $UserIds -StartDate $script:StartDate -EndDate $script:EndDate -RecordType $record -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount"
        if ($specificResult) {
            log -Message "$($record):$($specificResult)"
            Write-Output "$record,$specificResult" | Out-File $outputDirectory -Append
        }
        else {
            log -Message "[WARNING] $record has no log entries" -Color "Yellow"
        }
    }

    $totalCount = ExoCommand -Command "Search-UnifiedAuditLog" -cargs "-Userids $UserIds -StartDate $script:StartDate -EndDate $script:EndDate -ResultSize 1 | Select-Object -ExpandProperty ResultCount"
    if ($totalCount) {
        log -Message "--------------------------------------"
        log -Message "Total count:$($totalCount)" -Color "Green"
        log -Message "[INFO] Count complete file is written to $outputFile" -Color "Green"
        Write-Output "Total Count: $totalCount" | Out-File $outputDirectory -Append
    }
    else {
		log -Message "[INFO] No records found for $UserIds"
	}
}

Get-UALGraph(){}
Get-UALGroup(){}
function Get-UALGroup
{
<#
    .SYNOPSIS
    Gets the selected group of unified audit log entries.

    .DESCRIPTION
    Makes it possible to extract a group of specific unified audit data out of a Microsoft 365 environment.
	You can for example extract all Exchange or Azure logging in one go.
	The output will be written to: Output\UnifiedAuditLog\

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today -90 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.PARAMETER Interval
    Interval is the parameter specifying the interval in which the logs are being gathered.
	Default: 1440 minutes

	.PARAMETER Group
    Group is the group of logging needed to be extracted.
	Options are: Exchange, Azure, Sharepoint, Skype and Defender

	.PARAMETER Output
    Output is the parameter specifying the CSV or JSON output type.
	Default: CSV

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UnifiedAuditLog

 	.PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file
    Default: No

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV/JSON output file.
	Default: UTF8

	.EXAMPLE
	Get-UALGroup -Group Azure
	Gets the Azure related unified audit log entries.

	.EXAMPLE
	Get-UALGroup -Group Exchange -UserIds Test@invictus-ir.com
	Gets the Exchange related unified audit log entries for the user Test@invictus-ir.com.

	.EXAMPLE
	Get-UALGroup -Group Exchange -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"
	Gets all the unified audit log entries between 1/4/2023 and 5/4/2023 for the users Test@invictus-ir.com and HR@invictus-ir.com.

	.EXAMPLE
	Get-UALGroup -Group Azure -StartDate 1/4/2023 -EndDate 5/4/2023
	Gets all the Azure related unified audit log entries between 1/4/2023 and 5/4/2023.

	.EXAMPLE
	Get-UALGroup -Group Defender -UserIds Test@invictus-ir.com -Interval 720 -Output JSON
	Gets all the Defender related unified audit log entries for the user Test@invictus-ir.com in JSON format with a time interval of 720.

  	.EXAMPLE
	Get-UALGroup -Group Exchange -MergeOutput
	Gets the Azure related unified audit log entries and adds a combined output csv file at the end of acquisition
#>
	[CmdletBinding()]
	param(
		[string]$StartDate,
		[string]$EndDate,
		[string]$UserIds,
		[string]$Interval,
		[string]$Group,
		[string]$Output,
  		[string]$MergeOutput,
		[string]$OutputDir,
		[string]$Encoding
	)

	if ($Group -eq "Exchange") {
        $Exchange=[PSCustomObject]@{
            [array]$recordTypes = @("ExchangeAdmin","ExchangeAggregatedOperation","ExchangeItem","ExchangeItemGroup","ExchangeItemAggregated","ComplianceDLPExchange","ComplianceSupervisionExchange","MipAutoLabelExchangeItem")
            [string]$recordFile = "Exchange"
            }
	}
	elseif ($Group -eq "Azure") {
        $Azure=[PSCustomObject]@{
            [arr]$recordTypes = "AzureActiveDirectory","AzureActiveDirectoryAccountLogon","AzureActiveDirectoryStsLogon"]
            [string]$recordFile = "Azure"
	}
	elseif ($Group -eq "Sharepoint") {
        $Sharepoint=[PSCustomObject]@{
            [arr]$recordTypes = "ComplianceDLPSharePoint","SharePoint","SharePointFileOperation","SharePointSharingOperation","SharepointListOperation", "ComplianceDLPSharePointClassification","SharePointCommentOperation", "SharePointListItemOperation", "SharePointContentTypeOperation", "SharePointFieldOperation","MipAutoLabelSharePointItem","MipAutoLabelSharePointPolicyLocation"
		    [string]$recordFile = "Sharepoint"
            }
		
	}
	elseif ($Group -eq "Skype") {
        $Skype=[PSCustomObject]@{
           [arr]$recordTypes = "SkypeForBusinessCmdlets","SkypeForBusinessPSTNUsage","SkypeForBusinessUsersBlocked"
		    [string]$recordFile = "Skype"
            }
		
	}
	elseif ($Group -eq "Defender") {
        $Defender=[PSCustomObject]@{
            [arr]$recordTypes = "ThreatIntelligence", "ThreatFinder","ThreatIntelligenceUrl","ThreatIntelligenceAtpContent","Campaign","AirInvestigation","WDATPAlerts","AirManualInvestigation","AirAdminActionInvestigation","MSTIC","MCASAlerts"
            [string]$recordFile = "Defender"
            }
	}
	else {
		log -Message "[WARNING] Invalid input. Select Exchange, Azure, Sharepoint, Defender or Skype" -Color red
	}

	log -Message "[INFO] Running Get-UALGroup" -Color "Green"

    # Assertions.
    if([string]::IsNullOrwhiteSpace($StartDate)) {$StartDate = [DateTime]::Today.AddDays(-90)};
    if([string]::IsNullOrwhiteSpace($EndDate)) {$EndDate = [DateTime]::Now};
    if([string]::IsNullOrwhiteSpace($Group)) {$Group = "Exchange"};
    if([string]::IsNullOrwhiteSpace($UserIds)) {$UserIds = "*"};
    if([string]::IsNullOrwhiteSpace($Interval)) {$Interval = 1440};
    if([string]::IsNullOrwhiteSpace($Output)) {$Output = "JSON"};
	if([string]::IsNullOrwhiteSpace($Encoding)) {$Encoding = "UTF8"};
    if([string]::IsNullOrwhiteSpace($OutputDir)) {$OutputDir = "Output\UnifiedAuditLog"};
    if([string]::IsNullOrwhiteSpace($MergeOutput)) {$MergeOutput = $false};

	log -Message "[INFO] Extracting all available audit logs between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
	log -Message "[INFO] The following RecordType(s) are configured to be extracted:"

	foreach ($record in $recordTypes) {
		log -Message "-$record"
	}

	foreach ($record in $recordTypes) {
		$resetInterval = $interval
		[DateTime]$currentStart = $script:StartDate
		[DateTime]$currentEnd = $script:EndDate

		$specificResult = ExoCommand -Command Search-UnifiedAuditLog -cargs "-StartDate $script:StartDate -EndDate $script:EndDate -RecordType $record -UserIds $UserIds -ResultSize 1 |  Format-List -Property ResultCount| out-string -Stream | select-string ResultCount"

		if (($null -ne $specificResult) -and ($specificResult -ne 0)) {
			$number = $specificResult.tostring().split(":")[1]
			log -Message "[INFO]$($number) Records found for $record" -Color "Green"

			while ($currentStart -lt $script:EndDate) {
				$currentEnd = $currentStart.AddMinutes($Interval)
				$amountResults = ExoCommand -Command "Search-UnifiedAuditLog" -Cargs " -UserIds $UserIds -StartDate $currentStart -EndDate $currentEnd -RecordType $record -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount"

				if ($null -eq $amountResults) {
					log -Message "[INFO] No audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")). Moving on!"
					$CurrentStart = $CurrentEnd
				}

				elseif ($amountResults -gt 5000) {
					while ($amountResults -gt 5000) {
						$amountResults = ExoCommand -Command "Search-UnifiedAuditLog" -Cargs "-StartDate $currentStart -EndDate $currentEnd -UserIds $UserIds -RecordType $record -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount"
						if ($amountResults -lt 5000) {
							if ($Interval -eq 0) {
								Exit
							}
						}

						else {
							log -Message "[WARNING] $amountResults entries between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) exceeding the maximum of 5000 of entries" -Color "Red"
							$interval = [math]::Round(($Interval/(($amountResults/5000)*1.25)),2)
							$currentEnd = $currentStart.AddMinutes($Interval)
							log -Message "[INFO] Temporary lowering time interval to $Interval minutes" -Color "Yellow"
						}
					}
				}

				else {
					$Interval = $ResetInterval


					if ($currentEnd -gt $script:EndDate) {
						$currentEnd = $script:EndDate
					}

					$CurrentTries = 0
					$SessionID = $currentStart.ToString("yyyyMMddHHmmss")

					while ($true) {
						[Array]$results = ExoCommand -Command "Search-UnifiedAuditLog" -Cargs " -StartDate $currentStart -EndDate $currentEnd -UserIds $UserIds -RecordType $record -SessionCommand ReturnLargeSet -ResultSize $ResultSize"
						$currentCount = 0

						if ($null -eq $results -or $results.Count -eq 0) {
							if ($currentTries -lt $retryCount) {
								log -Message "[WARNING] The download encountered an issue and there might be incomplete data" -Color "Red"
								log -Message "[INFO] Sleeping 10 seconds before we try again" -Color "Red"
								Start-Sleep -Seconds 10
								$currentTries = $currentTries + 1
								continue
							}

							else{
								log -Message "[WARNING] Empty data set returned between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")). Retry count reached. Moving forward!"
								break
							}
						}

						else {
							$currentTotal = $results[0].ResultCount
							$currentCount = $currentCount + $results.Count
							log -Message "[INFO] Found $currentTotal audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Green"

							if ($currentTotal -eq $results[$results.Count - 1].ResultIndex){
								$message = "[INFO] Successfully retrieved $($currentCount) records out of total $($currentTotal) for the current time range. Moving on!"

								if ($Output -eq "JSON")
								{
									$results = $results|Select-Object AuditData -ExpandProperty AuditData
									$results | Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding $Encoding
									log -Message $message
								}
								elseif ($Output -eq "CSV")
								{
									$results | export-CSV "$OutputDir/UAL-$sessionID.csv" -NoTypeInformation -Append -Encoding $Encoding
									log -Message $message
								}
								break
							}
						}
					}
				}

				$currentStart = $currentEnd
			}
		}
		else {
			log -message "[INFO] No Records found for $Record"
		}
	}
	if ($Output -eq "CSV" -and ($MergeOutput.IsPresent))
  	{
		log -Message "[INFO] Merging output files into one file"
		$outputDirMerged = "$OutputDir\Merged\"
		If (!(test-path $outputDirMerged)) {
			log -Message "[INFO] Creating the following directory: $outputDirMerged"
			New-Item -ItemType Directory -Force -Path $outputDirMerged | Out-Null
		}

 		Get-ChildItem $OutputDir -Filter *.csv | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$outputDirMerged/UAL-Combined.csv" -NoTypeInformation -Append
    }

	log -Message "[INFO] Acquisition complete, check the Output directory for your files.." -Color "Green"
}

function Get-UALSpecific
{
<#
    .SYNOPSIS
    Gets specific record types of unified audit log.

    .DESCRIPTION
    Makes it possible to extract a group of specific unified audit data out of a Microsoft 365 environment.
	You can for example extract all Exchange or Azure logging in one go.
	The output will be written to: Output\UnifiedAuditLog\

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today -90 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.PARAMETER Interval
    Interval is the parameter specifying the interval in which the logs are being gathered.
	Default: 1440 minutes

	.PARAMETER RecordType
    The RecordType parameter filters the log entries by record type.
	Options are: ExchangeItem, ExchangeAdmin, etc. A total of 236 RecordTypes are supported.

	.PARAMETER Output
    Output is the parameter specifying the CSV or JSON output type.
	Default: CSV

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UnifiedAuditLog

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV/JSON output file.
	Default: UTF8

  	.PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge CSV outputs to a single file
    Default: No

	.EXAMPLE
	Get-UALSpecific -RecordType ExchangeItem
	Gets the ExchangeItem logging from the unified audit log.

	.EXAMPLE
	Get-UALSpecific -RecordType MipAutoLabelExchangeItem -UserIds Test@invictus-ir.com
	Gets the MipAutoLabelExchangeItem logging from the unified audit log for the user Test@invictus-ir.com.

	.EXAMPLE
	Get-UALSpecific -RecordType PrivacyInsights -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"
	Gets the PrivacyInsights logging from the unified audit log for the uses Test@invictus-ir.com and HR@invictus-ir.com.

	.EXAMPLE
	Get-UALSpecific -RecordType ExchangeAdmin -StartDate 1/4/2023 -EndDate 5/4/2023
	Gets the ExchangeAdmin logging from the unified audit log entries between 1/4/2023 and 5/4/2023.

	.EXAMPLE
	Get-UALSpecific -RecordType MicrosoftFlow -UserIds Test@invictus-ir.com -StartDate 25/3/2023 -EndDate 5/4/2023 -Interval 720 -Output JSON
	Gets all the MicrosoftFlow logging from the unified audit log for the user Test@invictus-ir.com in JSON format with a time interval of 720.

  	.EXAMPLE
	Get-UALSpecific -RecordType MipAutoLabelExchangeItem -MergeOutput
	Gets the ExchangeItem logging from the unified audit log and adds a combined output csv file at the end of acquisition
#>
	[CmdletBinding()]
	param(
		[string]$StartDate,
		[string]$EndDate,
		[string]$UserIds,
		[string]$Interval,
		[Parameter(Mandatory=$true)]$RecordType,
		[string]$Output,
  		[string]$MergeOutput,
  		[string]$OutputDir,
		[string]$Encoding
	)

	Assert-Connection -Cmdlet Get-AdminAuditLogConfig

	log -Message "[INFO] Running Get-UALSpecific" -Color "Green"

	StartDate
	EndDate

	if ($UserIds -eq "")
	{
		$UserIds = "*"
	}

	if ($interval -eq "")
	{
		$Interval = 1440
		log -Message "[INFO] Setting the Interval to the default value of 1440"
	}

	if ($Output -eq "JSON")
	{
		$Output = "JSON"
		log -Message "[INFO] Output set to JSON"
	}
	else {
		$Output = "CSV"
		log -Message "[INFO] Output set to CSV"
	}

	if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}

	log -Message "[INFO] Extracting all available audit logs between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
	log -Message "[INFO] The following RecordType(s) are configured to be extracted:"

	foreach ($record in $recordType) {
		log -Message "-$record"
	}

	foreach ($record in $recordType) {

		$resetInterval = $Interval
		[DateTime]$currentStart = $script:StartDate
		[DateTime]$currentEnd = $script:EndDate

		$specificResult = ExoCommand -Command "Search-UnifiedAuditLog" -Cargs " -StartDate $script:StartDate -EndDate $script:EndDate -RecordType $record -UserIds $UserIds -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount

		if (($null -ne $specificResult) -and ($specificResult -ne 0)) {
			if ($OutputDir -eq "" ){
				$OutputDir = "Output\UnifiedAuditLog\$record"
				if (!(test-path $OutputDir)) {
					log -Message "[INFO] Creating the following output directory: $OutputDir"
					New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
				}
			}

			else {
				if (Test-Path -Path $OutputDir) {
					log -Message "[INFO] Custom directory set to: $OutputDir"
				}

				else {
					write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
					log -Message "[Error] Custom directory invalid: $OutputDir exiting script"
				}
			}

			$number = $specificResult.tostring().split(":")[1]
			log -Message "[INFO]$($number) Records found for $record" -Color "Green"

			while ($currentStart -lt $script:EndDate) {
				$currentEnd = $currentStart.AddMinutes($Interval)
				$amountResults = ExoCommand -Command "Search-UnifiedAuditLog" -Cargs " -UserIds $UserIds -StartDate $currentStart -EndDate $currentEnd -RecordType $record -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount


				if ($null -eq $amountResults) {
					log -Message "[INFO] No audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")). Moving on!"
					$CurrentStart = $CurrentEnd
				}

				elseif ($amountResults -gt 5000) {
					while ($amountResults -gt 5000) {
						$amountResults = ExoCommand -Command "Search-UnifiedAuditLog" -Cargs " -StartDate $currentStart -EndDate $currentEnd -UserIds $UserIds -RecordType $record -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
						if ($amountResults -lt 5000) {
							if ($Interval -eq 0) {
								Exit
							}
						}

						else {
							log -Message "[WARNING] $amountResults entries between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) exceeding the maximum of 5000 of entries" -Color "Red"
							$interval = [math]::Round(($Interval/(($amountResults/5000)*1.25)),2)
							$currentEnd = $currentStart.AddMinutes($Interval)
							log -Message "[INFO] Temporary lowering time interval to $Interval minutes" -Color "Yellow"
						}
					}
				}

				else {
					$Interval = $ResetInterval

					if ($currentEnd -gt $script:endDate) {
						$currentEnd = $script:endDate
					}

					$currentTries = 0
					$sessionID = $currentStart.ToString("yyyyMMddHHmmss")

					while ($true) {
						[Array]$results = ExoCommand -Command "Search-UnifiedAuditLog" -Cargs " -StartDate $currentStart -EndDate $currentEnd -UserIds $UserIds -RecordType $record -SessionCommand ReturnLargeSet -ResultSize $ResultSize
						$CurrentCount = 0

						if ($null -eq $results -or $results.Count -eq 0) {
							if ($currentTries -lt $retryCount) {
								$currentTries = $currentTries + 1
								continue
							}
							else {
								log -Message "[INFO] No audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
								break
							}
						}

						$currentTotal = $results[0].ResultCount
						$currentCount = $currentCount + $results.Count
						log -Message "[INFO] Found $currentTotal audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Green"

						if ($currentTotal -eq $results[$results.Count - 1].ResultIndex) {
							$message = "[INFO] Successfully retrieved $($currentCount) records out of total $($currentTotal) for the current time range. Moving on!"

							if ($Output -eq "JSON")
							{
								$results = $results|Select-Object AuditData -ExpandProperty AuditData
								$results | Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding $Encoding
								log -Message $message
							}
							elseif ($Output -eq "CSV")
							{
								$results | export-CSV "$OutputDir/UAL-$sessionID.csv" -NoTypeInformation -Append -Encoding $Encoding
								log -Message $message
							}
							break
						}
					}
				}

				$currentStart = $currentEnd
			}
		}
		else {
			log -Message "[INFO] No Records found for $record"
		}
	}

	if ($Output -eq "CSV" -and ($MergeOutput.IsPresent))
	{
	log -Message "[INFO] Merging output files into one file"
	  $outputDirMerged = "$OutputDir\Merged\"
	  write-host $outputDirMerged
	  If (!(test-path $outputDirMerged)) {
		  log -Message "[INFO] Creating the following directory: $outputDirMerged"
		  New-Item -ItemType Directory -Force -Path $outputDirMerged | Out-Null
	  }

	    Get-ChildItem $OutputDir -Filter *.csv | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$outputDirMerged/UAL-Combined.csv" -NoTypeInformation -Append
	  }

	log -Message "[INFO] Acquisition complete, check the Output directory for your files.." -Color "Green"
}

function Get-UALSpecificActivity
{
<#
    .SYNOPSIS
    Gets specific activities from the unified audit log.

    .DESCRIPTION
    Makes it possible to extract a group of specific unified audit activities out of a Microsoft 365 environment.
	You can for example extract all Inbox Rules or Azure Changes in one go.
	The output will be written to: Output\UnifiedAuditLog\

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
	Default: Today -90 days

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
	Default: Now

	.PARAMETER Interval
    Interval is the parameter specifying the interval in which the logs are being gathered.
	Default: 1440 minutes

 	.PARAMETER ActivityType
    The ActivityType parameter filters the log entries by operation or activity type.
	Options are: New-MailboxRule, MailItemsAccessed, etc. A total of 108 common ActivityTypes are supported.

	.PARAMETER Output
    Output is the parameter specifying the CSV or JSON output type.
	Default: CSV

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UnifiedAuditLog

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV/JSON output file.
	Default: UTF8

	.EXAMPLE
	Get-UALSpecificActivity -ActivityType New-InboxRule
	Gets the New-InboxRule logging from the unified audit log.

	.EXAMPLE
	Get-UALSpecificActivity -ActivityType FileDownloaded -UserIds Test@invictus-ir.com
	Gets the Sharepoint FileDownload logging from the unified audit log for the user Test@invictus-ir.com.

	.EXAMPLE
	Get-UALSpecificActivity -ActivityType Add service principal. -UserIds "Test@invictus-ir.com,HR@invictus-ir.com"
	Gets the Add Service Principal. logging from the unified audit log for the uses Test@invictus-ir.com and HR@invictus-ir.com.

	.EXAMPLE
	Get-UALSpecificActivity -ActivityType MailItemsAccessed -StartDate 1/4/2023 -EndDate 5/4/2023
	Gets the MailItemsAccessed logging from the unified audit log entries between 1/4/2023 and 5/4/2023.

	.EXAMPLE
	Get-UALSpecificActivity -ActivityType MailItemsAccessed -UserIds Test@invictus-ir.com -StartDate 25/3/2023 -EndDate 5/4/2023 -Interval 720 -Output JSON
	Gets all the MailItemsAccessed logging from the unified audit log for the user Test@invictus-ir.com in JSON format with a time interval of 720.
#>
	[CmdletBinding()]
	param(
		[string]$StartDate,
		[string]$EndDate,
		[string]$UserIds,
		[string]$Interval,
		[Parameter(Mandatory=$true)]$ActivityType,
		[string]$Output,
		[string]$OutputDir,
		[string]$Encoding
	)

	Assert-Connection -Cmdlet Get-AdminAuditLogConfig

	log -Message "[INFO] Running Get-UALSpecificActivity" -Color "Green"

	StartDate
	EndDate

	Assert-UserIds
	Assert-Interval -Interval 1440
	Assert-Encoding


	if ($Output -eq "JSON")
	{
		$Output = "JSON"
		log -Message "[INFO] Output set to JSON"
	}
	else
	{
		$Output = "CSV"
		log -Message "[INFO] Output set to CSV"
	}

	log -Message "[INFO] Extracting all available audit logs between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
	log -Message "[INFO] The following ActivityType(s) are configured to be extracted:"

	foreach ($record in $ActivityType) {
		log -Message "-$record"
	}

	foreach ($record in $ActivityType) {

		$resetInterval = $Interval
		[DateTime]$currentStart = $script:StartDate
		[DateTime]$currentEnd = $script:EndDate

		$specificResult = ExoCommand -Command "Search-UnifiedAuditLog" -Cargs " -StartDate $script:StartDate -EndDate $script:EndDate -Operations $record -UserIds $UserIds -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount

		if (($null -ne $specificResult) -and ($specificResult -ne 0)) {
			if ($OutputDir -eq "" ){
				$OutputDir = "Output\UnifiedAuditLog\$record\"
				if (!(test-path $OutputDir)) {
					log -Message "[INFO] Creating the following output directory: $OutputDir"
					New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
				}
			}

			else {
				if (Test-Path -Path $OutputDir) {
					log -Message "[INFO] Custom directory set to: $OutputDir"
				}

				else {
					write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
					log -Message "[Error] Custom directory invalid: $OutputDir exiting script"
				}
			}

			$number = $specificResult.tostring().split(":")[1]
			log -Message "[INFO]$($number) Records found for $record" -Color "Green"

			while ($currentStart -lt $script:EndDate) {
				$currentEnd = $currentStart.AddMinutes($Interval)
				$amountResults = ExoCommand -Command "Search-UnifiedAuditLog" -Cargs " -UserIds $UserIds -StartDate $currentStart -EndDate $currentEnd -Operations $record -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount


				if ($null -eq $amountResults) {
					log -Message "[INFO] No audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")). Moving on!"
					$CurrentStart = $CurrentEnd
				}

				elseif ($amountResults -gt 5000) {
					while ($amountResults -gt 5000) {
						$amountResults = ExoCommand -Command "Search-UnifiedAuditLog" -Cargs " -StartDate $currentStart -EndDate $currentEnd -UserIds $UserIds -Operations $record -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
						if ($amountResults -lt 5000) {
							if ($Interval -eq 0) {
								Exit
							}
						}

						else {
							log -Message "[WARNING] $amountResults entries between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) exceeding the maximum of 5000 of entries" -Color "Red"
							$interval = [math]::Round(($Interval/(($amountResults/5000)*1.25)),2)
							$currentEnd = $currentStart.AddMinutes($Interval)
							log -Message "[INFO] Temporary lowering time interval to $Interval minutes" -Color "Yellow"
						}
					}
				}

				else {
					$Interval = $ResetInterval

					if ($currentEnd -gt $script:endDate) {
						$currentEnd = $script:endDate
					}

					$currentTries = 0
					$sessionID = $currentStart.ToString("yyyyMMddHHmmss")

					while ($true) {
						[Array]$results = ExoCommand -Command "Search-UnifiedAuditLog" -Cargs " -StartDate $currentStart -EndDate $currentEnd -UserIds $UserIds -Operations $record -SessionCommand ReturnLargeSet -ResultSize $ResultSize
						$CurrentCount = 0

						if ($null -eq $results -or $results.Count -eq 0) {
							if ($currentTries -lt $retryCount) {
								$currentTries = $currentTries + 1
								continue
							}
							else {
								log -Message "[INFO] No audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))"
								break
							}
						}

						$currentTotal = $results[0].ResultCount
						$currentCount = $currentCount + $results.Count
						log -Message "[INFO] Found $currentTotal audit logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Green"

						if ($currentTotal -eq $results[$results.Count - 1].ResultIndex) {
							$message = "[INFO] Successfully retrieved $($currentCount) records out of total $($currentTotal) for the current time range. Moving on!"

							if ($Output -eq "JSON")
							{
								$results = $results | Select-Object AuditData -ExpandProperty AuditData
								$results | Out-File -Append "$OutputDir/UAL-$sessionID.json" -Encoding $Encoding
								log -Message $message
							}
							elseif ($Output -eq "CSV")
							{
								$results | export-CSV "$OutputDir/UAL-$sessionID.csv" -NoTypeInformation -Append -Encoding $Encoding
								log -Message $message
							}
							break
						}
					}
				}

				$currentStart = $currentEnd
			}
		}
		else {
			log -Message "[INFO] No Records found for $record"
		}
	}
	log -Message "[INFO] Acquisition complete, check the Output directory for your files.." -Color "Green"
}