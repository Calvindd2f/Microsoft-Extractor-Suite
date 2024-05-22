using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Get-ActivityLogs {
	<#_removed for brevity_#>
	[CmdletBinding()]
	param(
		[string]$StartDate,
		[string]$EndDate,
		[string]$SubscriptionID,
		[string]$OutputDir,
		[string]$Encoding
	)

	try {
		$areYouConnected = Get-AzSubscription -ErrorAction Stop -WarningAction SilentlyContinue
	}
	catch {
		Write-LogFile -Message "[WARNING] You must call Connect-AzureAZ before running this script" -Color "Red"
		break
	}

	StartDateAzure
	EndDateAzure


	#Assert-OutputDir # Pull Request # Added the assertion function into the psm1

	$validSubscriptions = @()

	if ($SubscriptionID -eq "") {
		write-logFile -Message "[INFO] Retrieving all subscriptions linked to the logged-in user account" -Color "Green"
		$subScription = Get-AzSubscription

		foreach ($i in $subScription) {
			write-logFile -Message "[INFO] Identified Subscription: $i"
		}
	}

	else {
		$subScription = Get-AzSubscription -SubscriptionId $SubscriptionID
	}

	foreach ($sub in $subScription) {
        try {
            Set-AzContext -Subscription $sub.Id > $null
            $logs = Get-AzActivityLog -StartTime (Get-Date).AddDays(-89) -EndTime (Get-Date) -ErrorAction Stop -WarningAction SilentlyContinue

            if ($logs) {
                $validSubscriptions += $sub
                [console]::writeline("[INFO] Activity logs found in subscription: $($sub.Id)")# -ForegroundColor Green
            }
        }
        catch {
            [console]::writeline("[WARNING] No Activity logs in subscription: $($sub.Id), or an error occurred.")# -ForegroundColor Yellow
        }
    }

	if ($validSubscriptions.Count -eq 0) {
        [console]::writeline("[WARNING] No valid subscriptions with logs found.") # -ForegroundColor Red
        return
    }

	try {

		foreach ($sub in $validSubscriptions) {
			$name = $sub.Name
			$iD = $sub.Id

			write-logFile -Message "[INFO] Retrieving all Activity Logs for $sub" -Color "Green"
			Set-AzContext -Subscription $iD > $null # PR

			write-logFile -Message "[INFO] Connected to Subscription $iD" -Color "Green"
			$date = [datetime]::Now.ToString('yyyyMMddHHmmss')
			$filePath = "$OutputDir\$($date)-$iD-ActivityLog.json"

			[DateTime]$currentStart = $script:StartDate
			[DateTime]$currentEnd = $script:EndDate

			$totalDays = ($currentEnd - $currentStart).TotalDays

			for ($i = 0; $i -lt $totalDays; $i++) {
				$dagCounter = $currentStart.AddDays($i)
				$formattedDate = $dagCounter.ToString("yyyy-MM-dd")

				[DateTime]$start = (Get-Date $formattedDate).Date
				[DateTime]$end = (Get-Date $formattedDate).Date.AddDays(1).AddSeconds(-1)

				$currentStartnew = $start
				$currentEnd = $end

				$amountResults = Get-AzActivityLog -StartTime $start -EndTime $end -MaxRecord 1000 -WarningAction SilentlyContinue
				if ($amountResults.count -gt 0) {
					if ($amountResults.count -gt 1000) {
						while ($currentStartnew -lt $currentEnd) {
							Write-LogFile -Message "[WARNING] $formattedDate - We have exceeded the maximum allowable number of 100 logs, lowering the time interval.." -Color "Red"
							Write-LogFile -Message "[INFO] $formattedDate - Temporary lowering time interval.." -Color "Yellow"

							$tempInterval = 24
							$tempStartDate = $start
							$amountResults = Get-AzActivityLog -StartTime $tempStartDate -EndTime $currentEnd -MaxRecord 1000 -WarningAction SilentlyContinue

							while ($($amountResults.count) -gt 1000) {
								$timeLeft = ($currentEnd - $tempStartDate).TotalHours
								$tempInterval = $timeLeft / 2

								$backup = $tempInterval
								$tempStartDate = $tempStartDate.AddHours($tempInterval)
								$amountResults = Get-AzActivityLog -StartTime $tempStartDate -EndTime $currentEnd -MaxRecord 1000 -WarningAction SilentlyContinue
							}

							$amountResults = Get-AzActivityLog -StartTime $tempStartDate -EndTime $currentEnd -MaxRecord 1000 -WarningAction SilentlyContinue
							Write-LogFile -Message "[INFO] Successfully retrieved $($amountResults.count) Activity logs between $tempStartDate and $currentEnd" -Color "Green"

							$amountResults | Convert-ToJSON -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding

							if ($tempStartDate -eq $currentEnd) {
								$timeLeft = ($currentEnd - $start).TotalHours
								$tempStartDate = $start
							}

							$currentEnd = $tempStartDate
						}
					}

					else {
						Write-LogFile -Message "[INFO] Successfully retrieved $($amountResults.count) Activity logs for $formattedDate. Moving on!" -Color "Green"
<<<<<<< HEAD:Binary/Scripts/Get-AzureActivityLogs.ps1
						Get-AzActivityLog -StartTime $start -EndTime $end -MaxRecord 1000 -WarningAction silentlyContinue | Select-Object @{N='EventTimestamp';E={$_.EventTimestamp.ToString()}},EventName,EventDataId,TenantId,CorrelationId,SubStatus,SubscriptionId,@{N='SubmissionTimestamp';E={$_.SubmissionTimestamp.ToString()}},Status,ResourceType,ResourceProviderName,ResourceId,ResourceGroupName,OperationName,OperationId,Level,Id,Description,Category,Caller,Authorization,Claims,HttpRequest,Properties | ConvertTo-Json -Depth 100	| Out-File -FilePath $filePath -Append -Encoding $Encoding
					}
=======
						Get-AzActivityLog -StartTime $start -EndTime $end -MaxRecord 1000 -WarningAction silentlyContinue | Select-Object @{N='EventTimestamp';E={$_.EventTimestamp.ToString()}},EventName,EventDataId,TenantId,CorrelationId,SubStatus,SubscriptionId,@{N='SubmissionTimestamp';E={$_.SubmissionTimestamp.ToString()}},Status,ResourceType,ResourceProviderName,ResourceId,ResourceGroupName,OperationName,OperationId,Level,Id,Description,Category,Caller,Authorization,Claims,HttpRequest,Properties | ConvertTo-Json -Depth 100| Out-File -FilePath $filePath -Append -Encoding $Encoding
					}					
>>>>>>> 0f6d9cd195d7efc8822eb69c477f1b39aea6f9df:Scripts/Get-AzureActivityLogs.ps1
				}

				else {
					Write-LogFile -Message "[INFO] No Activity Logs found on $formattedDate. Moving on!"
				}
			}

			Write-LogFile -Message "[INFO] Done all logs are collected for $name" -Color "Green"
		}
	}
	catch [System.Management.Automation.ActionPreferenceStopException] {
		write-logFile -Message "[WARNING] $sub contains no or null logs! moving on" -Color "Red"
	}
	catch {
		write-logFile -Message "[ERROR] another error has occured $($error) please check the azure documentaion for further troubleshooting" -Color "Red"
		return
	}

}
function Get-ActivityLogsPaginated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$StartDate,
        [Parameter(Mandatory)]
        [string]$EndDate,
        [Parameter(Mandatory)]
        [string]$OutputDir,
        [Parameter(Mandatory)]
        [string]$Encoding,
        [Parameter(Mandatory)]
        [string]$token
    )
    
    # Ensure the output directory exists
    if (-not (Test-Path -Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
        Write-LogFile -Message "[INFO] Created output directory: $OutputDir" -Color "Green"
    }

    # Get all subscriptions if the user is connected to Azure
    try {
        $subscriptions = (Get-AzSubscription -ErrorAction Stop).Id
    }
    catch {
        Write-LogFile -Message "[WARNING] You must call Connect-AzureAZ before running this script" -Color "Red"
        return
    }

    foreach ($subscriptionId in $subscriptions) {
        # Construct the initial API URL
        $url = "https://management.azure.com/subscriptions/$subscriptionId/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&`$filter=eventTimestamp ge $StartDate and eventTimestamp le $EndDate"

        # Initialize an empty array to hold all results for this subscription
        $allResults = @()
        $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
        $filePath = Join-Path $OutputDir "$($date)-$subscriptionId-ActivityLog.json"

        do {
            # Call the Azure REST API
            $response = Invoke-RestMethod -Headers @{Authorization = "Bearer $token"} -Uri $url -Method Get -ContentType 'application/json'

            # Add the current batch of results to the allResults array
            $allResults += $response.value

            # Write the batch to the file
            $response.value | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding

            # Check if there is a nextLink to follow for more results
            if ($response.'nextLink') {
                $url = $response.'nextLink'
            } else {
                # If there is no nextLink, we have reached the end of the data for this subscription
                $url = $null
            }
        } while ($url)

        Write-LogFile -Message "[INFO] Done collecting logs for subscription $subscriptionId" -Color "Green"
    }
}





#startDateAzure and endDateAzure removed...
# Get-ActivityLogs will be replaced with get-activitylogspaginated after testing commences