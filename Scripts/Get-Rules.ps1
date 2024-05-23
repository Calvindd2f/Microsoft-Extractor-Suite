. "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

# This contains functions to display or collect the inbox and transport rules.

$date = Get-Date -Format "yyyyMMddHHmm"
function Show-TransportRules
{
<#    .SYNOPSIS
    Shows the transport rules in your organization.

    .DESCRIPTION
    Shows the transport rules in your organization.

    .Example
    Show-TransportRules
#>
	$transportRules = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/transportRules" -OutputType Microsoft.Open.MSG.Clients.TransportRules.MicrosoftGraph.TrustPolicy

	if ($null -ne $transportRules) {
		
		write-LogFile -Message "[INFO] Checking all TransportRules"
		$transportRules.Value | ForEach-Object {
			[void](write-LogFile -Message "[INFO] Found a TransportRule" -Color "Green")
			[void](write-LogFile -Message "Rule Name $($_.DisplayName)" -Color "Yellow")
			[void](write-LogFile -Message "Rule CreatedBy: $($_.CreatedBy.Application.DisplayName)" -Color "Yellow")
			[void](write-LogFile -Message "When Changed: $($_.CreatedBy.DateTime)" -Color "Yellow")
			[void](write-LogFile -Message "Rule State: $($_.IsEnabled)" -Color "Yellow")
			[void](write-LogFile -Message "Description: $($_.Description)" -Color "Yellow")
		}
	}
}

function Get-TransportRules
{
<#    .SYNOPSIS
    Collects all transport rules in your organization.

    .DESCRIPTION
    Collects all transport rules in your organization.
	The output will be written to a CSV file called "TransportRules.csv".

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\Rules

	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8

    .Example
    Get-TransportRules
#>

	[CmdletBinding()]
	param (
		[string]$OutputDir,
		[string]$Encoding
	)

	if ($OutputDir -eq ""{
		$OutputDir = "Output\Rules"
		if (!(test-path $OutputDir)) {
			[void](New-Item -ItemType Directory -Force -Name $OutputDir)
			write-LogFile -Message "[INFO] Creating the following directory: $OutputDir"
		}
	}

	else{
		if (Test-Path -Path $OutputDir) {
  			write-LogFile -Message "[INFO] Custom directory set to: $OutputDir"
     	}

       	else {
    		write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
    		write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script"
	 	}
   	}

	$filename = "$($date)-TransportRules.csv"
	$outputDirectory = Join-Path $OutputDir $filename

	if ($Encoding -eq ""{
		$Encoding = "UTF8"
	}

	$transportRules = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/transportRules" -OutputType Microsoft.Open.MSG.Clients.TransportRules.MicrosoftGraph.TrustPolicy

	if ($null -ne $transportRules) {
		$streamWriter = [IO.StreamWriter]::Create($outputDirectory, $false, [Text.Utf8Encoding]::new($Encoding, $false, $true))
		try {
			foreach ($transportRule in $transportRules.Value) {
				$streamWriter.WriteLine("Name,$($transportRule.DisplayName),Description,$($transportRule.Description),CreatedBy,$($transportRule.CreatedBy.Application.DisplayName),WhenChanged,$($transportRule.CreatedBy.DateTime),State,$($transportRule.IsEnabled)")
			}
		}
		finally {
			$streamWriter.Dispose()
		}
		write-LogFile -Message "[INFO] Transport rules are collected and writen to: $outputDirectory" -Color "Green"
	}
}


function Get-MailboxRules{
{
<#

    .SYNOPSIS
    Collects all the mailbox rules in your organization.

    .DESCRIPTION
    Collects all the mailbox rules in your organization.
	The output will be written to a CSV file called "InboxRules.csv".

	.Parameter UserIds
    UserIds is the Identity parameter specifies the Inbox rule that you want to view.

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\Rules

	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8

    .Example
	Get-mailboxRules -UserIds Test@Invictus-ir.com
    Get-mailboxRules -UserIds "HR@invictus-ir.com,Test@Invictus-ir.com"
#>
	[CmdletBinding()]
	param(
		[string]$UserIds,
		[string]$OutputDir,
		[string]$Encoding
	)

	$RuleList = @()

	if ($Encoding -eq "") {
		$Encoding = "UTF8"
	}

	if ($OutputDir -eq "") {
		$OutputDir = "Output\Rules"
		if (!(test-path $OutputDir)) {
			write-LogFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -force -Name $OutputDir | Out-Null
		}
	}

	else{
		if (Test-Path -Path $OutputDir) {
			write-LogFile -Message "[INFO] Custom directory set to: $OutputDir"
		}

		else {
			write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script"
			write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
		}
	}

	$filename = "$($date)-MailboxRules.csv"
	$outputDirectory = Join-Path $OutputDir $filename

	$amountofRules = 0
	if ($UserIds -eq "") {
		$totalRules = 0
		Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users?$select=id,mail" | ForEach-Object {
			$user = $_
			$inboxrule = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)/mailboxRules" -OutputType Microsoft.Open.MSG.Clients.MailboxRules.MicrosoftGraph.TrustPolicy
			if ($inboxrule) {
				$amountofRules = 0
				foreach ($rule in $inboxrule.Value) {
					$tempval = [pscustomobject]@{
						UserName = $user.mail
						RuleName = $rule.name
						RuleEnabled = $rule.IsEnabled
						CopytoFolder = $rule.CopyToFolder
						MovetoFolder = $rule.MoveToFolder
						RedirectTo = $rule.RedirectTo
						ForwardTo = $rule.ForwardTo
						TextDescription = $rule.Description
					}

					$RuleList = $tempval
					$amountofRules = $amountofRules + 1
					$totalRules = $totalRules + 1
					$RuleList | export-CSV $outputDirectory -Append -NoTypeInformation -Encoding UTF8
				}

				write-LogFile -Message "[INFO] Found $amountofRules InboxRule(s) for: $($user.mail)..." -Color "Yellow"
				write-LogFile -Message "[INFO] Collecting $amountofRules InboxRule(s) for: $($user.mail)..." -Color "Yellow"
			}
		}

	else {
		if ($UserIds -match ",") {
			$UserIds.Split(",") | ForEach-Object {
				$user = $_

				Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$user" | ForEach-Object {
					$inboxrule = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)/mailboxRules" -OutputType Microsoft.Open.MSG.Clients.MailboxRules.MicrosoftGraph.TrustPolicy
					if ($inboxrule) {
						$amountofRules = 0
						foreach ($rule in $inboxrule.Value) {
							$tempval = [pscustomobject]@{
								UserName = $user
								RuleName = $rule.name
								RuleEnabled = $rule.IsEnabled
								CopytoFolder = $rule.CopyToFolder
								MovetoFolder = $rule.MoveToFolder
								RedirectTo = $rule.RedirectTo
								ForwardTo = $rule.ForwardTo
								TextDescription = $rule.Description
							}

							$RuleList = $tempval
							$amountofRules = $amountofRules + 1
							$totalRules = $totalRules + 1
							$RuleList | export-CSV $outputDirectory -Append -NoTypeInformation -Encoding UTF8
						}

						write-LogFile -Message "[INFO] Found $amountofRules InboxRule(s) for: $user..." -Color "Yellow"
						write-LogFile -Message "[INFO] Collecting $amountofRules InboxRule(s) for: $user..." -Color "Yellow"
					}
				}
			}
		}

		write-LogFile -Message "[INFO] A total of $totalRules InboxRules found!" -Color "Green"
		write-LogFile -Message "[INFO] InboxRules rules are collected and writen to: $outputDirectory" -Color "Green"
	}
}