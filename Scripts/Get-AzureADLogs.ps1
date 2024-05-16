# This contains functions for getting Azure AD logging

function Get-ADSignInLogs
{
<#
    .SYNOPSIS
    Get sign-in logs.

    .DESCRIPTION
    The Get-ADSignInLogs cmdlet collects the contents of the Azure Active Directory sign-in logs.
	The output will be written to: Output\AzureAD\SignInLogs.json

	.PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
    The Before parameter specifies the date endDate which all logs need to be collected.

	.PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
	Default: Output\AzureAD

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

	.PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge outputs to a single file
    Default: No

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.
    
    .EXAMPLE
    Get-ADSignInLogs
	Get all sign-in logs.

    .EXAMPLE
    Get-ADAuditLogs -UserIds Test@invictus-ir.com
    Get sign-in logs for the user Test@invictus-ir.com.

	.EXAMPLE
    Get-ADSignInLogs -endDate 2023-04-12
	Get sign-in logs before 2023-04-12.

	.EXAMPLE
    Get-ADSignInLogs -startDate 2023-04-12
	Get sign-in logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[datetime]$startDate = (date).AddDays(-30).ToString('yyyy-MM-ddT00:00:00'),
		[datetime]$endDate = [datetime]::Now.ToString('yyyy-MM-ddT00:00:00'),
		[string]$OutputDir = "$((pwd).path)\Output\",
		[string]$UserIds,
		[switch]$MergeOutput,
		[string]$Encoding = 'UTF8',
		[int]$Interval
	)

	Write-logFile -Message "[INFO] Running Get-ADSignInLogs" -Color "Green"

	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	
	if ([string]::IsNullOrWhiteSpace($OutputDir.Split('\')[0])){mkdir -Force "$OutputDir\AzureAD\$date">$null}
	$OutputDir="$OutputDir\AzureAD\$date"

	if ($UserIds)
	{
		Write-LogFile -Message "[INFO] UserID's eq $($UserIds)"
	} 
	else 
	{
		Write-LogFile -Message "[INFO] UserIDs not specificed."
	}
	$filePath = "$OutputDir\SignInLogs.json"
		
	#Get-AzureADAuditSignInLogs -eq 	Get-MgBetaAuditLogSignIn
	$baseUri='https://graph.microsoft.com/v1.0'
	$resourcePath=(Find-MgGraphCommand -Command Get-MgBetaAuditLogSignIn).URI[1]
	$baseUri="$baseUri$resourcePath`?"

	$queryParameters = @();
	if ($StartDate) { $queryParameters += "`$filter=activityDateTime ge $StartDate" }
	if ($EndDate) { $queryParameters += "activityDateTime le $EndDate" }
	if ($UserIds) { $queryParameters += " and initiatedBy/user/id eq $UserIds" }
	$filterQuery = $queryParameters -join ' and '
	$apiUrl = "$baseUri``$filterQuery";
	
	
	try
    {
		Do
        {
			$response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json';
            $logs = $response;
            $date = [datetime]::Now.ToString('yyyy-MM-ddTHH:mm:ss');
            $filePath = "ADSignInLogs.json"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM ;
            Write-Host "[INFO] Sign-in logs written to $filePath" -ForegroundColor Green;
            $baseUri= $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        } While ($response.'@odata.nextLink')
    }
    catch [Exception]
    {
        Write-Error "Error fetching data: $_"
    }
    finally
    {
        # Clean up resources explicitly after the loop
        Remove-Variable response -ErrorAction Ignore
        Remove-Variable logs -ErrorAction Ignore
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }

	if ($MergeOutput)
    {
        try
        {
            Write-Host '[INFO] Merging output files...' -ForegroundColor Green ;
            $mergedFile="ADSignInLog-Combined.json"
            Merge-OutputFiles -OutputDir $OutputDir -Encoding $Encoding -mergedFile $mergedFile
        }
        catch
        {
            Write-Error "Error fetching data: $_" -ForegroundColor Red
        }
        finally
        {
            Write-Host '[INFO] Process completed.' -ForegroundColor Green
        }
    }
}

function Get-ADAuditLogs 
{
<#
    .SYNOPSIS
    Get directory audit logs.

    .DESCRIPTION
    The Get-ADAuditLogs cmdlet collects the contents of the Azure Active Directory Audit logs.
	The output will be written to: "Output\AzureAD\Auditlogs.json

	.PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
    The endDate parameter specifies the date before which all logs need to be collected.

	.PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
	Default: Output\AzureAD

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.
    
    .EXAMPLE
    Get-ADAuditLogs
	Get directory audit logs.

    .EXAMPLE
    Get-ADAuditLogs -UserIds Test@invictus-ir.com
    Get directory audit logs for the user Test@invictus-ir.com.

	.EXAMPLE
    Get-ADAuditLogs -endDate 2023-04-12
	Get directory audit logs before 2023-04-12.

	.EXAMPLE
    Get-ADAuditLogs -startDate 2023-04-12
	Get directory audit logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[datetime]$startDate = (date).AddDays(-30).ToString('yyyy-MM-ddT00:00:00'),
        [datetime]$endDate = [datetime]::Now.ToString('yyyy-MM-ddT00:00:00'), ,
        [string]$OutputDir = "$((pwd).path)\Output\",
        [string]$UserIds,
        [string]$Encoding = 'UTF8'
    )

	$filePath = "$OutputDir\$($date)-Auditlogs.json"
	Write-logFile -Message "[INFO] Collecting the Directory Audit Logs"

	

	#Get-AzureADAuditSignInLogs -eq 	Get-MgBetaAuditLogSignIn
	$baseUri='https://graph.microsoft.com/v1.0'
	$resourcePath=(Find-MgGraphCommand -Command 	Get-MgBetaAuditLogDirectoryAudit).URI[1]
	$baseUri="$baseUri$resourcePath`?"

	$queryParameters = @();
	if ($StartDate) { $queryParameters += "`$filter=activityDateTime ge $StartDate" }
	if ($EndDate) { $queryParameters += "activityDateTime le $EndDate" }
	if ($UserIds) { $queryParameters += " and initiatedBy/user/id eq $UserIds" }
	$filterQuery = $queryParameters -join ' and '
	$apiUrl = "$baseUri``$filterQuery";

	try
    {
        Do
        {
            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json' ;
            $logs = $response;
            $date = [datetime]::Now.ToString('yyyy-MM-ddTHH:mm:ss');
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM ;
            Write-Host "[INFO] Sign-in logs written to $filePath" -ForegroundColor Green;
            $baseUri= $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        } While ($response.'@odata.nextLink')
    }
    catch [Exception]
    {
        Write-Error "Error fetching data: $_"
    }
    finally
    {
        # Clean up resources explicitly after the loop
        Remove-Variable response -ErrorAction Ignore
        Remove-Variable logs -ErrorAction Ignore
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }

	Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
}
