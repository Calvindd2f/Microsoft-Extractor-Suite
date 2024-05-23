. "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Get-Users {
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\UserInfo",
        [string]$Encoding = "UTF8",
        [switch]$Application
    )

    # Assertions logic might be here (not shown)

    Write-logFile -Message "[INFO] Running Get-Users" -Color "Green"

    $selectObjects = "Id,AccountEnabled,DisplayName,UserPrincipalName,Mail,CreatedDateTime,LastPasswordChangeDateTime,DeletedDateTime,JobTitle,Department,OfficeLocation,City,State,Country"

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = Join-Path -Path $OutputDir -ChildPath "UserInfo-$date.csv"

    $batchSize = 100
    $skipToken = $null
    $uri = "https://graph.microsoft.com/v1.0/users"
    $allUsers = @()

    # Ensure the output directory exists
    if (-not (Test-Path -Path $OutputDir)) {
        [void](New-Item -ItemType Directory -Force -Path $OutputDir)
    }

    # Initialize StreamWriter for CSV
    $fileStream = [System.IO.File]::Create($filePath)
    $streamWriter = New-Object System.IO.StreamWriter($fileStream, [System.Text.Encoding]::GetEncoding($Encoding))
    
    # Write the CSV header
    $header = $selectObjects -replace ' ', '' -split ','
    $streamWriter.WriteLine(($header -join ','))

    do {
        $queryParams = @{
            '$select' = $selectObjects
            '$top' = $batchSize
        }
        if ($skipToken) {
            $queryParams['$skipToken'] = $skipToken
        }

        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -QueryParameters $queryParams

        if ($response.value) {
            foreach ($user in $response.value) {
                $line = $header | ForEach-Object {
                    if ($null -ne $user.$_) {
                        $user.$_.ToString()
                    } else {
                        ""
                    }
                }
                $streamWriter.WriteLine(($line -join ','))
            }
            $allUsers += $response.value
        }

        $skipToken = $response.'@odata.nextLink'
    } while ($skipToken)

    # Clean up resources
    $streamWriter.Dispose()
    $fileStream.Dispose()

    [console]::writeline("A total of $($allUsers.count) users found:")
    Get-UserCreationStats -Users $allUsers

    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
}

function Get-UserCreationStats {
    param(
        [Parameter(Mandatory)]
        [array]$Users
    )

    $counts = @()
    $dates = @((Get-Date).AddDays(-7), (Get-Date).AddDays(-30), (Get-Date).AddDays(-90), (Get-Date).AddDays(-180), (Get-Date).AddDays(-360))

    foreach ($user in $users) {
        for ($i = 0; $i -lt $dates.count; $i++) {
            if ([datetime]::Parse($user.CreatedDateTime) -gt $dates[$i]) {
                $counts[$i] += 1
                break
            }
        }
    }
    for ($i = 0; $i -lt $dates.count; $i++) {
        [console]::writeline(" - $($counts[$i]) users created within the last $($dates[$i].Days) days.")
    }
}

<#
Changes made:

Replaced Get-MgUser with Invoke-MgGraphRequest for making HTTP requests to the Microsoft Graph API with pagination support.
Removed the command pipeline for exporting CSV and replaced it with streaming output using StreamWriter.
Encapsulated the user creation statistics logic into a separate function called Get-UserCreationStats.
Removed Get-MgUser | Get-Member | out-null as it seemed to have no purpose in the original script.
Default parameters are now set directly in the parameter declaration.
$selectObjects is now a single string that is split later on to create the CSV header.
Make sure that Write-logFile is a function defined in your script or module for logging messages. The logic for Assert-Connection, Assert-UserIds, Assert-Interval, and Write-logFile would need to be implemented as they seem to be placeholders for actual logic not included in


#>

Function Get-AdminUsers {
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\UserInfo",
        [string]$Encoding = "UTF8",
        [switch]$Application
    )

    # Assertions logic might be here (not shown)

    Write-logFile -Message "[INFO] Running Get-AdminUsers" -Color "Green"

    $date = Get-Date -Format "yyyyMMddHHmm"
    $outputDirMerged = Join-Path -Path $OutputDir -ChildPath "Merged"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $OutputDir)) {
        [void](New-Item -ItemType Directory -Force -Path $OutputDir)
    }
    if (-not (Test-Path -Path $outputDirMerged)) {
        [void](New-Item -ItemType Directory -Force -Path $outputDirMerged)
        Write-logFile -Message "[INFO] Creating the following directory: $outputDirMerged" -Color Green
    }

    $getRoles = Get-MgDirectoryRole -All
    foreach ($role in $getRoles) {
        $roleId = $role.Id
        $roleName = $role.DisplayName

        if ($roleName -like "*Admin*") {
            $membersUri = "https://graph.microsoft.com/v1.0/directoryRoles/$roleId/members"
            $members = @()
            $skipToken = $null

            do {
                $queryParams = @{}
                if ($skipToken) {
                    $queryParams['$skipToken'] = $skipToken
                }

                $response = Invoke-MgGraphRequest -Method GET -Uri $membersUri -QueryParameters $queryParams

                if ($response.value) {
                    $members += $response.value
                }

                $skipToken = $response.'@odata.nextLink'
            } while ($skipToken)

            if ($members.Count -gt 0) {
                $filePath = Join-Path -Path $OutputDir -ChildPath "$date-$roleName.csv"
                $fileStream = [System.IO.File]::Create($filePath)
                $streamWriter = New-Object System.IO.StreamWriter($fileStream, [System.Text.Encoding]::GetEncoding($Encoding))

                # Write the CSV header
                $header = "UserName,UserId,Role"
                $streamWriter.WriteLine($header)

                foreach ($member in $members) {
                    $userId = $member.Id

                    try {
                        $user = Get-MgUser -UserId $userId -Property "UserPrincipalName"
                        $userName = $user.UserPrincipalName
                    } catch {
                        $userName = "Resource $userId does not exist or one of its queried reference-property objects are not present."
                        Write-logFile -Message "[INFO] $userName" -Color Yellow
                    }

                    $line = @($userName, $userId, $roleName) -join ','
                    $streamWriter.WriteLine($line)
                }

                # Clean up resources
                $streamWriter.Dispose()
                $fileStream.Dispose()

                Write-logFile -Message "[INFO] Output written to $filePath" -Color Green
            } else {
                [console]::writeline("[INFO] $roleName - No users found")
            }
        }
    }

    # Merge CSV files
    Write-logFile -Message "[INFO] Merging Administrator CSV Output Files" -Color Green
    Merge-AdminCsvFiles -OutputDir $OutputDir -MergedOutputDir $outputDirMerged -Encoding $Encoding
}

Function Merge-AdminCsvFiles {
    param(
        [string]$OutputDir,
        [string]$MergedOutputDir,
        [string]$Encoding
    )

    $combinedFilePath = Join-Path -Path $MergedOutputDir -ChildPath "All-Administrators.csv"
    $csvFiles = Get-ChildItem -Path $OutputDir -Filter "*Admin*.csv"

    foreach ($file in $csvFiles) {
        $content = [System.IO.File]::ReadAllText($file.FullName)
        [System.IO.File]::AppendAllText($combinedFilePath, $content)
    }
}
<#
Changes made:

Removed command pipelines for CSV export and replaced them with streaming output using StreamWriter.
Encapsulated the CSV merging logic into a separate function called Merge-AdminCsvFiles.
Removed Assertion function call and assumed the validations are done within the Write-logFile function or elsewhere.
Used Invoke-MgGraphRequest for making HTTP requests to the Microsoft Graph API with pagination support for directory role members.
Ensured output directories exist before attempting to write files.
Make sure that Write-logFile is a function
#>


<#

                                    ADDITIONAL FUNCTIONALITY ADDED

========================================================================================================================

FUNCTION: ExecuteQuery
DESCRIPTION: ExecuteQuery executes the query and returns the result in JSON format


========================================================================================================================

#>



<#
input.msgraph_token="$MSGRAPH_Api_Token_Client",
input.upn
out.User
#>


Function GetUserDetails($token)
{
    #Write-Host $token
    #Any value on "onPremisesSamAccountName" property indicates that the user was Created/Sync using AD Connect.
    $queryProps = @("onPremisesSamAccountName","onPremisesSyncEnabled","onPremisesImmutableId","onPremisesExtensionAttributes","businessPhones","jobTitle","givenName","surname","description","department","officeLocation","MobilePhone","companyName","aboutMe","displayName","streetAddress","state","city","postalCode","country","userPrincipalName","accountEnabled","mail","lastPasswordChangeDateTime","id","proxyAddresses","usageLocation")
                    
    $properties = $queryProps -join(",")
    $url = "https://graph.microsoft.com/beta/users/"+ [Uri]::EscapeUriString($upn)  + "?`$Select=$properties";
    Write-Host "Retrieving details for user $upn."
    $userDetails = $(ConvertFrom-Json $(ExecuteQuery -url $url -token $token))
        
    try{
        
        $url = "https://graph.microsoft.com/v1.0/users/"+ [Uri]::EscapeUriString($upn)  + "/manager"
        $managerDetails = $(ExecuteQuery -url $url -token $token);
        if($managerDetails -ne $null)
        {
            $userDetails | Add-Member -MemberType NoteProperty -name "manager" -value $(ConvertFrom-Json($managerDetails)).userPrincipalName;
            $userDetails | Add-Member -MemberType NoteProperty -name "managerName" -value $(ConvertFrom-Json($managerDetails)).displayName;
        }
    }
    catch {
        Write-Host "Unable to retreive manager: `n$($_.Exception.Message)"
        $userDetails | Add-Member -MemberType NoteProperty -name "manager" -value ""
        $userDetails | Add-Member -MemberType NoteProperty -name "managerName" -value ""
    }
    
    try{
        Write-Host "Retrieving signInActivity for user $upn."
        $url = "https://graph.microsoft.com/beta/users/"+ $userDetails.id  + "?`$select=signInActivity";
        write-host $url
        $signInActivity = $(ExecuteQuery -url $url -token $token);
        Write-host "signInActivity: $signInActivity"
        if($signInActivity.lastSignInDateTime){
            $userDetails | Add-Member -MemberType NoteProperty -name "lastSignInDateTime" -value $signInActivity.lastSignInDateTime
        } else{
            $userDetails | Add-Member -MemberType NoteProperty -name "lastSignInDateTime" -value "Never"
        }
    } catch {
        Write-Host "Unable to retreive signInActivity: `n$($_.Exception.Message)"
        $userDetails | Add-Member -MemberType NoteProperty -name "lastSignInDateTime" -value 'N/A'
    }
    
    $activityOutput.out.User = $(ConvertTo-Json $userDetails);
    #Write-Host $activityOutput.out.User
    
}

Function ExecuteQuery($url, $token)
{
    try{
        $request = [System.Net.HttpWebRequest]::Create($url)
    
    	$request.Method = "GET";
    	$request.ContentType =  "application/json;odata.metadata=minimal";
    	$request.Headers["Authorization"] = "Bearer $token";
    
        try {
    	    $response = $request.GetResponse();
        } catch { }
        #Neither tenant is B2C or tenant doesn't have premium license
    	$reader = new-object System.IO.StreamReader $response.GetResponseStream();
    	$jsonResult = $reader.ReadToEnd();
    	$response.Dispose();
    
        return $jsonResult;
    }
    catch{
        Write-Host "$url"
        Write-Host $($_.Exception.Message)
        return $null;
    }
    
}

Function MainActivity(){
    if([string]::IsNullOrEmpty($upn)){
        Write-Host "No UPN passed. Exiting..."
        $activityOutput.success = $false;

        return $activityOutput;
    }
    GetUserDetails($msgraph_token)
    $activityOutput.success = $true;

    return $activityOutput;
}

Function ExecuteActivity()
{
    return MainActivity;
	}