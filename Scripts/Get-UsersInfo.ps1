# Load required functions and modules
. "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

Function Get-Users {
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\UserInfo",
        [string]$Encoding = "UTF8",
        [switch]$Application
    )

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

Function Get-UserCreationStats {
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

Function Get-AdminUsers {
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\UserInfo",
        [string]$Encoding = "UTF8",
        [switch]$Application
    )

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

#Function Get-UserDetails($token)
#{
#    #Placeholder
#}