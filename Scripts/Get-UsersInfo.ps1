using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Get-Users {
<#
    .SYNOPSIS
    Retrieves the creation time and date of the last password change for all users.
    Script inspired by: https://github.com/tomwechsler/Microsoft_Graph/blob/main/Entra_ID/Create_time_last_password.ps1

    .DESCRIPTION
    Retrieves the creation time and date of the last password change for all users.
    The output will be written to: Output\UserInfo\

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\UserInfo

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER Application
    Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    Default: Delegated access (access on behalf a user)

    .EXAMPLE
    Get-Users
    Retrieves the creation time and date of the last password change for all users.

    .EXAMPLE
    Get-Users -Application
    Retrieves the creation time and date of the last password change for all users via application authentication.

    .EXAMPLE
    Get-Users -Encoding utf32
    Retrieves the creation time and date of the last password change for all users and exports the output to a CSV file with UTF-32 encoding.

    .EXAMPLE
    Get-Users -OutputDir C:\Windows\Temp
    Retrieves the creation time and date of the last password change for all users and saves the output to the C:\Windows\Temp folder.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding,
        [switch]$Application
    )

    #Assertions -Application -Encoding, -OutputDir -filename "UserInfo"

    Write-logFile -Message "[INFO] Running Get-Users" -Color "Green"

    $selectobjects = "Id","AccountEnabled","DisplayName","UserPrincipalName","Mail","CreatedDateTime","LastPasswordChangeDateTime","DeletedDateTime","JobTitle","Department","OfficeLocation","City","State","Country"

    $mgUsers = Get-MgUser -All -Select $selectobjects
    [console]::writeline( "A total of $($mgUsers.count) users found:")

    $dates = @((Get-Date).AddDays(-7), (Get-Date).AddDays(-30), (Get-Date).AddDays(-90), (Get-Date).AddDays(-180), (Get-Date).AddDays(-360))
    $mgUsers | ForEach-Object {
        for ($i = 0; $i -lt $dates.count; $i++) {
            if ($_.CreatedDateTime -gt $dates[$i]) {
                $counts[$i] += 1
                break
            }
        }
    }
    for ($i = 0; $i -lt $dates.count; $i++) {
        [console]::writeline("  - $($counts[$i]) users created within the last $($dates[$i].Days) days.")
    }

    Get-MgUser | Get-Member | out-null

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = "$OutputDir"

    $mgUsers | select-object $selectobjects | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding

    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
}

Function Get-AdminUsers {
<#
    .SYNOPSIS
    Retrieves all Administrator directory roles.

    .DESCRIPTION
    Retrieves Administrator directory roles, including the identification of users associated with each specific role.
	The output will be written to: Output\UserInfo\

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\UserInfo

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8

    .PARAMETER Application
    Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    Default: Delegated access (access on behalf a user)

    .EXAMPLE
    Get-AdminUsers
	Retrieves Administrator directory roles, including the identification of users associated with each specific role.

    .EXAMPLE
    Get-AdminUsers -Application
    Retrieves Administrator directory roles, including the identification of users associated with each specific role via application authentication.

	.EXAMPLE
	Get-AdminUsers -Encoding utf32
	Retrieves Administrator directory roles, including the identification of users associated with each specific role and exports the output to a CSV file with UTF-32 encoding.

	.EXAMPLE
	Get-AdminUsers -OutputDir C:\Windows\Temp
	Retrieves Administrator directory roles, including the identification of users associated with each specific role and saves the output to the C:\Windows\Temp folder.
#>

    [CmdletBinding()]
    param(
        [string]$outputDir,
        [string]$Encoding,
        [switch]$Application
    )

    Assertion -Application -Encoding -OutputDir "$OutputDir\$($date)-$roleName.csv"

    Write-logFile -Message "[INFO] Running Get-AdminUsers" -Color "Green"

    $getRoles = Get-MgDirectoryRole -all
    foreach ($role in $getRoles) {
        $roleId = $role.Id
        $roleName = $role.DisplayName

        if ($roleName -like "*Admin*") {
            $areThereUsers = Get-MgDirectoryRoleMember -DirectoryRoleId $roleId

            if ($null -eq $areThereUsers) {
                [console]::writeline("[INFO] $roleName - No users found")
            }

            else {
                $results=@();

                $myObject = [PSCustomObject]@{
                    UserName          = "-"
                    UserId            = "_"
                    Role              = "-"
                }

                $count = 0
                $areThereUsers | ForEach-Object {

                    $userid = $_.Id

                    if ($userid -eq ".") {
                        [console]::writeline(".")
                    }

                    else {
                        $count = $count +1
                        try{
                            $getUserName = Get-MgUser -Filter ("Id eq '$userid'")
                            $userName = $getUserName.UserPrincipalName

                            $myObject.UserName = $userName
                            $myObject.UserId = $userid
                            $myObject.Role = $roleName

                            $results+= $myObject;
                        }
                        catch{
                            Write-logFile -Message "[INFO] Resource $userid does not exist or one of its queried reference-property objects are not present." -Color "Yellow"
                        }
                    }
                }

                Write-logFile -Message "[info] $roleName - $count users found" -Color "Yellow"
                $filePath = "$OutputDir\$($date)-$roleName.csv"
                $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
                Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
            }
        }
    }

    $outputDirMerged = "$OutputDir\Merged\"
    If (!(test-path $outputDirMerged)) {
        Write-LogFile -Message "[INFO] Creating the following directory: $outputDirMerged"
        New-Item -ItemType Directory -Force -Path $outputDirMerged | Out-Null
    }

    Write-LogFile -Message "[INFO] Merging Administrator CSV Ouput Files" -Color "Green"
    Get-ChildItem $OutputDir -Filter "*Administrator.csv" | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv "$outputDirMerged/All-Administrators.csv" -NoTypeInformation -Append
}
