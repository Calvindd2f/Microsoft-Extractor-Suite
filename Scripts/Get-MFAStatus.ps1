using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Install-GraphModule {
    [CmdletBinding()]
    param()

    $moduleName = "Microsoft.Graph"
    $moduleVersion = "1.0.0"

    if (-not (Get-Module -Name $moduleName -ListAvailable)) {
        Write-LogFile -Message "Installing the Microsoft.Graph module..." -Color Yellow
        Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser
    }

    if (-not (Get-Module -Name $moduleName -ListAvailable)) {
        Write-LogFile -Message "Failed to install the Microsoft.Graph module. Please install it manually and try again." -Color Red
        return $false
    }

    $installedVersion = Get-MgModuleVersion -ModuleName $moduleName

    if ($installedVersion -lt $moduleVersion) {
        Write-LogFile -Message "The required version of the Microsoft.Graph module is not installed. Installing it now..." -Color Yellow
        Uninstall-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
        Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser -RequiredVersion $moduleVersion
    }

    if (-not (Get-Module -Name $moduleName -Name $moduleVersion)) {
        Write-LogFile -Message "Failed to install the required version of the Microsoft.Graph module. Please install it manually and try again." -Color Red
        return $false
    }

    $true
}

function Get-MgModuleVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ModuleName
    )

    $module = Get-Module -Name $ModuleName -ListAvailable

    if ($module) {
        $module.Version
    }
    else {
        $null
    }
}

function Test-MgConnection {
    [CmdletBinding()]
    param()

    $moduleName = "Microsoft.Graph"

    if (-not (Get-Module -Name $moduleName -ListAvailable)) {
        Write-LogFile -Message "The Microsoft.Graph module is not installed. Please install it and try again." -Color Red
        return $false
    }

    $module = Get-Module -Name $moduleName -ListAvailable | Select-Object -First 1

    if (-not $module.ExportedCommands.ContainsKey("Connect-MgGraph")) {
        Write-LogFile -Message "The required Connect-MgGraph cmdlet is not found in the Microsoft.Graph module. Please install the latest version and try again." -Color Red
        return $false
    }

    if (-not (Get-MgSession)) {
        Connect-MgGraph -Scopes @('UserAuthenticationMethod.Read.All', 'User.Read.All') -NoWelcome
    }

    if (-not (Get-MgSession)) {
        Write-LogFile -Message "Failed to connect to Microsoft Graph. Please check your credentials and try again." -Color Red
        return $false
    }

    $true
}

function Write-ErrorLogFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Color = "White"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $messageColor = @{
        Red     = "DarkRed"
        Green   = "Green"
        Yellow  = "Yellow"
        White   = "White"
    }

    $color = $messageColor[$Color]

    $logMessage = "$timestamp [$Color] ERROR: $Message"

    if ($ErrorActionPreference -eq "Stop") {
        Write-Host $logMessage -ForegroundColor Red
    }
    else {
        Write-Host $logMessage -ForegroundColor $color
    }

    Add-Content -Path "$PSScriptRoot\log.txt" -Value $logMessage
}

function Connect-MgGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Scopes,
        [switch]$NoWelcome
    )

    $moduleName = "Microsoft.Graph"

    if (-not (Test-MgConnection)) {
        return
    }

    $module = Import-Module -Name $moduleName -PassThru

    if (-not $module.ExportedCommands.ContainsKey("Connect-MgGraph")) {
        Write-ErrorLogFile -Message "The required Connect-MgGraph cmdlet is not found in the Microsoft.Graph module. Please install the latest version and try again." -Color Red
        return
    }

    Connect-MgGraph -Scopes $Scopes -NoWelcome
}

function Get-MFA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputDir = "Output\UserInfo",
        [Parameter(Mandatory=$false)]
        [string]$Encoding = "UTF8",
        [Parameter(Mandatory=$false)]
        [switch]$Application
    )

    param validation

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    $scopes = @('UserAuthenticationMethod.Read.All', 'User.Read.All')

    if (-not (Test-MgConnection)) {
        Connect-MgGraph -Scopes $scopes -NoWelcome
    }

    if (-not $Application.IsPresent) {
        try {
            $session = Get-MgSession
            if (-not $session.AccessToken) {
                Connect-MgGraph -Scopes $scopes -NoWelcome
            }
        }
        catch {
            Write-ErrorLogFile -Message "You must call Connect-MgGraph -Scopes '$($scopes -join ',')' before running this script" -Color "Red"
            return
        }
    }

    $mfaStatus = Get-MFAStatus -UserPrincipalNames (Get-MgUser -All).UserPrincipalName
    $mfaMethods = Get-MFAMethods -UserPrincipalNames (Get-MgUser -All).UserPrincipalName

    $results = Process-UserResults -MFAStatus $mfaStatus -MFAMethods $mfaMethods

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = Get-MFAOutputPath -Date $date -Encoding $Encoding

    Write-ResultsToCSV -Results $results -FilePath $filePath

    Write-LogFile -Message "Output written to $filePath" -Color "Green"

    $mfaStatusCount = ($results | Where-Object { $_.MFAStatus -eq "Enabled" }).Count
    Write-Host "$mfaStatusCount out of $($results.Count) users have MFA enabled:"
    $mfaMethods | ForEach-Object {
        Write-Host "  - $($_.Count) x $_"
    }
}

function Get-MFAStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$UserPrincipalNames
    )

    $results = @()

    foreach ($userPrincipalName in $UserPrincipalNames) {
        try {
            $mfaStatus = (Get-MgUser -UserId $userPrincipalName).AuthenticationMethodsStatus

            if ($mfaStatus -eq "mfaEnabled") {
                $mfaStatus = "Enabled"
            }
            else {
                $mfaStatus = "Disabled"
            }

            $results += [PSCustomObject]@{
                UserPrincipalName = $userPrincipalName
                MFAStatus = $mfaStatus
            }
        }
        catch {
            Write-ErrorLogFile -Message "Error while retrieving the MFA status for $userPrincipalName: $_" -Color "Red"
        }
    }

    $results
}

function Get-MFAMethods {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$UserPrincipalNames
    )

    $results = @()

    foreach ($userPrincipalName in $UserPrincipalNames) {
        try {
            $mfaMethods = Get-MgUserAuthenticationMethod -UserId $userPrincipalName

            if ($mfaMethods) {
                $mfaMethods = $mfaMethods | ForEach-Object {
                    switch ($_.AdditionalProperties.["@odata.type"]) {
                        "#microsoft.graph.emailAuthenticationMethod" {
                            "Email"
                        }

                        "#microsoft.graph.fido2AuthenticationMethod" {
                            "Fido2"
                        }

                        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                            "App"
                        }

                        "#microsoft.graph.passwordAuthenticationMethod" {
                            "Password"
                        }

                        "#microsoft.graph.phoneAuthenticationMethod" {
                            "Phone"
                        }

                        "#microsoft.graph.softwareOathAuthenticationMethod" {
                            "SoftwareOath"
                        }

                        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                            "HelloBusiness"
                        }

                        "#microsoft.graph.temporaryAccessPassAuthenticationMethod" {
                            "TemporaryAccessPass"
                        }

                        "#microsoft.graph.certificateBasedAuthConfiguration" {
                            "CertificateBasedAuthConfiguration"
                        }
                    }
                }

                $results += [PSCustomObject]@{
                    UserPrincipalName = $userPrincipalName
                    MFAMethods = $mfaMethods -join ', '
                }
            }
            else {
                $results += [PSCustomObject]@{
                    UserPrincipalName = $userPrincipalName
                    MFAMethods = $null
                }
            }
        }
        catch {
            Write-ErrorLogFile -Message "Error while retrieving the MFA methods for $userPrincipalName: $_" -Color "Red"
        }
    }

    $results
}

function Process-UserResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$MFAStatus,
        [Parameter(Mandatory=$true)]
        [object]$MFAMethods
    )

    $results = @()

    foreach ($status in $MFAStatus) {
        $mfaMethods = $MFAMethods | Where-Object { $_.UserPrincipalName -eq $status.UserPrincipalName }

        $results += [PSCustomObject]@{
            UserPrincipalName = $status.UserPrincipalName
            MFAStatus = $status.MFAStatus
            Email = $mfaMethods.MFAMethods -like "*Email*"
            Fido2 = $mfaMethods.MFAMethods -like "*Fido2*"
            App = $mfaMethods.MFAMethods -like "*App*"
            Password = $mfaMethods.MFAMethods -like "*Password*"
            Phone = $mfaMethods.MFAMethods -like "*Phone*"
            SoftwareOath = $mfaMethods.MFAMethods -like "*SoftwareOath*"
            HelloBusiness = $mfaMethods.MFAMethods -like "*HelloBusiness*"
            TemporaryAccessPass = $mfaMethods.MFAMethods -like "*TemporaryAccessPass*"
            CertificateBasedAuthConfiguration = $mfaMethods.MFAMethods -like "*CertificateBasedAuthConfiguration*"
        }
    }

    $results
}

function Write-ResultsToCSV {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$Results,
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    $results |
        ConvertTo-Csv -NoTypeInformation |
        Select-Object -Skip 1 |
        ForEach-Object {
            $_ -replace '"', ""
        } |
        Out-File -FilePath $FilePath -Encoding $Encoding
}

function Get-MFAOutputPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [datetime]$Date,
        [Parameter(Mandatory=$true)]
        [string]$Encoding
    )

    $outputDir = Join-Path -Path $PSScriptRoot -ChildPath "Output"
    $outputFile = "MFA-$(Get-Date -Format yyyy-MM-dd).csv"

    $filePath = Join-Path -Path $outputDir -ChildPath $outputFile

    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
    }

    $filePath
}

function Write-OutputToConsoleAndFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$true)]
        [switch]$Error,
        [Parameter(Mandatory=$false)]
        [string]$Color = "White"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $messageColor = @{
        Red     = "DarkRed"
        Green   = "Green"
        Yellow  = "Yellow"
        White   = "White"
    }

    $color = $messageColor[$Color]

    $logMessage = "$timestamp [$Color] $Message"

    if ($Error.IsPresent) {
        Write-Host $logMessage -ForegroundColor Red
    }
    else {
        Write-Host $logMessage -ForegroundColor $color
    }

    Add-Content -Path "$PSScriptRoot\log.txt" -Value $logMessage
}
