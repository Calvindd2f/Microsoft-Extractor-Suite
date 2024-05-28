using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Write-LogFile([string]$Message, [string]$Color = "White") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $messageColor = @{
        Red     = "DarkRed"
        Green   = "Green"
        Yellow  = "Yellow"
        White   = "White"
    }

    $color = $messageColor[$Color]

    $logMessage = "$timestamp [$Color] $Message"
    Write-Host $logMessage -ForegroundColor $color
    Add-Content -Path "$PSScriptRoot\log.txt" -Value $logMessage
}

function Connect-MgGraph([string[]]$Scopes, [switch]$NoWelcome) {
    $moduleName = "Microsoft.Graph"
    $moduleVersion = "1.0.0"

    if (-not (Get-Module -Name $moduleName -ListAvailable)) {
        Write-LogFile -Message "Installing the Microsoft.Graph module..." -Color Yellow
        Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser
    }

    if (-not (Get-Module -Name $moduleName -ListAvailable)) {
        Write-LogFile -Message "Failed to install the Microsoft.Graph module. Please install it manually and try again." -Color Red
        return
    }

    if (-not (Get-Module -Name $moduleName -Name $moduleVersion)) {
        Write-LogFile -Message "The required version of the Microsoft.Graph module is not installed. Installing it now..." -Color Yellow
        Uninstall-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
        Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser -RequiredVersion $moduleVersion
    }

    if (-not (Get-Module -Name $moduleName -Name $moduleVersion)) {
        Write-LogFile -Message "Failed to install the required version of the Microsoft.Graph module. Please install it manually and try again." -Color Red
        return
    }

    $module = Import-Module -Name $moduleName -PassThru -MinimumVersion $moduleVersion

    if (-not $module.ExportedCommands.ContainsKey("Connect-MgGraph")) {
        Write-LogFile -Message "The required Connect-MgGraph cmdlet is not found in the Microsoft.Graph module. Please install the latest version and try again." -Color Red
        return
    }

    if (-not (Get-MgSession)) {
        Connect-MgGraph -Scopes $Scopes -NoWelcome
    }
}

function Get-MFA {
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\UserInfo",
        [string]$Encoding = "UTF8",
        [switch]$Application
    )

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    $scopes = @('UserAuthenticationMethod.Read.All', 'User.Read.All')

    if (-not (Get-MgSession)) {
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
            Write-LogFile -Message "You must call Connect-MgGraph -Scopes '$($scopes -join ',')' before running this script" -Color "Red"
            return
        }
    }

    try {
        $users = Get-MgUser -All
    }
    catch {
        Write-LogFile -Message "Error while retrieving users: $_" -Color "Red"
        return
    }

    $mfaStatus = "Disabled"
    $mfaMethods = @{}

    foreach ($user in $users) {
        try {
            $mfaData = Get-MgUserAuthenticationMethod -UserId $user.UserPrincipalName

            if ($mfaData) {
                $mfaStatus = "Enabled"
                break
            }
        }
        catch {
            Write-LogFile -Message "Error while retrieving the MFA status for $($user.UserPrincipalName): $_" -Color "Red"
        }
    }

    $results = foreach ($user in $users) {
        $mfaMethods = @{}

        try {
            $mfaData = Get-MgUserAuthenticationMethod -UserId $user.UserPrincipalName

            if ($mfaData) {
                foreach ($method in $mfaData) {
                    switch ($method.AdditionalProperties.["@odata.type"]) {
                        "#microsoft.graph.emailAuthenticationMethod" {
                            $mfaMethods.email = $true
                        }

                        "#microsoft.graph.fido2AuthenticationMethod" {
                            $mfaMethods.fido2 = $true
                        }

                        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                            $mfaMethods.app = $true
                        }

                        "#microsoft.graph.passwordAuthenticationMethod" {
                            $mfaMethods.password = $true
                        }

                        "#microsoft.graph.phoneAuthenticationMethod" {
                            $mfaMethods.phone = $true
                        }

                        "#microsoft.graph.softwareOathAuthenticationMethod" {
                            $mfaMethods.softwareoath = $true
                        }

                        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                            $mfaMethods.hellobusiness = $true
                        }

                        "#microsoft.graph.temporaryAccessPassAuthenticationMethod" {
                            $mfaMethods.temporaryAccessPassAuthenticationMethod = $true
                        }

                        "#microsoft.graph.certificateBasedAuthConfiguration" {
                            $mfaMethods.certificateBasedAuthConfiguration = $true
                        }
                    }
                }
            }
        }
        catch {
            Write-LogFile -Message "Error while retrieving the MFA status for $($user.UserPrincipalName): $_" -Color "Red"
        }

        [PSCustomObject]@{
            User                 = $user.UserPrincipalName
            MFAStatus            = $mfaStatus
            Email               = $mfaMethods.email
            Fido2               = $mfaMethods.fido2
            App                 = $mfaMethods.app
            Password            = $mfaMethods.password
            Phone               = $mfaMethods.phone
            SoftwareOath       = $mfaMethods.softwareoath
            HelloBusiness      = $mfaMethods.hellobusiness
            TemporaryAccessPass = $mfaMethods.temporaryAccessPassAuthenticationMethod
            CertificateBasedAuthConfiguration = $mfaMethods.certificateBasedAuthConfiguration
        }
    }

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = Join-Path $OutputDir "$($date)-MFA-AuthenticationMethods.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-LogFile -Message "Output written to $filePath" -Color "Green"

    $mfaStatusCount = ($results | Where-Object { $_.MFAStatus -eq "Enabled" }).Count
    Write-Host "$mfaStatusCount out of $($users.Count) users have MFA enabled:"
    $mfaMethods | ForEach-Object {
        Write-Host "  - $($_.Count) x $_"
    }

    Write-LogFile -Message "Retrieving the user registration details" -Color "Green"

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = Join-Path $OutputDir "$($date)-MFA-UserRegistrationDetails.csv"

    $registrationDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
    $results = foreach ($detail in $registrationDetails) {
        [PSCustomObject]@{
            Id                                                  = $detail.Id
            IsAdmin                                             = $detail.IsAdmin
            IsMfaCapable                                        = $detail.IsMfaCapable
            IsMfaRegistered                                     = $detail.IsMfaRegistered
            IsPasswordlessCapable                               = $detail.IsPasswordlessCapable
            IsSsprCapable                                       = $detail.IsSsprCapable
            IsSsprEnabled                                       = $detail.IsSsprEnabled
            IsSsprRegistered                                    = $detail.IsSsprRegistered
            IsSystemPreferredAuthenticationMethodEnabled        = $detail.IsSystemPreferredAuthenticationMethodEnabled
            MethodsRegistered                                   = $detail.MethodsRegistered -join ', '
            SystemPreferredAuthenticationMethods                = $detail.SystemPreferredAuthenticationMethods -join ', '
            UserDisplayName                                     = $detail.UserDisplayName
            UserPreferredMethodForSecondaryAuthentication       = $detail.UserPreferredMethodForSecondaryAuthentication
            UserPrincipalName                                   = $detail.UserPrincipalName
            UserType                                            = $detail.UserType
            LastUpdatedDateTime                                 = $detail.LastUpdatedDateTime
        }
    }

    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-LogFile -Message "Output written to $filePath" -Color "Green"
}
