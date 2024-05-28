using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

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
    if (-not $Application.IsPresent) {
        Connect-MgGraph -Scopes $scopes -NoWelcome
    }

    try {
        $users = Get-MgUser -All
    }
    catch {
        Write-LogFile -Message "You must call Connect-MgGraph -Scopes '$($scopes -join ',')' before running this script" -Color "Red"
        return
    }

    $results = foreach ($user in $users) {
        $mfaStatus = "Disabled"
        $mfaMethods = @{}

        try {
            $mfaData = Get-MgUserAuthenticationMethod -UserId $user.UserPrincipalName

            foreach ($method in $mfaData) {
                switch ($method.AdditionalProperties.["@odata.type"]) {
                    "#microsoft.graph.emailAuthenticationMethod" {
                        $mfaMethods.email = $true
                        $mfaStatus = "Enabled"
                    }

                    "#microsoft.graph.fido2AuthenticationMethod" {
                        $mfaMethods.fido2 = $true
                        $mfaStatus = "Enabled"
                    }

                    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                        $mfaMethods.app = $true
                        $mfaStatus = "Enabled"
                    }

                    "#microsoft.graph.passwordAuthenticationMethod" {
                        $mfaMethods.password = $true
                        if ($mfaStatus -ne "Enabled") {
                            $mfaStatus = "Disabled"
                        }
                    }

                    "#microsoft.graph.phoneAuthenticationMethod" {
                        $mfaMethods.phone = $true
                        $mfaStatus = "Enabled"
                    }

                    "#microsoft.graph.softwareOathAuthenticationMethod" {
                        $mfaMethods.softwareoath = $true
                        $mfaStatus = "Enabled"
                    }

                    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                        $mfaMethods.hellobusiness = $true
                        $mfaStatus = "Enabled"
                    }

                    "#microsoft.graph.temporaryAccessPassAuthenticationMethod" {
                        $mfaMethods.temporaryAccessPassAuthenticationMethod = $true
                        $mfaStatus = "Enabled"
                    }

                    "#microsoft.graph.certificateBasedAuthConfiguration" {
                        $mfaMethods.certificateBasedAuthConfiguration = $true
                        $mfaStatus = "Enabled"
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
