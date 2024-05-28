using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

Function Get-ConditionalAccessPolicies {
<#
    .SYNOPSIS
    Retrieves all the conditional access policies. 

    .DESCRIPTION
    Retrieves the risky users from the Entra ID Identity Protection, which marks an account as being at risk based on the pattern of activity for the account.
    The output will be written to: Output\UserInfo\

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\UserInfo

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8
    Aliases: Enc

    .PARAMETER Application
    Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    Default: Delegated access (access on behalf a user)
    ValidateSet: Application, Delegated
    ValidateCount: 1
    ValidateNotNull: $true
    ValidateNotNullOrEmpty: $true
    SuppressMessage: 'PS0045', 'Parameter has invalid attributes'

    .EXAMPLE
    Get-ConditionalAccessPolicies
    Retrieves all the conditional access policies.

    .EXAMPLE
    Get-ConditionalAccessPolicies -Application
    Retrieves all the conditional access policies via application authentication.
	
    .EXAMPLE
    Get-ConditionalAccessPolicies -Encoding utf32
    Retrieves all the conditional access policies and exports the output to a CSV file with UTF-32 encoding.
		
    .EXAMPLE
    Get-ConditionalAccessPolicies -OutputDir C:\Windows\Temp
    Retrieves all the conditional access policies and saves the output to the C:\Windows\Temp folder.	
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,
                    Position=0,
                    ValueFromPipelineByPropertyName=$true,
                    ValueFromPipeline=$true,
                    HelpMessage='The output directory.')]
        [System.Management.Automation.ValidateNotNullOrEmpty()]
        [System.Management.Automation.ValidateScript({Test-Path $_ -PathType Container})]
        [System.Management.Automation.ValidatePattern('^[a-zA-Z]:\\.*$')]
        [string]$OutputDir = "Output\UserInfo",

        [Parameter(Mandatory=$false,
                    Position=1,
                    ValueFromPipelineByPropertyName=$true,
                    HelpMessage='The encoding of the CSV output file.')]
        [System.Management.Automation.AllowNull()]
        [System.Management.Automation.ValidateNotNull()]
        [System.Management.Automation.ValidateNotNullOrEmpty()]
        [System.Management.Automation.ValidateSet('utf8','utf16','utf32','ascii','bigendianunicode','default','oem','unicode')]
        [string]$Encoding = "UTF8",

        [Parameter(Mandatory=$false,
                    Position=2,
                    HelpMessage='App-only access (access without a user) for authentication and authorization.')]
        [System.Management.Automation.ValidateSet('Application','Delegated',IgnoreCase=$true)]
        [System.Management.Automation.ValidateCount(1)]
        [System.Management.Automation.ValidateNotNull()]
        [System.Management.Automation.ValidateNotNullOrEmpty()]
        [switch]$Application
    )

    [System.Management.Automation.OutputType()]
    [System.Collections.Generic.List`1[System.Management.Automation.PSObject]]
    $Results = @()

    if ($Encoding -eq "" ){
        $Encoding = "UTF8"
    }

    if (!($Application.IsPresent)) {
        try {
            $Credential = Get-Credential -Message "Enter your credentials for connecting to Microsoft Graph API" -ErrorAction Stop
            Connect-MgGraph -Credential $Credential -Scopes Policy.Read.All -NoWelcome -ErrorAction Stop
        }
        catch {
            Write-Error "[Error] Failed to connect to Microsoft Graph API: $_" -ErrorAction Stop
        }
    }

    try {
        $areYouConnected = get-MgIdentityConditionalAccessPolicy -ErrorAction stop
    }
    catch {
        Write-Error "[Error] Failed to retrieve conditional access policies: $_" -ErrorAction Stop
    }

    $Date = [datetime]::Now.ToString('yyyyMMddHHmmss')
    $FilePath = "$OutputDir\$($Date)-ConditionalAccessPolicy.csv"

    $Results = @()

    get-MgIdentityConditionalAccessPolicy -all | ForEach-Object {
        $myObject = [PSCustomObject]@{
            DisplayName                   = "-"
            CreatedDateTime               = "-"
            Description                   = "-"
            Id                            = "-"
            ModifiedDateTime              = "-"
            State                         = "-"
            ClientAppTypes                = "-"
            ServicePrincipalRiskLevels    = "-"
            SignInRiskLevels              = "-"
            UserRiskLevels                = "-"
            BuiltInControls               = "-"
            CustomAuthenticationFactors   = "-"
            ClientOperatorAppTypes        = "-"
            TermsOfUse                    = "-"
            DisableResilienceDefaults     = "-"
        }

        $myobject.DisplayName = $_.DisplayName
        $myobject.CreatedDateTime = $_.CreatedDateTime
        $myobject.Description = $_.Description
        $myobject.Id = $_.Id
        $myobject.ModifiedDateTime = $_.ModifiedDateTime
        $myobject.State = $_.State
        $myobject.ClientAppTypes = $_.Conditions.ClientAppTypes | out-string
        $myobject.ServicePrincipalRiskLevels = $_.Conditions.ServicePrincipalRiskLevels | out-string
        $myobject.SignInRiskLevels = $_.Conditions.SignInRiskLevels | out-string
        $myobject.UserRiskLevels = $_.Conditions.UserRiskLevels | out-string
        $myobject.BuiltInControls = $_.GrantControls.BuiltInControls | out-string
        $myobject.CustomAuthenticationFactors = $_.GrantControls.CustomAuthenticationFactors | out-string
        $myobject.ClientOperatorAppTypes = $_.GrantControls.Operator | out-string
        $myobject.TermsOfUse = $_.GrantControls.TermsOfUse | out-string
        $myobject.DisableResilienceDefaults = $_.SessionControls.DisableResilienceDefaults | out-string
        $Results += $myObject
    }

    $Results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-Host "[INFO] Output written to $filePath" -ForegroundColor Green
}
