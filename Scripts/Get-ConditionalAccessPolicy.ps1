using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

Function Get-ConditionalAccessPolicies {
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

    # Initialize the results array
    $Results = @()

    # Set the default encoding if it's empty
    if (-not $Encoding) {
        $Encoding = "UTF8"
    }

    # Connect to Microsoft Graph API
    if (-not $Application.IsPresent) {
        try {
            $Credential = Get-Credential -Message "Enter your credentials for connecting to Microsoft Graph API" -ErrorAction Stop
            Connect-MgGraph -Credential $Credential -Scopes Policy.Read.All -NoWelcome -ErrorAction Stop
        }
        catch {
            Write-Error "[Error] Failed to connect to Microsoft Graph API: $_" -ErrorAction Stop
        }
    }

    try {
        # Retrieve conditional access policies
        $policies = get-MgIdentityConditionalAccessPolicy -ErrorAction stop
    }
    catch {
        Write-Error "[Error] Failed to retrieve conditional access policies: $_" -ErrorAction Stop
    }

    # Generate the output file path
    $Date = Get-Date -Format "yyyyMMddHHmmss"
    $FilePath = Join-Path -Path $OutputDir -ChildPath "$($Date)-ConditionalAccessPolicy.csv"

    # Process each policy
    foreach ($policy in $policies) {
        $myObject = New-Object -TypeName PSObject -Property @{
            DisplayName                   = $policy.DisplayName
            CreatedDateTime               = $policy.CreatedDateTime
            Description                   = $policy.Description
            Id                            = $policy.Id
            ModifiedDateTime              = $policy.ModifiedDateTime
            State                         = $policy.State
            ClientAppTypes                = $policy.Conditions.ClientAppTypes -join ', '
            ServicePrincipalRiskLevels    = $policy.Conditions.ServicePrincipalRiskLevels -join ', '
            SignInRiskLevels              = $policy.Conditions.SignInRiskLevels -join ', '
            UserRiskLevels                = $policy.Conditions.UserRiskLevels -join ', '
            BuiltInControls               = $policy.GrantControls.BuiltInControls -join ', '
            CustomAuthenticationFactors   = $policy.GrantControls.CustomAuthenticationFactors -join ', '
            ClientOperatorAppTypes        = $policy.GrantControls.Operator -join ', '
            TermsOfUse                    = $policy.GrantControls.TermsOfUse -join ', '
            DisableResilienceDefaults     = $policy.SessionControls.DisableResilienceDefaults
        }

        # Add the object to the results array
        $Results += $myObject
    }

    # Export the results to a CSV file
    $Results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-Host "[INFO] Output written to $filePath" -ForegroundColor Green
}

