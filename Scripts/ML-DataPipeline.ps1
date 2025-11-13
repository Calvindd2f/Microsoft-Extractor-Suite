# ML Data Pipeline Functions and Classes
# This module provides classes and functions for machine learning data preparation
# and synthetic incident dataset generation

#region Risk Type Classes

class EntraRiskType {
    [string] $Name
    [string] $DetectionType
    [string] $Tier
    [string] $RiskEventType

    EntraRiskType([string]$name, [string]$detectionType, [string]$tier, [string]$riskEventType) {
        $this.Name = $name
        $this.DetectionType = $detectionType
        $this.Tier = $tier
        $this.RiskEventType = $riskEventType
    }

    [string] ToString() {
        return "$($this.Name) ($($this.RiskEventType))"
    }
}

class SignInRiskType : EntraRiskType {
    SignInRiskType([string]$name, [string]$detectionType, [string]$tier, [string]$riskEventType)
    : base($name, $detectionType, $tier, $riskEventType) {
    }
}

class UserRiskType : EntraRiskType {
    UserRiskType([string]$name, [string]$detectionType, [string]$tier, [string]$riskEventType)
    : base($name, $detectionType, $tier, $riskEventType) {
    }
}

#endregion

#region Risk Type Registry Class

class EntraRiskTypeRegistry {
    static [System.Collections.Generic.List[SignInRiskType]] GetSignInRiskTypes() {
        $types = [System.Collections.Generic.List[SignInRiskType]]::new()

        $types.Add([SignInRiskType]::new("Activity from anonymous IP address", "Offline", "Premium", "riskyIPAddress"))
        $types.Add([SignInRiskType]::new("Additional risk detected (sign-in)", "Real-time or Offline", "Nonpremium", "generic"))
        $types.Add([SignInRiskType]::new("Admin confirmed user compromised", "Offline", "Nonpremium", "adminConfirmedUserCompromised"))
        $types.Add([SignInRiskType]::new("Anomalous Token (sign-in)", "Real-time or Offline", "Premium", "anomalousToken"))
        $types.Add([SignInRiskType]::new("Anonymous IP address", "Real-time", "Nonpremium", "anonymizedIPAddress"))
        $types.Add([SignInRiskType]::new("Atypical travel", "Offline", "Premium", "unlikelyTravel"))
        $types.Add([SignInRiskType]::new("Impossible travel", "Offline", "Premium", "mcasImpossibleTravel"))
        $types.Add([SignInRiskType]::new("Malicious IP address", "Offline", "Premium", "maliciousIPAddress"))
        $types.Add([SignInRiskType]::new("Mass Access to Sensitive Files", "Offline", "Premium", "mcasFinSuspiciousFileAccess"))
        $types.Add([SignInRiskType]::new("Microsoft Entra threat intelligence (sign-in)", "Real-time or Offline", "Nonpremium", "investigationsThreatIntelligence"))
        $types.Add([SignInRiskType]::new("New country", "Offline", "Premium", "newCountry"))
        $types.Add([SignInRiskType]::new("Password spray", "Real-time or Offline", "Premium", "passwordSpray"))
        $types.Add([SignInRiskType]::new("Suspicious browser", "Offline", "Premium", "suspiciousBrowser"))
        $types.Add([SignInRiskType]::new("Suspicious inbox forwarding", "Offline", "Premium", "suspiciousInboxForwarding"))
        $types.Add([SignInRiskType]::new("Suspicious inbox manipulation rules", "Offline", "Premium", "mcasSuspiciousInboxManipulationRules"))
        $types.Add([SignInRiskType]::new("Token issuer anomaly", "Offline", "Premium", "tokenIssuerAnomaly"))
        $types.Add([SignInRiskType]::new("Unfamiliar sign-in properties", "Real-time", "Premium", "unfamiliarFeatures"))
        $types.Add([SignInRiskType]::new("Verified threat actor IP", "Real-time", "Premium", "nationStateIP"))

        return $types
    }

    static [System.Collections.Generic.List[UserRiskType]] GetUserRiskTypes() {
        $types = [System.Collections.Generic.List[UserRiskType]]::new()

        $types.Add([UserRiskType]::new("Additional risk detected (user)", "Real-time or Offline", "Nonpremium", "generic"))
        $types.Add([UserRiskType]::new("Anomalous Token (user)", "Real-time or Offline", "Premium", "anomalousToken"))
        $types.Add([UserRiskType]::new("Anomalous user activity", "Offline", "Premium", "anomalousUserActivity"))
        $types.Add([UserRiskType]::new("Attacker in the Middle", "Offline", "Premium", "attackerinTheMiddle"))
        $types.Add([UserRiskType]::new("Leaked credentials", "Offline", "Nonpremium", "leakedCredentials"))
        $types.Add([UserRiskType]::new("Microsoft Entra threat intelligence (user)", "Real-time or Offline", "Nonpremium", "investigationsThreatIntelligence"))
        $types.Add([UserRiskType]::new("Possible attempt to access Primary Refresh Token (PRT)", "Offline", "Premium", "attemptedPrtAccess"))
        $types.Add([UserRiskType]::new("Suspicious API Traffic", "Offline", "Premium", "suspiciousAPITraffic"))
        $types.Add([UserRiskType]::new("Suspicious sending patterns", "Offline", "Premium", "suspiciousSendingPatterns"))
        $types.Add([UserRiskType]::new("User reported suspicious activity", "Offline", "Premium", "userReportedSuspiciousActivity"))

        return $types
    }

    static [System.Collections.Generic.List[EntraRiskType]] GetAllRiskTypes() {
        $allTypes = [System.Collections.Generic.List[EntraRiskType]]::new()
        $allTypes.AddRange([EntraRiskTypeRegistry]::GetSignInRiskTypes())
        $allTypes.AddRange([EntraRiskTypeRegistry]::GetUserRiskTypes())
        return $allTypes
    }
}

#endregion

#region assertions

<#
    synthetic data usage
    =====================
    - if the email is not .onmicrosoft.com and/or the tenant does not have the M365 E5 Developer licenses (SKU: c42b9cae-ea4f-4ab7-9717-81576235ccac), the function will throw a terminating error. This is to prevent accidental use of real customer data.
    - if the email is .onmicrosoft.com, the function will return true.
    - if the tenant does not have the M365 E5 Developer licenses (SKU: c42b9cae-ea4f-4ab7-9717-81576235ccac), the function will throw a terminating error otherwise it will return true.
    - The UserId email domain regex check is just to be annoying.
    - The E5 Dev licenses are definitive because under developer microsoft partner agreements, the only way to get the E5 Dev licenses is to have a developer tenant - which cannot be used for anything other than development/testing purposes. You can still have users created receive emails over long time periods and such; this does not mean you can use it as free email provider.
    - For the avoidance of doubt, consult the Microsoft Partner Agreement and Microsoft Terms of Service specifically regarding Developer Program.
#>

filter Assert-M365E5DevLicenseAvailable {
    <#
    .SYNOPSIS
        Checks if the tenant has at least 25 available M365 E5 Developer licenses.

    .DESCRIPTION
        Pulls all tenant licenses, stores the output as a global variable ($Global:M365_TenantLicenses),
        and checks specifically for the presence of at least 25 available M365 E5 Developer licenses
        (SKU: c42b9cae-ea4f-4ab7-9717-81576235ccac). If the license does not exist or does not have
        enough available units, writes a warning and throws a terminating error about liability/risks.

    .NOTES
        Requires connectivity to Microsoft Graph/online PowerShell with suitable permissions.
    #>
    [CmdletBinding()]
    param ()

    $skuId = "c42b9cae-ea4f-4ab7-9717-81576235ccac" # M365 E5 Developer
    try {
        # Retrieve all tenant license SKUs. Use Graph where possible for performance.
        $Global:M365_TenantLicenses = Get-MgSubscribedSku -ErrorAction Stop
    }
    catch {
        $errorMessage = @"
Unable to retrieve tenant license information.
Ensure you are connected with appropriate rights (Connect-MgGraph) and try again.

Professional & Ethical Standards Advisory:
- Synthetic data features are only licensed for use with the Microsoft 365 E5 Developer SKU.
- Do not use for production tenants, or those without explicit development/E5 licensing.
- Proceeding may violate Microsoft Terms, regulatory policy, and/or expose your organization to liability.

Remedy: Please provision at least 25 available Microsoft 365 E5 Developer licenses (SKU: $skuId) and assign as needed.
"@
        Write-Error $errorMessage
        throw
    }

    $devLicense = $Global:M365_TenantLicenses | Where-Object { $_.SkuId -eq $skuId }
    if (-not $devLicense) {
        $errorMessage = @"
[LICENSE CHECK FAILED]
No Microsoft 365 E5 Developer licenses (SKU: $skuId) were found in the tenant.

Synthetic ML data generation and export functions are licensed for use only with Microsoft 365 E5 Developer tenants.
Do NOT run these ML data generation features in production, customer, or regulated environments.

Risks & Liability:
- May violate Microsoft's service agreement or legal/policy restrictions.
- Use in unauthorized tenants exposes users to regulatory and civil risk.

Remedy: Please provision at least 25 available Microsoft 365 E5 Developer licenses (SKU: $skuId).
"@
        Write-LogFile -Message $errorMessage -Color Red -Level Standard
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.UnauthorizedAccessException]::new("No M365 E5 Developer licenses found in tenant."),
            'MissingE5DevLicense',
            [System.Management.Automation.ErrorCategory]::PermissionDenied,
            $skuId
        )
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }

    $available = $devLicense.PrepaidUnits.Enabled - $devLicense.ConsumedUnits
    if ($available -lt 1 -or $null -eq $available -or $available -eq 0 -or $available -gt $devLicense.PrepaidUnits.Enabled) {
        $errorMessage = @"
[LICENSE CHECK FAILED]
Found Microsoft 365 E5 Developer license (SKU: $skuId), but only $available are available; at least 1 are required.

Synthetic ML data generation and export functions are licensed for use only with Microsoft 365 E5 Developer tenants (minimum 1 available unit).
Do NOT run these ML data generation features in production, customer, or regulated environments.

Risks & Liability:
- May violate Microsoft's service agreement or legal/policy restrictions.
- Use in unauthorized tenants exposes users to regulatory and civil risk.

Remedy: Please provision at least 1 available Microsoft 365 E5 Developer licenses (SKU: $skuId), with enough unassigned units.
"@
        Write-LogFile -Message $errorMessage -Color Red -Level Standard
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            [System.UnauthorizedAccessException]::new("Insufficient M365 E5 Developer licenses available."),
            'InsufficientE5DevLicense',
            [System.Management.Automation.ErrorCategory]::ResourceUnavailable,
            $skuId
        )
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }
    Write-LogFile -Message "[INFO] License check successful: $available available M365 E5 Developer licenses found." -Color Green -Level Debug
    return $true
}

filter Assert-M365VanityDomain {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0,HelpMessage="This should only be invoked if the UserEmail is defined and not null, otherwise the check should be skipped.")]
        [string]$UserEmail
    )

    begin {
        # validate email domain
        if ([string]::IsNullOrWhiteSpace($UserEmail)) {
            throw "UserEmail cannot be null or empty"
        }

        # parse email domain by splitting @
        $emailParts = $UserEmail -split '@'
        if ($emailParts.Count -ne 2) {
            throw "Invalid email format: $UserEmail"
        }
    }

    process {
        # check domain contains *.onmicrosoft.com
        if ($emailParts[1] -notmatch '\.onmicrosoft\.com$') {
            $errorMessage = @"
[COMPLIANCE ERROR] Invalid email domain detected: $domain

TRANSPARENCY AND DUE DILIGENCE NOTICE:
This function is designed exclusively for generating SYNTHETIC training data using
demo/test domains (*.onmicrosoft.com). Using real customer email addresses violates
multiple ethical and legal principles:

1. EU COMPLIANCE CONCERNS:
    - GDPR Article 5(1)(a): Processing must be lawful, fair, and transparent
    - GDPR Article 6: Requires explicit consent for data processing
    - GDPR Article 25: Data protection by design and by default
    - Using real customer data without explicit consent violates these principles

2. ETHICAL CONCERNS:
    - There is sufficient synthetic material available that can mimic real-life incidents
    nearly 1:1 without exposing actual customer data
    - Real customer incident data contains sensitive information that should never be
    embedded in ML training pipelines
    - The utility of using real customer data does not justify the privacy risks

3. LIABILITY RISKS:
    - Severe legal liability under GDPR (fines up to 4% of annual revenue or €20M)
    - Potential violations of data protection laws in multiple jurisdictions
    - Breach of customer trust and professional ethics
    - Especially critical when data is embedded via ChatML training pipelines, as
    this creates permanent records that cannot be easily removed

4. ALTERNATIVES:
    - Use demo@demo.onmicrosoft.com or similar test domains
    - Generate synthetic data that mirrors real-world patterns without real identifiers
    - This approach provides the same training utility without ethical or legal exposure

Please use only *.onmicrosoft.com domains for synthetic data generation.
"@
            Write-LogFile -Message $errorMessage -Color Red -Level Standard
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                [System.ArgumentException]::new("Invalid email domain: $domain. Only *.onmicrosoft.com domains are permitted for synthetic data generation."),
                'InvalidEmailDomain',
                [System.Management.Automation.ErrorCategory]::InvalidArgument,
                $UserEmail
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }

        Write-LogFile -Message "[INFO] Generating $Count synthetic incidents in $Format format..." -Color Cyan
        Write-LogFile -Message "[INFO] Using validated demo domain: $domain" -Level Debug
    }

    end {
        return $true
    }
}

#endregion

#region ML Data Export Functions

function Get-EntraRiskType {
    <#
    .SYNOPSIS
        Retrieves Entra ID risk type definitions for synthetic incident generation or enrichment.

    .DESCRIPTION
        Returns structured data for both Sign-in and User risk detections, including detection mode, license tier,
        and the canonical riskEventType identifier. Can be filtered by -Type or randomized for permutations.

    .PARAMETER Type
        Specify 'SignIn', 'User', or 'All'. Default is 'All'.

    .PARAMETER Random
        If specified, returns N random records from the selected category.

    .PARAMETER Count
        Number of random entries to return when using -Random. Default = 1.

    .EXAMPLE
        Get-EntraRiskType -Type SignIn

    .EXAMPLE
        Get-EntraRiskType -Type User -Random -Count 3

    .NOTES
        Uses class-based risk type definitions for better type safety and performance.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('SignIn', 'User', 'All')]
        [string]$Type = 'All',
        [switch]$Random,
        [int]$Count = 1
    )

    begin {
        # Assertions & var declarations
        if ($Random -and $Count -lt 1) {
            throw "Count must be greater than 0 when using -Random parameter"
        }

        $data = $null
        $selected = $null
    }

    process {
        # retrieve risk types based on Type parameter
        $data = switch ($Type) {
            'SignIn' { [EntraRiskTypeRegistry]::GetSignInRiskTypes() }
            'User' { [EntraRiskTypeRegistry]::GetUserRiskTypes() }
            default { [EntraRiskTypeRegistry]::GetAllRiskTypes() }
        }

        # If Random is specified, perform random selection
        if ($Random) {
            if ($Count -ge $data.Count) {
                $selected = $data
            }
            else {
                $selected = [System.Collections.Generic.List[EntraRiskType]]::new($Count)
                $available = [System.Collections.Generic.List[EntraRiskType]]::new($data)
                $random = [System.Random]::new()

                for ($i = 0; $i -lt $Count; $i++) {
                    $index = $random.Next(0, $available.Count)
                    $selected.Add($available[$index])
                    $available.RemoveAt($index)
                }
            }
        }
    }

    end {
        if ($Random -and $null -ne $selected) {
            return $selected
        }
        elseif ($null -ne $data) {
            return $data
        }
        else {
            return @()
        }
    }
}

function Export-IncidentData {
    <#
    .SYNOPSIS
        Exports incident data in various formats for ML training pipelines.

    .DESCRIPTION
        Exports incident data to JSONL, ChatML, InputOutput, TSV, or RawJSON formats.
        Supports optional schema metadata for dataset documentation.

    .PARAMETER Data
        Array of incident data objects to export.

    .PARAMETER Format
        Output format: JSONL, ChatML, InputOutput, TSV, or RawJSON.

    .PARAMETER FileName
        Base filename for the output file. Default: "incident_data"

    .PARAMETER OutputDir
        Output directory path. Default: "Output"

    .PARAMETER Schema
        Optional hashtable containing schema metadata.

    .EXAMPLE
        Export-IncidentData -Data $incidents -Format ChatML -Schema @{schema_version="1.0.0"}

    .NOTES
        Optimized for performance using List<T> and efficient string operations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [array]$Data,
        [Parameter(Mandatory)]
        [ValidateSet('JSONL', 'ChatML', 'InputOutput', 'TSV', 'RawJSON')]
        [string]$Format,
        [string]$FileName = "incident_data",
        [string]$OutputDir = "Output",
        [hashtable]$Schema = $null
    )

    begin {
        # Assertions and declarations
        if (!(Test-Path $OutputDir)) {
            Write-LogFile -Message "[INFO] Creating output directory $OutputDir" -Color "Yellow"
            $null = New-Item -ItemType Directory -Force -Path $OutputDir
        }

        $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $extension = switch ($Format) {
            'TSV' { 'tsv' }
            'RawJSON' { 'json' }
            default { 'jsonl' }
        }
        $script:outputPath = Join-Path $OutputDir "$FileName-$timestamp.$extension"

        # Prepare schema metadata block if provided
        $script:schemaBlock = if ($Schema) {
            @{
                schema_version = $Schema.schema_version
                description    = $Schema.description
                author         = $Schema.author
                generated_at   = (Get-Date).ToString('s')
            } | ConvertTo-Json -Compress
        }

        # collect all data items for processing
        $script:allData = [System.Collections.Generic.List[object]]::new()
    }

    process {
        # collect all items from pipeline or parameter
        if ($null -ne $Data) {
            foreach ($item in $Data) {
                $null = $script:allData.Add($item)
            }
        }
    }

    end {
        # validate we have data to process
        if ($script:allData.Count -eq 0) {
            throw "Data parameter cannot be null or empty - no data items were provided"
        }

        # format and write data based on Format parameter
        switch ($Format) {
            'JSONL' {
                $lines = [System.Collections.Generic.List[string]]::new($script:allData.Count + 1)
                if ($script:schemaBlock) {
                    $null = $lines.Add($script:schemaBlock)
                }
                foreach ($item in $script:allData) {
                    $null = $lines.Add(($item | ConvertTo-Json -Compress -Depth 10))
                }
                [System.IO.File]::WriteAllLines($script:outputPath, $lines, [System.Text.Encoding]::UTF8)
                Write-LogFile -Message "[INFO] Exported JSONL dataset with $($script:allData.Count) records to $script:outputPath"
            }

            'ChatML' {
                $lines = [System.Collections.Generic.List[string]]::new($script:allData.Count + 1)
                if ($script:schemaBlock) {
                    $null = $lines.Add($script:schemaBlock)
                }
                foreach ($item in $script:allData) {
                    $obj = @{
                        messages = @(
                            @{ role = "system"; content = "You are a SOC analyst classifying Entra ID security incidents." }
                            @{ role = "user"; content = $item.Prompt }
                            @{ role = "assistant"; content = $item.Response }
                        )
                    }
                    $null = $lines.Add(($obj | ConvertTo-Json -Compress -Depth 10))
                }
                [System.IO.File]::WriteAllLines($script:outputPath, $lines, [System.Text.Encoding]::UTF8)
                Write-LogFile -Message "[INFO] Exported ChatML JSONL dataset to $script:outputPath"
            }

            'InputOutput' {
                $lines = [System.Collections.Generic.List[string]]::new($script:allData.Count + 1)
                if ($script:schemaBlock) {
                    $null = $lines.Add($script:schemaBlock)
                }
                foreach ($item in $script:allData) {
                    $inputValue = if ($item.Input) { $item.Input } elseif ($item.Prompt) { $item.Prompt } else { "" }
                    $outputValue = if ($item.Output) { $item.Output } elseif ($item.Response) { $item.Response } else { "" }
                    $obj = @{ input = $inputValue; output = $outputValue }
                    $null = $lines.Add(($obj | ConvertTo-Json -Compress -Depth 10))
                }
                [System.IO.File]::WriteAllLines($script:outputPath, $lines, [System.Text.Encoding]::UTF8)
                Write-LogFile -Message "[INFO] Exported Input/Output JSONL dataset to $script:outputPath"
            }

            'TSV' {
                if ($script:allData.Count -eq 0) {
                    Write-LogFile -Message "[WARNING] No data to export to TSV format" -Color Yellow
                    return $null
                }

                # sb for TSV construction
                $sb = [System.Text.StringBuilder]::new()

                # write headers
                $headers = [System.Collections.Generic.List[string]]::new()
                foreach ($prop in $script:allData[0].PSObject.Properties) {
                    $null = $headers.Add($prop.Name)
                }
                $null = $sb.AppendLine(($headers -join "`t"))

                # write data rows
                foreach ($item in $script:allData) {
                    $values = [System.Collections.Generic.List[string]]::new()
                    foreach ($prop in $item.PSObject.Properties) {
                        $value = if ($null -eq $prop.Value) { "" } else { $prop.Value.ToString() }
                        # Replace tabs in values with spaces to avoid breaking TSV format
                        $value = $value -replace "`t", " "
                        $null = $values.Add($value)
                    }
                    $null = $sb.AppendLine(($values -join "`t"))
                }

                [System.IO.File]::WriteAllText($script:outputPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
                Write-LogFile -Message "[INFO] Exported TSV dataset with $($script:allData.Count) records to $script:outputPath"
            }

            'RawJSON' {
                $json = if ($Schema) {
                    @{ _schema = $Schema; data = $script:allData } | ConvertTo-Json -Depth 10
                }
                else {
                    $script:allData | ConvertTo-Json -Depth 10
                }
                [System.IO.File]::WriteAllText($script:outputPath, $json, [System.Text.Encoding]::UTF8)
                Write-LogFile -Message "[INFO] Exported raw JSON dataset to $script:outputPath"
            }
        }

        return $script:outputPath
    }
}

function New-SyntheticIncidentDataset {
    <#
    .SYNOPSIS
        Generates synthetic incident datasets for ML training.

    .DESCRIPTION
        Creates synthetic Entra ID security incident datasets by randomly selecting risk types
        and generating training examples in various formats.

    .PARAMETER Count
        Number of synthetic incidents to generate. Default: 100.

    .PARAMETER Format
        Output format: JSONL, ChatML, InputOutput, TSV, or RawJSON. Default: JSONL.

    .PARAMETER FileName
        Base filename for the output file. Default: "synthetic_incidents".

    .PARAMETER OutputDir
        Output directory path. Default: "Output".

    .PARAMETER UserEmail
        Email address to use in synthetic incidents. Default: "user@demo.onmicrosoft.com".
        MUST be a *.onmicrosoft.com domain for compliance and ethical reasons... Get europe'd lol

    .PARAMETER IncludeSchema
        Include schema metadata in the output.

    .EXAMPLE
        New-SyntheticIncidentDataset -Count 200 -Format ChatML

    .NOTES
        Uses class-based risk types for better performance and type safety.
        This function enforces strict email domain validation to prevent accidental use of real customer data.
    #>
    [CmdletBinding()]
    param(
        [int]$Count = 100,
        [ValidateSet('JSONL', 'ChatML', 'InputOutput', 'TSV', 'RawJSON')]
        [string]$Format = 'JSONL',
        [string]$FileName = "synthetic_incidents",
        [string]$OutputDir = "Output",
        [string]$UserEmail = "user@demo.onmicrosoft.com",
        [switch]$IncludeSchema
    )

    begin {
        # assertions & declarations
        if ($Count -lt 1) {
            throw "Count must be greater than 0"
        }

        #TODO: Both Ethics checks need to return true
        if (-not (Assert-M365E5DevLicenseAvailable -ErrorAction Stop)) {
            # This check is definitive.
            throw "M365 E5 Developer license not available"
        }
        if (-not ([string]::IsNullOrEmpty($UserEmail.Split('@')[1]))) {
            # This check is sepculative, yet grounded in context of a developer tenant.
            throw "Invalid email domain"
        }
    }

    process {
        # retrieve risk types and generate synthetic incidents
        $riskTypes = Get-EntraRiskType -Type All -Random -Count $Count

        $syntheticData = [System.Collections.Generic.List[object]]::new($Count)
        $random = [System.Random]::new()

        foreach ($risk in $riskTypes) {
            $incident = [ordered]@{
                Prompt        = "Alert: $($risk.Name) detected for user $UserEmail"
                Response      = "Detected via $($risk.DetectionType), risk category: $($risk.RiskEventType), tier: $($risk.Tier)"
                RiskType      = $risk.RiskEventType
                DetectionType = $risk.DetectionType
                Tier          = $risk.Tier
                Timestamp     = (Get-Date).AddSeconds(-$random.Next(0, 86400 * 30)).ToString('s')
            }
            $null = $syntheticData.Add($incident)
        }
    }

    end {
        # export data and cleanup
        $schema = if ($IncludeSchema) {
            @{
                schema_version = "1.0.0"
                description    = "Synthetic Entra Incident Training Data"
                author         = "Invictus Incident Response"
            }
        }
        else {
            $null
        }

        $outputPath = Export-IncidentData -Data $syntheticData -Format $Format -FileName $FileName -OutputDir $OutputDir -Schema $schema

        Write-LogFile -Message "[INFO] Successfully generated $Count synthetic incidents" -Color Green
        Write-LogFile -Message "[INFO] Output file: $outputPath" -Color Green

        return $outputPath
    }
}

#endregion

Export-ModuleMember -Function @(
    'Get-EntraRiskType',
    'Export-IncidentData',
    'New-SyntheticIncidentDataset',
    'Assert-M365E5DevLicenseAvailable',
    'Assert-M365VanityDomain'
)
