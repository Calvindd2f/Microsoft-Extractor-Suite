using module 'ScubaConfig\ScubaConfig.psm1'



$ArgToProd = @{
    teams = "Teams";
    exo = "EXO";
    defender = "Defender";
    aad = "AAD";
    powerplatform = "PowerPlatform";
    sharepoint = "SharePoint";
}

$ProdToFullName = @{
    Teams = "Microsoft Teams";
    EXO = "Exchange Online";
    Defender = "Microsoft 365 Defender";
    AAD = "Azure Active Directory";
    PowerPlatform = "Microsoft Power Platform";
    SharePoint = "SharePoint Online";
}



function Get-FileEncoding{
    <#
    .Description
    This function returns encoding type for setting content.
    .Functionality
    Internal
    #>
    $PSVersion = $PSVersionTable.PSVersion

    $Encoding = 'utf8'

    if ($PSVersion -ge '6.0'){
        $Encoding = 'utf8NoBom'
    }

    return $Encoding
}

function Invoke-ProviderList {
    <#
    .Description
    This function runs the various providers modules stored in the Providers Folder
    Output will be stored as a ProviderSettingsExport.json in the OutPath Folder
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("teams", "exo", "defender", "aad", "powerplatform", "sharepoint", '*', IgnoreCase = $false)]
        [string[]]
        $ProductNames,

        [Parameter(Mandatory = $true)]
        [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $M365Environment,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $TenantDetails,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ModuleVersion,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutFolderPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutProviderFileName,

        [Parameter(Mandatory = $true)]
        [hashtable]
        $BoundParameters
    )
    process {
        try {
            # yes the syntax has to be like this
            # fixing the spacing causes PowerShell interpreter errors
            $ProviderJSON = @"
"@
            $N = 0
            $Len = $ProductNames.Length
            $ProdProviderFailed = @()
            $ConnectTenantParams = @{
                'M365Environment' = $M365Environment
            }
            $SPOProviderParams = @{
                'M365Environment' = $M365Environment
            }

            $PnPFlag = $false
            if ($BoundParameters.AppID) {
                $ServicePrincipalParams = Get-ServicePrincipalParams -BoundParameters $BoundParameters
                $ConnectTenantParams += @{ServicePrincipalParams = $ServicePrincipalParams; }
                $PnPFlag = $true
                $SPOProviderParams += @{PnPFlag = $PnPFlag }
            }

            foreach ($Product in $ProductNames) {
                $BaselineName = $ArgToProd[$Product]
                $N += 1
                $Percent = $N * 100 / $Len
                $Status = "Running the $($BaselineName) Provider; $($N) of $($Len) Product settings extracted"
                $ProgressParams = @{
                    'Activity' = "Running the provider for each baseline";
                    'Status' = $Status;
                    'PercentComplete' = $Percent;
                    'Id' = 1;
                    'ErrorAction' = 'Stop';
                }
                Write-Progress @ProgressParams
                try {
                    $RetVal = ""
                    switch ($Product) {
                        "aad" {
                            $RetVal = Export-AADProvider | Select-Object -Last 1
                        }
                        "exo" {
                            $RetVal = Export-EXOProvider | Select-Object -Last 1
                        }
                        "defender" {
                            $RetVal = Export-DefenderProvider @ConnectTenantParams  | Select-Object -Last 1
                        }
                        "powerplatform" {
                            $RetVal = Export-PowerPlatformProvider -M365Environment $M365Environment | Select-Object -Last 1
                        }
                        "sharepoint" {
                            $RetVal = Export-SharePointProvider @SPOProviderParams | Select-Object -Last 1
                        }
                        "teams" {
                            $RetVal = Export-TeamsProvider | Select-Object -Last 1
                        }
                        default {
                            Write-Error -Message "Invalid ProductName argument"
                        }
                    }
                    $ProviderJSON += $RetVal
                }
                catch {
                    Write-Error "Error with the $($BaselineName) Provider. See the exception message for more details:  $($_)"
                    $ProdProviderFailed += $Product
                    Write-Warning "$($Product) will be omitted from the output because of the failure above `n`n"
                }
            }

            $ProviderJSON = $ProviderJSON.TrimEnd(",")
            $TimeZone = ""
            $CurrentDate = Get-Date -ErrorAction 'Stop'
            $TimestampZulu = $CurrentDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $GetTimeZone = Get-TimeZone -ErrorAction 'Stop'
            if (($CurrentDate).IsDaylightSavingTime()) {
                $TimeZone = ($GetTimeZone).DaylightName
            }
            else {
                $TimeZone = ($GetTimeZone).StandardName
            }

        $ConfigDetails = @(ConvertTo-Json -Depth 100 $([ScubaConfig]::GetInstance().Configuration))
        if(! $ConfigDetails) {
            $ConfigDetails = "{}"
        }

        $BaselineSettingsExport = @"
        {
                "baseline_version": "1",
                "module_version": "$ModuleVersion",
                "date": "$($CurrentDate) $($TimeZone)",
                "timestamp_zulu": "$($TimestampZulu)",
                "tenant_details": $($TenantDetails),
                "scuba_config": $($ConfigDetails),

                $ProviderJSON
        }
"@

            # Strip the character sequences that Rego tries to interpret as escape sequences,
            # resulting in the error "unable to parse input: yaml: line x: found unknown escape character"
            # "\/", ex: "\/Date(1705651200000)\/"
            $BaselineSettingsExport = $BaselineSettingsExport.replace("\/", "")
            # "\B", ex: "Removed an entry in Tenant Allow\Block List"
            $BaselineSettingsExport = $BaselineSettingsExport.replace("\B", "/B")

            $FinalPath = Join-Path -Path $OutFolderPath -ChildPath "$($OutProviderFileName).json" -ErrorAction 'Stop'
            $BaselineSettingsExport | Set-Content -Path $FinalPath -Encoding $(Get-FileEncoding) -ErrorAction 'Stop'
            $ProdProviderFailed
        }
        catch {
            $InvokeProviderListErrorMessage = "Fatal Error involving the Provider functions. `
            Ending ScubaGear execution. See the exception message for more details: $($_)"
            throw $InvokeProviderListErrorMessage
        }
    }
}

function Invoke-RunRego {
    <#
    .Description
    This function runs the RunRego module.
    Which runs the various rego files against the
    ProviderSettings.json using the specified OPA executable
    Output will be stored as a TestResults.json in the OutPath Folder
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("teams", "exo", "defender", "aad", "powerplatform", "sharepoint", '*', IgnoreCase = $false)]
        [string[]]
        $ProductNames,

        [ValidateNotNullOrEmpty()]
        [string]
        $OPAPath = [ScubaConfig]::ScubaDefault('DefaultOPAPath'),

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ParentPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OutFolderPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $OutProviderFileName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutRegoFileName
    )
    process {
        try {
            $ProdRegoFailed = @()
            $TestResults = @()
            $N = 0
            $Len = $ProductNames.Length
            foreach ($Product in $ProductNames) {
                $BaselineName = $ArgToProd[$Product]
                $N += 1
                $Percent = $N * 100 / $Len

                $Status = "Running the $($BaselineName) Rego Verification; $($N) of $($Len) Rego verifications completed"
                $ProgressParams = @{
                    'Activity' = "Running the rego for each baseline";
                    'Status' = $Status;
                    'PercentComplete' = $Percent;
                    'Id' = 1;
                    'ErrorAction' = 'Stop';
                }
                Write-Progress @ProgressParams
                $InputFile = Join-Path -Path $OutFolderPath "$($OutProviderFileName).json" -ErrorAction 'Stop'
                $RegoFile = Join-Path -Path $ParentPath -ChildPath "Rego" -ErrorAction 'Stop'
                $RegoFile = Join-Path -Path $RegoFile -ChildPath "$($BaselineName)Config.rego" -ErrorAction 'Stop'
                $params = @{
                    'InputFile' = $InputFile;
                    'RegoFile' = $RegoFile;
                    'PackageName' = $Product;
                    'OPAPath' = $OPAPath
                }
                try {
                    $RetVal = Invoke-Rego @params
                    $TestResults += $RetVal
                }
                catch {
                    Write-Error "Error with the $($BaselineName) Rego invocation. See the exception message for more details:  $($_)"
                    $ProdRegoFailed += $Product
                    Write-Warning "$($Product) will be omitted from the output because of the failure above"
                }
            }

            $TestResultsJson = $TestResults | ConvertTo-Json -Depth 5 -ErrorAction 'Stop'
            $FileName = Join-Path -Path $OutFolderPath "$($OutRegoFileName).json" -ErrorAction 'Stop'
            $TestResultsJson | Set-Content -Path $FileName -Encoding $(Get-FileEncoding) -ErrorAction 'Stop'

            foreach ($Product in $TestResults) {
                foreach ($Test in $Product) {
                    # ConvertTo-Csv struggles with the nested nature of the ActualValue
                    # and Commandlet fields. Explicitly convert these to json strings before
                    # calling ConvertTo-Csv
                    $Test.ActualValue = $Test.ActualValue | ConvertTo-Json -Depth 3 -Compress -ErrorAction 'Stop'
                    $Test.Commandlet = $Test.Commandlet -Join ", "
                }
            }
            $TestResultsCsv = $TestResults | ConvertTo-Csv -NoTypeInformation -ErrorAction 'Stop'
            $CSVFileName = Join-Path -Path $OutFolderPath "$($OutRegoFileName).csv" -ErrorAction 'Stop'
            $TestResultsCsv | Set-Content -Path $CSVFileName -Encoding $(Get-FileEncoding) -ErrorAction 'Stop'
            $ProdRegoFailed
        }
        catch {
            $InvokeRegoErrorMessage = "Fatal Error involving the OPA output function. `
            Ending ScubaGear execution. See the exception message for more details: $($_)"
            throw $InvokeRegoErrorMessage
        }
    }
}

function Pluralize {
    <#
    .Description
    This function whether the singular or plural version of the noun
    is needed and returns the appropriate version.
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SingularNoun,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PluralNoun,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]
        $Count
    )
    process {
        if ($Count -gt 1) {
            $PluralNoun
        }
        else {
            $SingularNoun
        }
    }
}

function Merge-JsonOutput {
    <#
    .Description
    This function packages all the json output created into a single json file.
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("teams", "exo", "defender", "aad", "powerplatform", "sharepoint", '*', IgnoreCase = $false)]
        [string[]]
        $ProductNames,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutFolderPath,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutProviderFileName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [object]
        $TenantDetails,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ModuleVersion,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutJsonFileName
    )
    process {
        try {
            # Files to delete at the end if no errors are encountered
            $DeletionList = @()

            # Load the raw provider output
            $SettingsExportPath = Join-Path $OutFolderPath -ChildPath "$($OutProviderFileName).json"
            $DeletionList += $SettingsExportPath
            $SettingsExport =  Get-Content $SettingsExportPath -Raw
            $TimestampZulu = $(ConvertFrom-Json $SettingsExport).timestamp_zulu

            # Get a list and abbreviation mapping of the products assessed
            $FullNames = @()
            $ProductAbbreviationMapping = @{}
            foreach ($ProductName in $ProductNames) {
                $BaselineName = $ArgToProd[$ProductName]
                $FullNames += $ProdToFullName[$BaselineName]
                $ProductAbbreviationMapping[$ProdToFullName[$BaselineName]] = $BaselineName
            }

            # Extract the metadata
            $Results = [pscustomobject]@{}
            $Summary = [pscustomobject]@{}
            $MetaData = [pscustomobject]@{
                "TenantId" = $TenantDetails.TenantId;
                "DisplayName" = $TenantDetails.DisplayName;
                "DomainName" = $TenantDetails.DomainName;
                "ProductSuite" = "Microsoft 365";
                "ProductsAssessed" = $FullNames;
                "ProductAbbreviationMapping" = $ProductAbbreviationMapping
                "Tool" = "ScubaGear";
                "ToolVersion" = $ModuleVersion;
                "TimestampZulu" = $TimestampZulu;
            }


            # Aggregate the report results and summaries
            $IndividualReportPath = Join-Path -Path $OutFolderPath $IndividualReportFolderName -ErrorAction 'Stop'
            foreach ($Product in $ProductNames) {
                $BaselineName = $ArgToProd[$Product]
                $FileName = Join-Path $IndividualReportPath "$($BaselineName)Report.json"
                $DeletionList += $FileName
                $IndividualResults = Get-Content $FileName | ConvertFrom-Json

                $Results | Add-Member -NotePropertyName $BaselineName `
                    -NotePropertyValue $IndividualResults.Results

                # The date is listed under the metadata, no need to include it in the summary as well
                $IndividualResults.ReportSummary.PSObject.Properties.Remove('Date')

                $Summary | Add-Member -NotePropertyName $BaselineName `
                    -NotePropertyValue $IndividualResults.ReportSummary
            }

            # Convert the output a json string
            $MetaData = ConvertTo-Json $MetaData -Depth 3
            $Results = ConvertTo-Json $Results -Depth 5
            $Summary = ConvertTo-Json $Summary -Depth 3
            $ReportJson = @"
{
    "MetaData": $MetaData,
    "Summary": $Summary,
    "Results": $Results,
    "Raw": $SettingsExport
}
"@

            # ConvertTo-Json for some reason converts the <, >, and ' characters into unicode escape sequences.
            # Convert those back to ASCII.
            $ReportJson = $ReportJson.replace("\u003c", "<")
            $ReportJson = $ReportJson.replace("\u003e", ">")
            $ReportJson = $ReportJson.replace("\u0027", "'")

            # Save the file
            $JsonFileName = Join-Path -Path $OutFolderPath "$($OutJsonFileName).json" -ErrorAction 'Stop'
            $ReportJson | Set-Content -Path $JsonFileName -Encoding $(Get-FileEncoding) -ErrorAction 'Stop'

            # Delete the now redundant files
            foreach ($File in $DeletionList) {
                Remove-Item $File
            }
        }
        catch {
            $MergeJsonErrorMessage = "Fatal Error involving the Json reports aggregation. `
            Ending ScubaGear execution. See the exception message for more details: $($_)"
            throw $MergeJsonErrorMessage
        }
    }
}

function Get-TenantDetail {
    <#
    .Description
    This function gets the details of the M365 Tenant using
    the various M365 PowerShell modules
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("teams", "exo", "defender", "aad", "powerplatform", "sharepoint", IgnoreCase = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ProductNames,

        [Parameter(Mandatory = $true)]
        [ValidateSet("commercial", "gcc", "gcchigh", "dod", IgnoreCase = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $M365Environment
    )

    # organized by best tenant details information
    if ($ProductNames.Contains("aad")) {
        Get-AADTenantDetail
    }
    elseif ($ProductNames.Contains("sharepoint")) {
        Get-AADTenantDetail
    }
    elseif ($ProductNames.Contains("teams")) {
        Get-TeamsTenantDetail -M365Environment $M365Environment
    }
    elseif ($ProductNames.Contains("powerplatform")) {
        Get-PowerPlatformTenantDetail -M365Environment $M365Environment
    }
    elseif ($ProductNames.Contains("exo")) {
        Get-EXOTenantDetail -M365Environment $M365Environment
    }
    elseif ($ProductNames.Contains("defender")) {
        Get-EXOTenantDetail -M365Environment $M365Environment
    }
    else {
        $TenantInfo = @{
            "DisplayName" = "Orchestrator Error retrieving Display name";
            "DomainName" = "Orchestrator Error retrieving Domain name";
            "TenantId" = "Orchestrator Error retrieving Tenant ID";
            "AdditionalData" = "Orchestrator Error retrieving additional data";
        }
        $TenantInfo = $TenantInfo | ConvertTo-Json -Depth 3
        $TenantInfo
    }
}

function Invoke-Connection {
    <#
    .Description
    This function uses the Connection.psm1 module
    which uses the various PowerShell modules to establish
    a connection to an M365 Tenant associated with provided
    credentials
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [boolean]
        $LogIn,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("teams", "exo", "defender", "aad", "powerplatform", "sharepoint", '*', IgnoreCase = $false)]
        [string[]]
        $ProductNames,

        [ValidateSet("commercial", "gcc", "gcchigh", "dod")]
        [ValidateNotNullOrEmpty()]
        [string]
        $M365Environment = "commercial",

        [Parameter(Mandatory=$true)]
        [hashtable]
        $BoundParameters
    )

    $ConnectTenantParams = @{
        'ProductNames' = $ProductNames;
        'M365Environment' = $M365Environment
    }

    if ($BoundParameters.AppID) {
        $ServicePrincipalParams = Get-ServicePrincipalParams -BoundParameters $BoundParameters
        $ConnectTenantParams += @{ServicePrincipalParams = $ServicePrincipalParams;}
    }

    if ($LogIn) {
        $AnyFailedAuth = Connect-Tenant @ConnectTenantParams
        $AnyFailedAuth
    }
}

function Compare-ProductList {
    <#
    .Description
    Compares two ProductNames Lists and returns the Diff between them
    Used to compare a failed execution list with the original list
    .Functionality
    Internal
    #>
    param(

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("teams", "exo", "defender", "aad", "powerplatform", "sharepoint", '*', IgnoreCase = $false)]
        [string[]]
        $ProductNames,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("teams", "exo", "defender", "aad", "powerplatform", "sharepoint", '*', IgnoreCase = $false)]
        [string[]]
        $ProductsFailed,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ExceptionMessage
    )

    $Difference = Compare-Object $ProductNames -DifferenceObject $ProductsFailed -PassThru
    if (-not $Difference) {
        throw "$($ExceptionMessage); aborting ScubaGear execution"
    }
    else {
        $Difference
    }
}

function Get-ServicePrincipalParams {
    <#
    .Description
    Returns a valid a hastable of parameters for authentication via
    Service Principal. Throws an error if there are none.
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [hashtable]
    $BoundParameters
    )

    $ServicePrincipalParams = @{}

    $CheckThumbprintParams = ($BoundParameters.CertificateThumbprint) `
    -and ($BoundParameters.AppID) -and ($BoundParameters.Organization)

    if ($CheckThumbprintParams) {
        $CertThumbprintParams = @{
            CertificateThumbprint = $BoundParameters.CertificateThumbprint;
            AppID = $BoundParameters.AppID;
            Organization = $BoundParameters.Organization;
        }
        $ServicePrincipalParams += @{CertThumbprintParams = $CertThumbprintParams}
    }
    else {
        throw "Missing parameters required for authentication with Service Principal Auth; Run Get-Help Invoke-Scuba for details on correct arguments"
    }
    $ServicePrincipalParams
}

function Import-Resources {
    <#
    .Description
    This function imports all of the various helper Provider,
    Rego, and Reporter modules to the runtime
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    param()
    try {
        $ProvidersPath = Join-Path -Path $PSScriptRoot `
        -ChildPath "Providers" `
        -Resolve `
        -ErrorAction 'Stop'
        $ProviderResources = Get-ChildItem $ProvidersPath -Recurse | Where-Object { $_.Name -like 'Export*.psm1' }
        if (!$ProviderResources)
        {
            throw "Provider files were not found, aborting this run"
        }

        foreach ($Provider in $ProviderResources.Name) {
            $ProvidersPath = Join-Path -Path $PSScriptRoot -ChildPath "Providers" -ErrorAction 'Stop'
            $ModulePath = Join-Path -Path $ProvidersPath -ChildPath $Provider -ErrorAction 'Stop'
            Import-Module $ModulePath
        }

        @('Connection', 'RunRego', 'CreateReport', 'ScubaConfig', 'Support') | ForEach-Object {
            $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath $_ -ErrorAction 'Stop'
            Write-Debug "Importing $_ module"
            Import-Module -Name $ModulePath
        }
    }
    catch {
        $ImportResourcesErrorMessage = "Fatal Error involving importing PowerShell modules. `
            Ending ScubaGear execution. See the exception message for more details: $($_)"
            throw $ImportResourcesErrorMessage
    }
}

function Remove-Resources {
    <#
    .Description
    This function cleans up all of the various imported modules
    Mostly meant for dev work
    .Functionality
    Internal
    #>
    [CmdletBinding()]
    $Providers = @("ExportPowerPlatform", "ExportEXOProvider", "ExportAADProvider",
    "ExportDefenderProvider", "ExportTeamsProvider", "ExportSharePointProvider")
    foreach ($Provider in $Providers) {
        Remove-Module $Provider -ErrorAction "SilentlyContinue"
    }

    Remove-Module "ScubaConfig" -ErrorAction "SilentlyContinue"
    Remove-Module "RunRego" -ErrorAction "SilentlyContinue"
    Remove-Module "CreateReport" -ErrorAction "SilentlyContinue"
    Remove-Module "Connection" -ErrorAction "SilentlyContinue"
}



Export-ModuleMember -Function @(
    'Invoke-SCuBA',
    'Invoke-RunCached'
)
