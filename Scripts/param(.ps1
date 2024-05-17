using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

<#
New Potential Variables for script
#>
function fuck(){
    <#
.SYNOPSIS
    Execute the SCuBAGear tool security baselines for specified M365 products.
    .Description
    This is the main function that runs the Providers, Rego, and Report creation all in one PowerShell script call.

    .Parameter OutPath
    The folder path where both the output JSON and the HTML report will be created.
    The folder will be created if it does not exist. Defaults to current directory.

    .Parameter OutFolderName
    The name of the folder in OutPath where both the output JSON and the HTML report will be created.
    Defaults to "M365BaselineConformance". The client's local timestamp will be appended.

    .Parameter MergeJson
    Set switch to merge all json output into a single file and delete the individual files
    after merging.
    
	.Example
    Invoke-
    
    .Functionality
    Public
    #>
    [string]$OutPath = [ScubaConfig]::ScubaDefault('DefaultOutPath'),
    [string]$OutFolderName = [ScubaConfig]::ScubaDefault('DefaultOutFolderName'),
    [switch]$MergeJson,
    [string]$OutJsonFileName = [ScubaConfig]::ScubaDefault('DefaultOutJsonFileName'),
    [Parameter(Mandatory = $true, ParameterSetName = 'Configuration')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (-Not ($_ | Test-Path)){
                throw "SCuBA configuration file or folder does not exist. $_"
            }
            if (-Not ($_ | Test-Path -PathType Leaf)){
                throw "SCuBA configuration Path argument must be a file."
            }
            return $true
        })]
        [System.IO.FileInfo]
        $ConfigFilePath,

    
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

$InputFile = Join-Path -Path $OutFolderPath "$($OutProviderFileName).json" -ErrorAction 'Stop'
$FileName = Join-Path -Path $OutFolderPath "$($OutRegoFileName).json" -ErrorAction 'Stop'
$TestResultsJson | Set-Content -Path $FileName -Encoding $(Get-FileEncoding) -ErrorAction 'Stop'

$TestResultsCsv = $TestResults | ConvertTo-Csv -NoTypeInformation -ErrorAction 'Stop'
$CSVFileName = Join-Path -Path $OutFolderPath "$($OutRegoFileName).csv" -ErrorAction 'Stop'
$TestResultsCsv | Set-Content -Path $CSVFileName -Encoding $(Get-FileEncoding) -ErrorAction 'Stop'



$ParentPath = Split-Path $PSScriptRoot -Parent
$ScubaManifest = Import-PowerShellDataFile (Join-Path -Path $ParentPath -ChildPath 'ScubaGear.psd1' -Resolve)
$ModuleVersion = $ScubaManifest.ModuleVersion

# Create outpath if $Outpath does not exist
if(-not (Test-Path -PathType "container" $OutPath))
{
    New-Item -ItemType "Directory" -Path $OutPath | Out-Null
}
$OutFolderPath = $OutPath




$GraphScopes = (
                       'User.Read.All',
                       'Policy.Read.All',
                       'Organization.Read.All',
                       'RoleManagement.Read.Directory',
                       'GroupMember.Read.All',
                       'Directory.Read.All',
                       'PrivilegedEligibilitySchedule.Read.AzureADGroup',
                       'PrivilegedAccess.Read.AzureADGroup',
                       'RoleManagementPolicy.Read.AzureADGroup'
    )
 $GraphParams = @{
     'ErrorAction' = 'Stop';
 }
 if ($ServicePrincipalParams.CertThumbprintParams) {
     $GraphParams += @{
         CertificateThumbprint = $ServicePrincipalParams.CertThumbprintParams.CertificateThumbprint;
         ClientID = $ServicePrincipalParams.CertThumbprintParams.AppID;
         TenantId  = $ServicePrincipalParams.CertThumbprintParams.Organization; # Organization also works here
     }
 }
 else {
     $GraphParams += @{Scopes = $GraphScopes;}
}
Connect-MgGraph @GraphParams | Out-Null
$AADAuthRequired = $false






if ($EXOAuthRequired) {
$EXOParams = @{
        ErrorAction = "Stop";
        ShowBanner = $false;
    }
    if ($ServicePrincipalParams) {
        $EXOHeParams += @{ServicePrincipalParams = $ServicePrincipalParams}
    }
        if ($ServicePrincipalParams.CertThumbprintParams) {
        $EXOParams += $ServicePrincipalParams.CertThumbprintParams
    }
 Connect-ExchangeOnline @EXOParams | Out-Null