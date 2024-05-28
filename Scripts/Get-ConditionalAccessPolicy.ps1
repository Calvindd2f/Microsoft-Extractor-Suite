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
                
