<#
.SYNOPSIS
Retrieves the conditional access policies from Microsoft Graph API

.DESCRIPTION
This command retrieves all the conditional access policies from Microsoft Graph API and exports them to a CSV or JSON file.

.PARAMETER OutputDir
Specifies the output directory for the CSV/JSON file. Default is 'UserInfo' directory within the 'Output' directory.

.PARAMETER OutputFile
Specifies the output file name. Default is 'ConditionalAccessPolicies_yyyy-MM-dd.csv'.

