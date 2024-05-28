# Load required module
Import-Module Microsoft.Graph.Identity.Policy.ConditionalAccess

<#
.SYNOPSIS
Retrieves the conditional access policies from Microsoft Graph API

.DESCRIPTION
This command retrieves all the conditional access policies from Microsoft Graph API and exports them to a CSV or JSON file.

.PARAMETER OutputDir
Specifies the output directory for the CSV/JSON file. Default is 'UserInfo' directory within the 'Output' directory.

