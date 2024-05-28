Install-Module -Name Microsoft-Extractor-Suite


Import-Module -Name Microsoft-Extractor-Suite


Connect-ExchangeOnline -UserPrincipalName user@domain.com -ShowBanner:$false
Connect-AzureAD -UserPrincipalName user@domain.com -ShowBanner:$false



Replace `<username>` with the actual GitHub repository owner's username.
