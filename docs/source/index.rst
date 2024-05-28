# Install required modules
Install-Module Connect-ExchangeOnline -Force
Install-Module Connect-AzureAD -Force

# Install Microsoft-Extractor-Suite toolkit
Install-Module Microsoft-Extractor-Suite -Force


Import-Module Microsoft-Extractor-Suite


Connect-ExchangeOnline -UserPrincipalName user@domain.com -ShowBanner:$false
Connect-AzureAD -UserPrincipalName user@domain.com -TenantId "tenant_id" -ShowBanner:$false
