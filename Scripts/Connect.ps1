Function Connect-M365
{
	PARAM(
		[string]
		$ConnectionUri,
		[string]
		$AzureADAuthorizationEndpointUri,
		[ValidateSet('O365China', 'O365Default', 'O365GermanyCloud', 'O365USGovDoD', 'O365USGovGCCHigh')]
		[ExchangeEnvironment]
		$ExchangeEnvironmentName,
		[PSSessionOptions]
		$PSSessionOptions,
		[string]
		$DelegatedOrganization,
		[string]
		$Prefix,
		[string[]]
		$CommandName,
		[string[]]
		$FormatTypeName,
		[string]
		$AccessToken,
		[string]
		$AppId,
		[switch]
		$BypassMailboxAnchoring,
		[X509Certificate2]
		$Certificate,
		[string]
		$CertificateFilePath,
		[SecureString]
		$CertificatePassword,
		[string]
		$CertificateThumbprint,
		[PSCredential]
		$Credential,
		[switch]
		$Device,
		[switch]
		$EnableErrorReporting,
		[switch]
		$InlineCredential,
		[string]
		$LogDirectoryPath,
		[string]
		$LogLevel,
		[switch]
		$ManagedIdentity,
		[string]
		$ManagedIdentityAccountId,
		[string]
		$Organization,
		[uin32]
		$PageSize,
		[switch]
		$ShowBanner,
		[X509Certificate2]
		$SigningCertificate,
		[switch]
		$SkipLoadingCmdletHelp,
		[switch]
		$SkipLoadingFormatData,
		[Boolean]
		$TrackPerformance,
		[Boolean]
		$UseMultithreading,
		[string]
		$UserPrincipalName,
		[Switch]
		$UseRPSSession
	)
	versionCheck
	Connect-ExchangeOnline @PSBoundParameters > $null;
}

Function Connect-Azure
{
	PARAM(
		[ValidateSet('AzureChinaCloud', 'AzureCloud', 'AzureGermanyCloud', 'AzurePPE', 'AzureUSGovernment', 'AzureUSGovernment2', 'AzureUSGovernment3')]
		[AzureEnvironment+EnvironmentName]
		$AzureEnvironmentName,
		[string]
		$TenantId,
		[pscredential]
		$Credential,
		[string]
		$CertificateThumbprint,
		[string]
		$ApplicationId,
		[string]
		$AadAccessToken,
		[string]
		$MsAccessToken,
		[string]
		$AccountId,
		[ValidateSet('Error', 'Info', 'None', 'Warning')]
		[LogLevel]
		$LogLevel,
		[string]
		$LogFilePath,
		[switch]
		$WhatIf,
		[switch]
		$Confirm,
		[Switch]
		$Verbose,
		[switch]
		$Debug
	)
	versionCheck
	Connect-AzureAD @PSBoundParameters > $null;
}

Function Connect-AzureAZ
{
	PARAM(
		[String]
		$AccessToken ,
		[String]
		$AccountId ,
		[String]
		$ApplicationId ,
		[String]
		$AuthScope ,
		[SecureString]
		$CertificatePassword,
		[String]
		$CertificatePath ,
		[String]
		$CertificateThumbprint ,
		[String]
		$ContextName ,
		[PSCredential]
		$Credential,
		[IAzureContextContainer]
		$DefaultProfile ,
		[String]
		$Environment ,
		[String]
		$FederatedToken ,
		[switch]
		$Force ,
		[String]
		$GraphAccessToken ,
		[switch]
		$Identity,
		[String]
		$KeyVaultAccessToken ,
		[int]
		$MaxContextPopulation,
		[String]
		$MicrosoftGraphAccessToken ,
		[ValidateSet('CurrentUser', 'Process')]
		[ContextModificationScope]
		$Scope,
		[switch]
		$SendCertificateChain,
		[switch]
		$ServicePrincipal,
		[switch]
		$SkipContextPopulation ,
		[switch]
		$SkipValidation ,
		[String]
		$Subscription ,
		[String]
		$Tenant ,
		[switch]
		$UseDeviceAuthentication,
		[switch]
		$Confirm,
		[switch]
		$WhatIf
	)
	versionCheck
	Connect-AzAccount @PSBoundParameters > $null;
}

