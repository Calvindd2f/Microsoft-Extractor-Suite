<#
 .SYNOPSIS
 .DESCRIPTION
 ASSUMPTIONS
 1. Due to the necessity for having an application mode it is assumed you have an application registered in Entra and you have the following env variables set:
    $env:AppId
    $env:AppSecret
    $env:AppThumbprint
    $env:TenantId
    $env:EntraBaseUrl
2. If the above is not true, there is a function for creating an applicaiton in Entra via azcli
#>















function CreateSelfSignedCertificate(){
    
    # Remove an existing certificates with the same common name from personal and root stores, if -Force option is set.
    # Need to be very wary of this as could break something
    if($CommonName.ToLower().StartsWith("cn="))
    {
        # Remove CN from common name
        $CommonName = $CommonName.Substring(3)
    }
    $certs = Get-ChildItem -Path Cert:\LocalMachine\my | Where-Object{$_.Subject -eq "CN=$CommonName"}
    if($certs -ne $null -and $certs.Length -gt 0)
    {
        if($Force)
        {
        
            foreach($c in $certs)
            {
                remove-item $c.PSPath
            }
        } else {
            Write-Host -ForegroundColor Red "One or more certificates with the same common name (CN=$CommonName) are already located in the local certificate store. Use -Force to remove existing certificate with the same name and create new one.";
            return $false
        }
    }

    $name = new-object -com "X509Enrollment.CX500DistinguishedName.1"
    $name.Encode("CN=$CommonName", 0)

    $key = new-object -com "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
    $key.KeySpec = 1
    $key.Length = 2048 
    $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $key.MachineContext = 1
    $key.ExportPolicy = 1 # This is required to allow the private key to be exported
    $key.Create()

    $serverauthoid = new-object -com "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1") # Server Authentication
    $ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
    $ekuoids.add($serverauthoid)
    $ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
    $ekuext.InitializeEncode($ekuoids)

    $cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey(2, $key, "")
    $cert.Subject = $name
    $cert.Issuer = $cert.Subject
    $cert.NotBefore = $StartDate
    $cert.NotAfter = $EndDate
    $cert.X509Extensions.Add($ekuext)
    $cert.Encode()

    $enrollment = new-object -com "X509Enrollment.CX509Enrollment.1"
    $enrollment.InitializeFromRequest($cert)
    $certdata = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certdata, 0, "")
    return $true
}
function ExportPFXFile()
{
    if($CommonName.ToLower().StartsWith("cn="))
    {
        # Remove CN from common name
        $CommonName = $CommonName.Substring(3)
    }
    if($Password -eq $null)
    {
        $Password = Read-Host -Prompt "Enter Password to protect private key" -AsSecureString
    }
    $cert = Get-ChildItem -Path Cert:\LocalMachine\my | where-object{$_.Subject -eq "CN=$CommonName"}
    
    Export-PfxCertificate -Cert $cert -Password $Password -FilePath "$($CommonName).pfx"
    Export-Certificate -Cert $cert -Type CERT -FilePath "$CommonName.cer"
}
function RemoveCertsFromStore()
{
    # Once the certificates have been been exported we can safely remove them from the store
    if($CommonName.ToLower().StartsWith("cn="))
    {
        # Remove CN from common name
        $CommonName = $CommonName.Substring(3)
    }
    $certs = Get-ChildItem -Path Cert:\LocalMachine\my | Where-Object{$_.Subject -eq "CN=$CommonName"}
    foreach($c in $certs)
    {
        remove-item $c.PSPath
    }
}
function CreateAppCertificate 
{
    Param(
    [Parameter(Mandatory=$true)]
    [string]$CommonName,

    [Parameter(Mandatory=$true)]
    [DateTime]$StartDate,
    
    [Parameter(Mandatory=$true)]
    [DateTime]$EndDate,

    [Parameter(Mandatory=$false, HelpMessage="Will overwrite existing certificates")]
    [Switch]$Force,

    [Parameter(Mandatory=$false)]
    [SecureString]$Password
    )

    if(CreateSelfSignedCertificate)
    {
        ExportPFXFile >$null 2>&1 
        RemoveCertsFromStore >$null 2>&1 
    }
}
function CreateAppRegistration {
    param (
        [string]$appName = "extractorapp"
    )

    $ProgressPreference = 'SilentlyContinue'; 
    $installUri = "https://aka.ms/installazurecliwindows"
    $installPath = ".\AzureCLI.msi"
    $installArgs = "/I AzureCLI.msi /quiet"
    $rmArgs = ".\AzureCLI.msi"

    try {
        Invoke-WebRequest -Uri $installUri -OutFile $installPath
        Start-Process msiexec.exe -Wait -ArgumentList $installArgs
        Remove-Item -Path $rmArgs

        az login --no-subscription-allowed

        Write-Host "Creating app registration"
        $app = az ad app create --display-name $appName --identifier-uris "http://$appName" | ConvertFrom-Json
        $appId = $app.appId

        Write-Host "Creating service principal for the app"
        az ad sp create --id $appId

        Write-Host "Assigning MS Graph API permissions"
        az ad app permission add --id $appId --api 00000003-0000-0000-c000-000000000000 --api-permissions 7e8c3a1e-2e59-4d3b-950e-c83a7dcca0e3=Role 9a5d0681-1c6f-41b1-a2a1-54c569a8d3a8=Role

        Write-Host "Finding Exchange Online appId"
        $exchangeApp = az ad sp list --filter "displayName eq 'Office 365 Exchange Online'" | ConvertFrom-Json
        $exchangeAppId = $exchangeApp[0].appId

        Write-Host "Assigning Exchange Online API permissions"
        az ad app permission add --id $appId --api $exchangeAppId --api-permissions e1fbdff8-b3de-4869-bc45-ec3d071b250f=Role

        Write-Host "Granting admin consent for MS Graph API permissions"
        az ad app permission grant --id $appId --api 00000003-0000-0000-c000-000000000000 --consent-type AllPrincipals

        Write-Host "Granting admin consent for Exchange Online API permissions"
        az ad app permission grant --id $appId --api $exchangeAppId --consent-type AllPrincipals

        Write-Host "Creating client secret"
        $secret = az ad app credential reset --id $appId --append --credential-description "AppSecret" --years 1 | ConvertFrom-Json
        $clientSecret = $secret.password

        return @{
            appId = $appId
            clientSecret = $clientSecret
        }
    }
    catch {
        Write-Error $_
    }
}




function execute() {
    [console]::WriteLine("1/4 | Creating app registration.")
    try {
        $result = CreateAppRegistration
    } catch {
        Write-Error $_
    }

    [console]::WriteLine("2/4 | Creating self-signed certificate for app registration.")
    try {
        $result = CreateAppCertificate
    } catch {
        Write-Error $_
    }

    [console]::WriteLine("3/4 | Adding permissions and service principals and consenting them.")
    try {
        $result = CreateAppCertificate
    } catch {
        Write-Error $_
    }

    [console]::WriteLine("4/4 | Registering constants & generating tokens.")
    MES.constants()
    [console]::WriteLine("Done!")
    [console]::WriteLine("Generate tokens.")
        try {
            [console]::WriteLine("Generating MSGraph token.")
            $script:token=Get-Token
            if(![string]::IsNullOrEmpty($token)){
                [console]::WriteLine("Generating EXO token.")
                $script:exo_token=Get-Token -UseExchangeOnline
                if(![string]::IsNullOrEmpty($exo_token)){
                    [console]::WriteLine("Generating msgraph_token.")
                    $script:msgraph_token=Get-Token
                }
            }
        }
        catch {
            Write-Error $_
        }
        finally {
            [console]::WriteLine("Tests passed, clearing temporary variables")
            $null=@('$token','$exo_token','$msgraph_token')
        }
    }


function MES.constants() {
    [console]::WriteLine("Registering constants.")
    try 
    {
        [console]::WriteLine("Registering...")
        New-Variable -Force -Option Constant -Name 'appID' -Value           "$env:appID"
        New-Variable -Force -Option Constant -Name 'appSecret' -Value       "$env:appSecret"
        New-Variable -Force -Option Constant -Name 'appThumbprint' -Value   "$env:appThumbprint"
        New-Variable -Force -Option Constant -Name 'tenantID' -Value        "$env:tenantID"
        New-Variable -Force -Option AllScope -Name 'EntraBaseUrl' -Value    "$env:EntraBaseUrl"
        New-Variable -Force -Option AllScope -Name 'msgraph_token' -Value   "$env:msgraph_token"
        New-Variable -Force -Option AllScope -Name 'exo_token' -Value       "$env:exo_token"
        New-Variable -Force -Option AllScope -Name 'token'     -Value       "$msgraph_token"
    } catch {
        Write-Error $_
    }
}
function New-UALQuery 
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory=$true)]
        [DateTime]$StartDate,

        [Parameter(Mandatory=$true)]
        [DateTime]$EndDate,

        [Parameter(Mandatory=$false)]
        [string[]]$Operations = $null,

        [Parameter(Mandatory=$false)]
        [string]$SearchName = ("Extractor Suite : Audit Search {0}" -f (Get-Date -format 'dd-MMM-yyyy HH:mm'))
    )

    $UALQueryParams = @{
        StartDateSearch  = (Get-Date $StartDate -format s) + "Z"
        EndDateSearch    = (Get-Date $EndDate -format s) + "Z"
        Operations       = $Operations
        SearchName       = $SearchName
        SearchParameters = @{
            "displayName"         = $SearchName
            "filterStartDateTime" = $StartDateSearch
            "filterEndDateTime"   = $EndDateSearch
            "operationFilters"    = $Operations
        }
    }

    $AdditionalFilters = @{
        keywordFilter               = $null
        administrativeUnitIdFilters = $null
        objectIdFilters             = $null
        recordTypeFilters           = $null
        ipAddressFilters            = $null
        userPrincipalNameFilters    = $null
        serviceFilters              = $null
    }

    $UALQueryParams.SearchParameters.Add("additionalFilters", $AdditionalFilters)

    return $UALQueryParams
}

    #region IsApplication or Delegate

    # Check if $IsApplication is not null before performing the switch operation to avoid null reference exception
    if ($PSBoundParameters.ContainsKey('IsApplication')) 
    {
        switch ($IsApplication) 
        {
            true {
                New-Alias -Name Invoke-MgGraphRequest -Value Invoke-RestMethod -Option Constant -Force
                $script:chk_token = $true
            }
            false {break}
            Default {break}
        }
    }

    if($script:chk_token)
    {
        $exo_token
        $msgraph_token
    }

    











function MES.Application()
{

}
function MES.Application.Template($data, $retry=5,$Api_Url) 
{
    $json = $data | ConvertTo-Json -Depth 10
    Write-Host $json
    $success = $false
    $WaitTime = 30
    $RetryCount = 0    
    $RetryCodes = @(503, 504, 520, 521, 522, 524)
    while ($RetryCount -lt $retry -and $success -eq $false) {
        try{
            $request = [System.Net.HttpWebRequest]::Create("$Api_Url")
        
        	$request.Method = "POST";
        	$request.ContentType = "application/json";
        	#$authBytes = [System.Text.Encoding]::UTF8.GetBytes($Api_Token);
        	#$authStr = "Basic " + $([System.Convert]::ToBase64String($authBytes));
            $authStr = "Bearer $Api_Token"
        	$request.Headers["Authorization"] = $authStr;
        	$request.Headers["clientId"] = $CW_Api_Client_Id;
        	$request.Timeout = 10000
        	
        	$requestWriter = New-Object System.IO.StreamWriter $request.GetRequestStream();
        	$requestWriter.Write($json);
        	$requestWriter.Flush();
        	$requestWriter.Close();
        	$requestWriter.Dispose();
    
    	    $response = $request.GetResponse();
    	    $response.Dispose();
            $success = $true
            return $response
        } catch {
            Write-Host "WARNING: $($_.Exception.Message)"
            $ErrorCode = $_.Exception.InnerException.Response.StatusCode
            if ($ErrorCode -in $RetryCodes){
                $RetryCount++

                if ($RetryCount -eq $retry) {
                    Write-host "WARNING: Retry limit reached." 
                } else {
                    Write-host "Waiting $WaitTime seconds."
                    Start-Sleep -seconds $WaitTime
                    Write-host "Retrying."                    
                }

            } else {
                return $null;
            }
        }
    }
}
function MES.Delegate()
{
    
}