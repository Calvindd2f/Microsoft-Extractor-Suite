# DeletegatedAccessTokenGraph.ps1
try {
Connect-MgGraph -TenantId $env:TenantId -ClientId $env:ClientId -ClientSecret $env:ClientSecret
break
} catch {
    Connect-MgGraph -DeviceCode
    continue
}
$request=(Invoke-MgGraphRequest -Method get -Uri 'https://graph.microsoft.com/beta/users' -OutputType HttpResponseMessage).RequestMessage
$access_token = $request.Headers.Authorization.Parameter
