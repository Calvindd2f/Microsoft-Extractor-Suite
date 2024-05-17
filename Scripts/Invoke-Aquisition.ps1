using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

using namespace System.Net

function Invoke-Aquisition([string]$user, [string]$OutputDir, [string]$Encoding)
{
	$jobs=@();
}



[pscustomobject]@{
	Name = 'thing1'
	Value = 'value1'
}

$Request.Query.GetEnumerator() | ForEach-Object {
	New-Variable -Name $_.Key -Value $_.Value
}

$response = @{
	Body = "The name passed was [$Name] with value of [$Value]
}