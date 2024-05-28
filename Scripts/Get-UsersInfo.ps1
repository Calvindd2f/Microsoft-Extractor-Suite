# Load required functions and modules
. "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

Function Get-CurrentDate {
    return Get-Date -Format "yyyyMMddHHmm"
}

Function Write-LogFile($message, $color = "White") {
    $colorCode = switch ($color) {
        "Green"   { 2 }
        "Yellow"  { 3 }
        "Red"     { 4 }
        "Blue"    { 9 }
        default   { 7 }
    }
    Write-Host ("[" + (Get-Host).UI.RawUI.ForegroundColor + "]" + $message + "[-]") -NoNewline
    [console]::ForegroundColor = $colorCode
    Write-Host " $message"
    [console]::ForegroundColor = "Green"
}

Function Get-MicrosoftGraphToken {
    # Placeholder for getting the Microsoft Graph token
}

Function Get-Users {
    # ... (same as original code)
}

Function Get-UserCreationStats {
    # ... (same as original code)
}

Function Get-AdminUsers {
    # ... (same as original code)
}

Function Merge-AdminCsvFiles {
    # ... (same as original code)
}

# Get the Microsoft Graph token
$token = Get-MicrosoftGraphToken

# Call the functions
Get-Users -OutputDir "Output\UserInfo" -Encoding "UTF8"
Get-UserCreationStats -Users $allUsers
Get-AdminUsers -OutputDir "Output\UserInfo" -Encoding "UTF8"
