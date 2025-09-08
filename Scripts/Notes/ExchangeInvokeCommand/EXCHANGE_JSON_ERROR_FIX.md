# Fix for Exchange API JSON Parsing Error

## Problem
Error: `The input does not contain any JSON tokens. Expected the input to start with a valid JSON token`

This error occurs when the Exchange Admin API returns HTML (error page) instead of JSON data.

## Root Causes

1. **Incorrect Authentication**: Using wrong client ID or token
2. **Wrong API Endpoint**: The URL format may be incorrect
3. **Missing Permissions**: Global Admin role doesn't automatically grant API access
4. **Tenant Configuration**: Exchange Online may not be properly configured

## Fixes Applied

### 1. Enhanced Error Handling
Added detection for non-JSON responses in `ExchangeRestClient.cs`:
- Checks if response starts with `{` or `[` (JSON markers)
- Provides detailed error messages with response preview
- Logs URL and request details for debugging

### 2. Better Authentication Flow
- Uses official Exchange Online Management client ID: `fb78d390-0c51-40cd-8e17-fdbfab77341b`
- Separate authentication method: `ConnectExchangeOnlineAsync()`
- Proper scope: `https://outlook.office365.com/.default`

### 3. Improved Logging
- Logs the actual URL being called
- Shows request body
- Displays response status and headers on error
- Shows response content preview for debugging

## How to Use

### Step 1: Close PowerShell and Rebuild
```bash
# Close any PowerShell sessions using the module
# Then rebuild:
~/.dotnet/dotnet clean src/Microsoft.ExtractorSuite.csproj
~/.dotnet/dotnet build src/Microsoft.ExtractorSuite.csproj
```

### Step 2: Connect with Exchange Online
```powershell
# Import the module
Import-Module ./src/bin/Debug/netstandard2.0/Microsoft.ExtractorSuite.dll

# Connect with Exchange Online flag
Connect-M365 -TenantId "your-tenant-id" -ExchangeOnline -Verbose

# The -Verbose flag will show:
# - Which client ID is being used
# - Authentication progress
# - Any connection issues
```

### Step 3: Test with Verbose Output
```powershell
# Run with verbose to see API calls
Get-MailboxAuditLog -UserIds "user@domain.com" -Verbose

# This will now show:
# - The exact URL being called
# - Request body sent
# - Error details if non-JSON response
```

## What the Error Messages Tell You

### "Exchange API returned non-JSON response"
- **Meaning**: Got HTML instead of JSON
- **Check**: Authentication and endpoint URL
- **Action**: Reconnect with `-ExchangeOnline` flag

### "Access denied to Exchange Online Management API"
- **Meaning**: Token valid but lacks permissions
- **Check**: User has Exchange Administrator role
- **Action**: Grant appropriate admin roles

### "Exchange Online Management API endpoint not found"
- **Meaning**: The API endpoint doesn't exist
- **Check**: Tenant has Exchange Online licensed
- **Action**: Verify Exchange Online configuration

### "Authentication failed for Exchange API"
- **Meaning**: Token is invalid or expired
- **Action**: Run `Connect-M365 -ExchangeOnline` again

## Debugging Tips

1. **Check the Console Output**: The improved error handling shows:
   - Actual URL called
   - Response status code
   - First 500 characters of response

2. **Verify Token**: After connecting, check if Exchange token exists:
   ```powershell
   # The module will indicate if using Graph token (limited) or Exchange token (full)
   ```

3. **Test Graph API First**: If Exchange API fails, test if Graph API works:
   ```powershell
   # This uses Graph API instead of Exchange Admin API
   Get-Emails -UserIds "user@domain.com"
   ```

## Alternative: Use Graph API
If Exchange Admin API continues to fail, use Graph API alternatives:
- `Get-Emails` instead of message trace
- `Get-MailboxSettings` for mailbox configuration
- Graph API audit logs instead of Exchange audit logs

## Next Steps
If errors persist after these fixes:
1. Verify Exchange Online is activated for your tenant
2. Check if Conditional Access policies block the app
3. Ensure MFA is completed during authentication
4. Try with a different Global Admin account