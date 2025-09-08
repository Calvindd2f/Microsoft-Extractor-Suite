# Exchange Admin API Authentication Guide

## Overview
This module now properly supports the Exchange Admin API using the official Exchange Online Management client ID (`fb78d390-0c51-40cd-8e17-fdbfab77341b`), which is the same ID used by the Exchange Online PowerShell V3 module.

## Authentication Methods

### Method 1: Exchange Online Management (Recommended for Global Admins)
```powershell
# Connect with Exchange Online Management
Connect-M365 -TenantId "your-tenant-id" -ExchangeOnline

# This uses the official Exchange client ID and prompts for authentication
# Global Admins will have full access to Exchange Admin API endpoints
```

### Method 2: Graph API Only (Limited Exchange Operations)
```powershell
# Connect with Graph API only
Connect-M365 -TenantId "your-tenant-id"

# This provides access to mail operations through Graph API
# Limited to Graph API mail endpoints, not full Exchange Admin API
```

## Exchange Admin API Endpoints

When properly authenticated with the Exchange Online Management client ID, you can access:

### Admin API Endpoints (`https://outlook.office365.com/adminapi/beta`)
- **Search-UnifiedAuditLog** - Full audit log search capabilities
- **Get-MessageTrace** - Message trace operations
- **Get-Mailbox** - Mailbox management
- **Set-Mailbox** - Mailbox configuration
- **Get-MailboxPermission** - Permission management
- **Get-RecipientPermission** - Recipient permissions
- **Get-TransportRule** - Transport rules

### Requirements for Exchange Admin API

1. **User Requirements**:
   - Global Administrator role OR
   - Exchange Administrator role OR
   - Specific Exchange management roles

2. **Tenant Requirements**:
   - Exchange Online license
   - Exchange Online configured for the tenant

3. **Authentication Flow**:
   ```
   User → Exchange Client ID (fb78d390-0c51-40cd-8e17-fdbfab77341b)
        → OAuth2 with scope: https://outlook.office365.com/.default
        → Exchange Admin API Access
   ```

## Troubleshooting

### Error: "Access denied to Exchange Online Management API"
**Solution**: Ensure your account has one of these roles:
- Global Administrator
- Exchange Administrator
- Compliance Administrator (for audit logs)

### Error: "Exchange Online Management API endpoint not found"
**Solution**: Verify Exchange Online is properly licensed and configured for your tenant.

### Error: "Failed to obtain Exchange Online access token"
**Solution**: The authentication flow requires:
1. Interactive authentication (cannot be fully automated)
2. MFA may be required based on tenant policies
3. Conditional Access policies may apply

## Code Implementation Details

### Authentication Manager Changes
- Added `ExchangeClientId = "fb78d390-0c51-40cd-8e17-fdbfab77341b"`
- Implemented `ConnectExchangeOnlineAsync()` method
- Separate token storage for Exchange (`_exchangeAuthResult`)

### ExchangeRestClient Usage
```csharp
// The client now properly authenticates using Exchange tokens
var token = await _authManager.GetExchangeOnlineTokenAsync();
// This will:
// 1. Check for valid Exchange token
// 2. If none, attempt ConnectExchangeOnlineAsync
// 3. Fall back to Graph token for basic mail operations
```

## Cmdlet Examples

After successful Exchange Online authentication:

```powershell
# Search audit logs (requires Exchange Admin API)
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

# Get message trace (requires Exchange Admin API)
Get-MessageTraceLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date)

# Get mailbox audit logs
Get-MailboxAuditLog -UserIds "user@domain.com"

# Get transport rules
Get-TransportRules

# These work with Graph API fallback:
Get-Emails -UserIds "user@domain.com"
Get-MailboxSettings -UserIds "user@domain.com"
```

## Security Notes

1. The Exchange Online Management client ID is a Microsoft first-party application
2. It requires explicit user consent for the `https://outlook.office365.com/.default` scope
3. Tokens are cached securely using MSAL token cache
4. MFA and Conditional Access policies are enforced

## References
- [Exchange Online PowerShell V3](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2)
- [Exchange Admin API](https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-authenticate-an-ews-application-by-using-oauth)
- Client ID Source: Official Microsoft Exchange Online Management module