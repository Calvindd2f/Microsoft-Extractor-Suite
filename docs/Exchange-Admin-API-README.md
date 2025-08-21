# Exchange Online Beta Admin API Integration

This document describes the new Exchange Online beta admin API integration in the Microsoft Extractor Suite, which allows you to invoke Exchange Online PowerShell cmdlets directly through the REST API.

## Overview

The Exchange Online beta admin API provides a REST interface to execute PowerShell cmdlets remotely. This integration replaces the previous direct REST API calls with a more standardized approach using the `/InvokeCommand` endpoint.

## Key Features

- **InvokeCommand Endpoint**: Execute any Exchange Online PowerShell cmdlet via REST API
- **Automatic Parameter Handling**: Convert C# parameters to PowerShell parameter format
- **Response Parsing**: Automatically parse cmdlet output into strongly-typed objects
- **Fallback Support**: Graceful fallback to Graph API when Exchange API is unavailable
- **Rate Limiting**: Built-in rate limiting and retry logic
- **Error Handling**: Comprehensive error handling with detailed error messages

## API Endpoint

```
POST https://outlook.office365.com/adminapi/beta/{tenantId}/InvokeCommand
```

## Request Format

```json
{
  "CmdletInput": {
    "Cmdlet": "Search-UnifiedAuditLog",
    "Parameters": {
      "StartDate": "2025-01-01T00:00:00Z",
      "EndDate": "2025-01-31T23:59:59Z",
      "ResultSize": 1000,
      "UserIds": ["user@domain.com"]
    }
  }
}
```

## Supported Cmdlets

### Audit and Compliance
- `Search-UnifiedAuditLog` - Search unified audit logs
- `Search-MailboxAuditLog` - Search mailbox audit logs
- `Search-AdminAuditLog` - Search admin audit logs

### Mail Flow
- `Get-MessageTrace` - Get message trace logs
- `Get-TransportRule` - Get transport rules
- `Get-MailFlowRule` - Get mail flow rules

### Mailbox Management
- `Get-Mailbox` - Get mailbox information
- `Get-InboxRule` - Get inbox rules
- `Get-MailboxPermission` - Get mailbox permissions
- `Get-RecipientPermission` - Get recipient permissions
- `Get-SendAsPermission` - Get send-as permissions

### Distribution and Groups
- `Get-DistributionGroup` - Get distribution groups
- `Get-RetentionPolicy` - Get retention policies

## Usage Examples

### Basic InvokeCommand Usage

```csharp
var exchangeClient = new ExchangeRestClient(authManager);

// Execute a simple cmdlet
var result = await exchangeClient.InvokeCommandAsync("Get-Mailbox");

// Execute with parameters
var parameters = new Dictionary<string, object>
{
    ["Identity"] = "user@domain.com",
    ["ResultSize"] = 100
};
var result = await exchangeClient.InvokeCommandAsync("Get-Mailbox", parameters);
```

### Search Unified Audit Log

```csharp
var startDate = DateTime.UtcNow.AddDays(-7);
var endDate = DateTime.UtcNow;

var auditLogs = await exchangeClient.SearchUnifiedAuditLogAsync(
    startDate,
    endDate,
    resultSize: 1000
);
```

### Get Message Trace

```csharp
var messageTraces = exchangeClient.GetMessageTraceAsync(
    startDate,
    endDate,
    senderAddress: "sender@domain.com"
);

await foreach (var trace in messageTraces)
{
    // Process each message trace
}
```

### Get Mailbox Audit Log

```csharp
var auditLogs = exchangeClient.GetMailboxAuditLogAsync(
    "user@domain.com",
    startDate,
    endDate,
    operations: new[] { "MailboxLogin", "HardDelete" }
);

await foreach (var log in auditLogs)
{
    // Process each audit log entry
}
```

## Response Format

The API returns responses in the following format:

```json
{
  "Results": [
    {
      "ObjectId": "guid",
      "Output": "cmdlet output as JSON string",
      "ErrorDetails": null,
      "HasErrors": false,
      "HasWarnings": false,
      "Warnings": []
    }
  ],
  "Errors": [],
  "Warnings": [],
  "HasErrors": false,
  "HasWarnings": false
}
```

## Error Handling

The integration includes comprehensive error handling:

- **Authentication Errors**: Clear messages about token issues
- **Permission Errors**: Specific guidance on required Exchange permissions
- **API Errors**: Detailed error messages from Exchange Online
- **Parsing Errors**: Graceful fallback when JSON parsing fails
- **Rate Limiting**: Automatic retry with exponential backoff

## Authentication Requirements

To use the Exchange Online beta admin API, you need:

1. **Exchange Online Management** permissions
2. **Delegated permissions** for the specific operations
3. **Admin consent** if using application permissions
4. **Valid access token** with appropriate scopes

### Required Scopes

- `https://outlook.office365.com/.default` - Exchange Online Management
- `User.Read.All` - User information access
- `Mail.Read.All` - Mail access
- `AuditLog.Read.All` - Audit log access

## Rate Limiting

The integration includes built-in rate limiting:

- **Concurrent Requests**: Maximum 20 concurrent requests
- **Requests per Minute**: Maximum 300 requests per minute
- **Automatic Retry**: Exponential backoff for failed requests
- **429 Handling**: Automatic handling of rate limit responses

## Fallback Mechanisms

When the Exchange Online API is unavailable, the integration falls back to:

1. **Graph API**: For basic user and mailbox information
2. **Cached Results**: When available from previous requests
3. **Error Reporting**: Clear error messages for troubleshooting

## Testing

Use the provided test script to verify functionality:

```powershell
.\Scripts\Test-ExchangeInvokeCommand.ps1 -Verbose
```

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Verify Exchange Online permissions
   - Check token expiration
   - Ensure admin consent is granted

2. **Permission Denied**
   - Verify Exchange Administrator role
   - Check specific cmdlet permissions
   - Ensure tenant has Exchange Online

3. **API Not Found**
   - Verify Exchange Online is enabled
   - Check tenant configuration
   - Ensure beta API access

4. **Rate Limiting**
   - Reduce concurrent requests
   - Implement proper delays
   - Use batch operations

### Debug Information

Enable verbose logging to see detailed API calls:

```csharp
// Enable console logging
Console.WriteLine($"Invoking Exchange cmdlet: {cmdlet}");
Console.WriteLine($"Request body: {JsonSerializer.Serialize(requestBody)}");
```

## Performance Considerations

- **Batch Operations**: Use appropriate result sizes
- **Pagination**: Implement proper pagination for large datasets
- **Caching**: Cache frequently accessed data
- **Parallel Processing**: Use async/await for concurrent operations

## Security Notes

- **Token Security**: Never log or expose access tokens
- **Parameter Validation**: Validate all input parameters
- **Error Information**: Avoid exposing sensitive information in error messages
- **Audit Logging**: Log all API calls for compliance

## Future Enhancements

- **Cmdlet Discovery**: Automatic discovery of available cmdlets
- **Parameter Validation**: Server-side parameter validation
- **Batch Operations**: Support for multiple cmdlet execution
- **Real-time Updates**: WebSocket support for real-time data
- **Advanced Filtering**: Enhanced filtering and search capabilities
