using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core.Authentication;
using Microsoft.ExtractorSuite.Models.Exchange;
using Polly;
using Polly.Extensions.Http;

namespace Microsoft.ExtractorSuite.Core.Exchange
{
    /// <summary>
    /// Direct REST API client for Exchange Online without ExchangeOnlineManagement module dependency
    /// Uses Exchange REST API v2.0 and Admin API endpoints
    /// </summary>
    public class ExchangeRestClient : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly AuthenticationManager _authManager;
        private readonly IAsyncPolicy<HttpResponseMessage> _retryPolicy;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly SemaphoreSlim _rateLimitSemaphore;
        
        // Exchange Online REST API endpoints
        private const string ExchangeRestBaseUrl = "https://outlook.office365.com/api/v2.0";
        private const string ExchangeAdminApiUrl = "https://outlook.office365.com/adminapi/beta";
        private const string ComplianceApiUrl = "https://compliance.microsoft.com/api";
        private const string EwsUrl = "https://outlook.office365.com/EWS/Exchange.asmx";
        
        // Rate limiting
        private const int MaxConcurrentRequests = 20;
        private const int RequestsPerMinute = 300;
        private readonly Queue<DateTime> _requestTimestamps = new();
        private readonly object _rateLimitLock = new();
        
        public ExchangeRestClient(AuthenticationManager authManager)
        {
            _authManager = authManager;
            _rateLimitSemaphore = new SemaphoreSlim(MaxConcurrentRequests, MaxConcurrentRequests);
            
            // Configure HttpClient with optimal settings
            var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                MaxConnectionsPerServer = 50,
                UseProxy = false
            };
            
            _httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromMinutes(5), // Long timeout for large operations
                DefaultRequestHeaders =
                {
                    Accept = { new MediaTypeWithQualityHeaderValue("application/json") },
                    UserAgent = { new ProductInfoHeaderValue("Microsoft-Extractor-Suite", "4.0.0") }
                }
            };
            
            // Configure retry policy with exponential backoff
            _retryPolicy = HttpPolicyExtensions
                .HandleTransientHttpError()
                .OrResult(msg => msg.StatusCode == HttpStatusCode.TooManyRequests)
                .WaitAndRetryAsync(
                    5,
                    retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)),
                    onRetry: (outcome, timespan, retryCount, context) =>
                    {
                        var reason = outcome.Result?.StatusCode.ToString() ?? outcome.Exception?.Message;
                        Console.WriteLine($"Retry {retryCount} after {timespan}s: {reason}");
                    });
            
            // Configure System.Text.Json for optimal performance
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                Converters =
                {
                    new JsonStringEnumConverter(JsonNamingPolicy.CamelCase),
                    new DateTimeOffsetConverter()
                }
            };
        }
        
        #region Unified Audit Log via REST API
        
        public async Task<UnifiedAuditLogResult> SearchUnifiedAuditLogAsync(
            DateTime startDate,
            DateTime endDate,
            string? sessionId = null,
            string[]? operations = null,
            string[]? recordTypes = null,
            string[]? userIds = null,
            int resultSize = 5000,
            CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);
            
            var requestBody = new
            {
                StartDate = startDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"),
                EndDate = endDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"),
                SessionId = sessionId ?? Guid.NewGuid().ToString(),
                SessionCommand = sessionId == null ? "ReturnNextPreviewPage" : "ReturnNextPreviewPage",
                ResultSize = resultSize,
                Operations = operations,
                RecordTypes = recordTypes,
                UserIds = userIds
            };
            
            var url = $"{ExchangeAdminApiUrl}/{_authManager.CurrentTenantId}/ActivityFeed/SearchUnifiedAuditLog";
            
            using var content = new StringContent(
                JsonSerializer.Serialize(requestBody, _jsonOptions),
                Encoding.UTF8,
                "application/json");
            
            var response = await ExecuteWithRetryAsync(
                () => _httpClient.PostAsync(url, content, cancellationToken),
                cancellationToken);
            
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<UnifiedAuditLogResult>(json, _jsonOptions)!;
        }
        
        #endregion
        
        #region Message Trace via REST API
        
        public async IAsyncEnumerable<MessageTraceResult> GetMessageTraceAsync(
            DateTime startDate,
            DateTime endDate,
            string? senderAddress = null,
            string? recipientAddress = null,
            string? messageId = null,
            int pageSize = 5000,
            CancellationToken cancellationToken = default)
        {
            var page = 1;
            bool hasMoreData;
            
            do
            {
                await ThrottleRequestAsync(cancellationToken);
                
                var queryParams = new Dictionary<string, string>
                {
                    ["StartDate"] = startDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"),
                    ["EndDate"] = endDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"),
                    ["$top"] = pageSize.ToString(),
                    ["Page"] = page.ToString()
                };
                
                if (!string.IsNullOrEmpty(senderAddress))
                    queryParams["SenderAddress"] = senderAddress;
                if (!string.IsNullOrEmpty(recipientAddress))
                    queryParams["RecipientAddress"] = recipientAddress;
                if (!string.IsNullOrEmpty(messageId))
                    queryParams["MessageId"] = messageId;
                
                var url = BuildUrl($"{ExchangeAdminApiUrl}/{_authManager.CurrentTenantId}/MessageTrace", queryParams);
                
                var response = await ExecuteWithRetryAsync(
                    () => _httpClient.GetAsync(url, cancellationToken),
                    cancellationToken);
                
                var json = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<MessageTraceResult>(json, _jsonOptions)!;
                
                hasMoreData = result.Value?.Length == pageSize;
                page++;
                
                yield return result;
                
            } while (hasMoreData && !cancellationToken.IsCancellationRequested);
        }
        
        #endregion
        
        #region Mailbox Operations via Graph/REST Hybrid
        
        public async Task<MailboxInfo> GetMailboxAsync(string userPrincipalName, CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);
            
            // Use Graph API for mailbox info (more reliable than EXO REST)
            var graphClient = _authManager.GraphClient 
                ?? throw new InvalidOperationException("Graph client not initialized");
            
            var user = await graphClient.Users[userPrincipalName]
                .Request()
                .Select("id,displayName,mail,mailboxSettings,assignedLicenses")
                .GetAsync(cancellationToken);
            
            // Get additional Exchange-specific info via REST
            var url = $"{ExchangeAdminApiUrl}/{_authManager.CurrentTenantId}/Mailbox('{userPrincipalName}')";
            
            var response = await ExecuteWithRetryAsync(
                () => _httpClient.GetAsync(url, cancellationToken),
                cancellationToken);
            
            var json = await response.Content.ReadAsStringAsync();
            var exchangeData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json, _jsonOptions);
            
            return new MailboxInfo
            {
                UserPrincipalName = userPrincipalName,
                DisplayName = user.DisplayName,
                Email = user.Mail,
                MailboxGuid = exchangeData?["ExchangeGuid"].GetString(),
                RecipientTypeDetails = exchangeData?["RecipientTypeDetails"].GetString(),
                WhenCreated = exchangeData?["WhenCreated"].GetDateTime(),
                LitigationHoldEnabled = exchangeData?["LitigationHoldEnabled"].GetBoolean() ?? false
            };
        }
        
        public async IAsyncEnumerable<MailboxAuditLogRecord> GetMailboxAuditLogAsync(
            string userPrincipalName,
            DateTime startDate,
            DateTime endDate,
            string[]? operations = null,
            CancellationToken cancellationToken = default)
        {
            var sessionId = Guid.NewGuid().ToString();
            string? resultSetId = null;
            bool hasMoreData;
            
            do
            {
                await ThrottleRequestAsync(cancellationToken);
                
                var requestBody = new
                {
                    Identity = userPrincipalName,
                    StartDate = startDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"),
                    EndDate = endDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"),
                    Operations = operations,
                    ResultSize = 10000,
                    SessionId = sessionId,
                    ResultSetId = resultSetId
                };
                
                var url = $"{ExchangeAdminApiUrl}/{_authManager.CurrentTenantId}/MailboxAuditLog";
                
                using var content = new StringContent(
                    JsonSerializer.Serialize(requestBody, _jsonOptions),
                    Encoding.UTF8,
                    "application/json");
                
                var response = await ExecuteWithRetryAsync(
                    () => _httpClient.PostAsync(url, content, cancellationToken),
                    cancellationToken);
                
                var json = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<MailboxAuditLogResult>(json, _jsonOptions)!;
                
                if (result.Records != null)
                {
                    foreach (var record in result.Records)
                    {
                        yield return record;
                    }
                }
                
                resultSetId = result.ResultSetId;
                hasMoreData = result.HasMoreData;
                
            } while (hasMoreData && !cancellationToken.IsCancellationRequested);
        }
        
        #endregion
        
        #region Transport Rules via REST
        
        public async Task<TransportRule[]> GetTransportRulesAsync(CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);
            
            var url = $"{ExchangeAdminApiUrl}/{_authManager.CurrentTenantId}/TransportRule";
            
            var response = await ExecuteWithRetryAsync(
                () => _httpClient.GetAsync(url, cancellationToken),
                cancellationToken);
            
            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<TransportRuleResult>(json, _jsonOptions)!;
            
            return result.Value ?? Array.Empty<TransportRule>();
        }
        
        #endregion
        
        #region Inbox Rules via REST
        
        public async Task<InboxRule[]> GetInboxRulesAsync(
            string userPrincipalName, 
            CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);
            
            var url = $"{ExchangeAdminApiUrl}/{_authManager.CurrentTenantId}/InboxRule?Mailbox={Uri.EscapeDataString(userPrincipalName)}";
            
            var response = await ExecuteWithRetryAsync(
                () => _httpClient.GetAsync(url, cancellationToken),
                cancellationToken);
            
            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<InboxRuleResult>(json, _jsonOptions)!;
            
            return result.Value ?? Array.Empty<InboxRule>();
        }
        
        public async IAsyncEnumerable<InboxRule> GetAllMailboxInboxRulesAsync(
            string[]? specificUsers = null,
            int maxDegreeOfParallelism = 10,
            IProgress<(int processed, int total, string currentUser)>? progress = null,
            CancellationToken cancellationToken = default)
        {
            // Get list of mailboxes to process
            var mailboxes = specificUsers ?? await GetAllMailboxesAsync(cancellationToken);
            var totalMailboxes = mailboxes.Length;
            var processedCount = 0;
            
            using var semaphore = new SemaphoreSlim(maxDegreeOfParallelism, maxDegreeOfParallelism);
            var tasks = new List<Task<(string user, InboxRule[] rules)>>();
            
            foreach (var mailbox in mailboxes)
            {
                await semaphore.WaitAsync(cancellationToken);
                
                var task = Task.Run(async () =>
                {
                    try
                    {
                        progress?.Report((Interlocked.Increment(ref processedCount), totalMailboxes, mailbox));
                        var rules = await GetInboxRulesAsync(mailbox, cancellationToken);
                        return (mailbox, rules);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, cancellationToken);
                
                tasks.Add(task);
                
                // Process completed tasks
                while (tasks.Any(t => t.IsCompleted))
                {
                    var completed = await Task.WhenAny(tasks);
                    tasks.Remove(completed);
                    
                    var (user, rules) = await completed;
                    foreach (var rule in rules)
                    {
                        rule.MailboxOwnerId = user;
                        yield return rule;
                    }
                }
            }
            
            // Process remaining tasks
            while (tasks.Any())
            {
                var completed = await Task.WhenAny(tasks);
                tasks.Remove(completed);
                
                var (user, rules) = await completed;
                foreach (var rule in rules)
                {
                    rule.MailboxOwnerId = user;
                    yield return rule;
                }
            }
        }
        
        private async Task<string[]> GetAllMailboxesAsync(CancellationToken cancellationToken)
        {
            await ThrottleRequestAsync(cancellationToken);
            
            var graphClient = _authManager.GraphClient 
                ?? throw new InvalidOperationException("Graph client not initialized");
            
            var users = new List<string>();
            var request = graphClient.Users
                .Request()
                .Select("userPrincipalName,mail,assignedLicenses")
                .Filter("assignedLicenses/any()") // Only licensed users
                .Top(999);
            
            do
            {
                var page = await request.GetAsync(cancellationToken);
                users.AddRange(page.Select(u => u.UserPrincipalName ?? u.Mail).Where(u => !string.IsNullOrEmpty(u)));
                request = page.NextPageRequest;
            } while (request != null);
            
            return users.ToArray();
        }
        
        #endregion
        
        #region Helper Methods
        
        private async Task<HttpResponseMessage> ExecuteWithRetryAsync(
            Func<Task<HttpResponseMessage>> operation,
            CancellationToken cancellationToken)
        {
            // Ensure we have a valid token
            var token = await _authManager.GetExchangeOnlineTokenAsync(cancellationToken);
            if (string.IsNullOrEmpty(token))
            {
                throw new InvalidOperationException("Failed to obtain Exchange Online access token");
            }
            
            _httpClient.DefaultRequestHeaders.Authorization = 
                new AuthenticationHeaderValue("Bearer", token);
            
            var response = await _retryPolicy.ExecuteAsync(async () =>
            {
                var result = await operation();
                
                // Handle rate limiting
                if (result.StatusCode == HttpStatusCode.TooManyRequests)
                {
                    if (result.Headers.RetryAfter != null)
                    {
                        var delay = result.Headers.RetryAfter.Delta ?? TimeSpan.FromSeconds(60);
                        await Task.Delay(delay, cancellationToken);
                    }
                }
                
                result.EnsureSuccessStatusCode();
                return result;
            });
            
            return response;
        }
        
        private async Task ThrottleRequestAsync(CancellationToken cancellationToken)
        {
            await _rateLimitSemaphore.WaitAsync(cancellationToken);
            
            try
            {
                lock (_rateLimitLock)
                {
                    var now = DateTime.UtcNow;
                    var oneMinuteAgo = now.AddMinutes(-1);
                    
                    // Remove timestamps older than 1 minute
                    while (_requestTimestamps.Count > 0 && _requestTimestamps.Peek() < oneMinuteAgo)
                    {
                        _requestTimestamps.Dequeue();
                    }
                    
                    // If we're at the rate limit, wait
                    if (_requestTimestamps.Count >= RequestsPerMinute)
                    {
                        var oldestRequest = _requestTimestamps.Peek();
                        var waitTime = oldestRequest.AddMinutes(1) - now;
                        if (waitTime > TimeSpan.Zero)
                        {
                            Task.Delay(waitTime, cancellationToken).Wait(cancellationToken);
                        }
                    }
                    
                    _requestTimestamps.Enqueue(now);
                }
            }
            finally
            {
                _rateLimitSemaphore.Release();
            }
        }
        
        private string BuildUrl(string baseUrl, Dictionary<string, string> queryParams)
        {
            if (queryParams == null || queryParams.Count == 0)
                return baseUrl;
            
            var query = string.Join("&", queryParams.Select(kvp => 
                $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
            
            return $"{baseUrl}?{query}";
        }
        
        public void Dispose()
        {
            _httpClient?.Dispose();
            _rateLimitSemaphore?.Dispose();
        }
        
        #endregion
    }
    
    // Custom DateTime converter for System.Text.Json
    public class DateTimeOffsetConverter : JsonConverter<DateTimeOffset>
    {
        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.String)
            {
                var value = reader.GetString();
                if (DateTimeOffset.TryParse(value, out var result))
                    return result;
            }
            return DateTimeOffset.MinValue;
        }
        
        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.ToString("yyyy-MM-ddTHH:mm:ssZ"));
        }
    }
}