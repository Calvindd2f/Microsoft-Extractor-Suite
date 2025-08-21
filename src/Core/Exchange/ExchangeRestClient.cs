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
        private readonly Core.Authentication.AuthenticationManager _authManager;
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

        public ExchangeRestClient(Core.Authentication.AuthenticationManager authManager)
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
                .OrResult(msg => msg.StatusCode == (HttpStatusCode)429)
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

        /// <summary>
        /// Invoke Exchange Online PowerShell cmdlets via the beta admin API
        /// </summary>
        public async Task<InvokeCommandResult> InvokeCommandAsync(
            string cmdlet,
            Dictionary<string, object>? parameters = null,
            CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);

            var requestBody = new
            {
                CmdletInput = new
                {
                    Cmdlet = cmdlet,
                    Parameters = parameters ?? new Dictionary<string, object>()
                }
            };

            var url = $"{ExchangeAdminApiUrl}/{_authManager.CurrentTenantId}/InvokeCommand";

            Console.WriteLine($"Invoking Exchange cmdlet: {cmdlet}");
            Console.WriteLine($"Request body: {JsonSerializer.Serialize(requestBody, _jsonOptions)}");

            using var content = new StringContent(
                JsonSerializer.Serialize(requestBody, _jsonOptions),
                Encoding.UTF8,
                "application/json");

            var response = await ExecuteWithRetryAsync(
                () => _httpClient.PostAsync(url, content, cancellationToken),
                cancellationToken);

            var responseContent = await response.Content.ReadAsStringAsync();

            // Check if response is JSON
            if (string.IsNullOrWhiteSpace(responseContent))
            {
                throw new InvalidOperationException("Exchange API returned empty response");
            }

            if (!responseContent.TrimStart().StartsWith("{") && !responseContent.TrimStart().StartsWith("["))
            {
                // Response is not JSON, likely HTML error page
                throw new InvalidOperationException(
                    $"Exchange API returned non-JSON response. This usually indicates an authentication or endpoint issue. " +
                    $"Response preview: {responseContent.Substring(0, Math.Min(500, responseContent.Length))}");
            }

            try
            {
                return JsonSerializer.Deserialize<InvokeCommandResult>(responseContent, _jsonOptions)!;
            }
            catch (JsonException ex)
            {
                throw new InvalidOperationException(
                    $"Failed to parse Exchange API response as JSON. Error: {ex.Message}. " +
                    $"Response: {responseContent.Substring(0, Math.Min(500, responseContent.Length))}", ex);
            }
        }

        /// <summary>
        /// Search Unified Audit Log using the InvokeCommand endpoint
        /// </summary>
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
            var parameters = new Dictionary<string, object>
            {
                ["StartDate"] = startDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ["EndDate"] = endDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ["ResultSize"] = resultSize
            };

            if (!string.IsNullOrEmpty(sessionId))
                parameters["SessionId"] = sessionId;

            if (operations != null && operations.Length > 0)
                parameters["Operations"] = operations;

            if (recordTypes != null && recordTypes.Length > 0)
                parameters["RecordTypes"] = recordTypes;

            if (userIds != null && userIds.Length > 0)
                parameters["UserIds"] = userIds;

            var result = await InvokeCommandAsync("Search-UnifiedAuditLog", parameters, cancellationToken);

            // Parse the result and convert to UnifiedAuditLogResult
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        // The output should contain the actual audit log data
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            return JsonSerializer.Deserialize<UnifiedAuditLogResult>(outputJson, _jsonOptions)!;
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Search-UnifiedAuditLog output: {ex.Message}");
                    }
                }
            }

            // Fallback: return empty result
            return new UnifiedAuditLogResult
            {
                Value = Array.Empty<UnifiedAuditLogRecord>(),
                ResultCount = 0,
                HasMoreData = false
            };
        }

        /// <summary>
        /// Search Unified Audit Log with session support for pagination
        /// </summary>
        public async Task<UnifiedAuditLogResult> SearchUnifiedAuditLogWithSessionAsync(
            DateTime startDate,
            DateTime endDate,
            string? sessionId = null,
            string[]? operations = null,
            string[]? recordTypes = null,
            string[]? userIds = null,
            int resultSize = 5000,
            CancellationToken cancellationToken = default)
        {
            var parameters = new Dictionary<string, object>
            {
                ["StartDate"] = startDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ["EndDate"] = endDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ["ResultSize"] = resultSize
            };

            if (!string.IsNullOrEmpty(sessionId))
            {
                parameters["SessionId"] = sessionId;
                parameters["SessionCommand"] = "ReturnNextPreviewPage";
            }
            else
            {
                parameters["SessionCommand"] = "ReturnNextPreviewPage";
            }

            if (operations != null && operations.Length > 0)
                parameters["Operations"] = operations;

            if (recordTypes != null && recordTypes.Length > 0)
                parameters["RecordTypes"] = recordTypes;

            if (userIds != null && userIds.Length > 0)
                parameters["UserIds"] = userIds;

            var result = await InvokeCommandAsync("Search-UnifiedAuditLog", parameters, cancellationToken);

            // Parse the result and convert to UnifiedAuditLogResult
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        // The output should contain the actual audit log data
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            return JsonSerializer.Deserialize<UnifiedAuditLogResult>(outputJson, _jsonOptions)!;
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Search-UnifiedAuditLog output: {ex.Message}");
                    }
                }
            }

            // Fallback: return empty result
            return new UnifiedAuditLogResult
            {
                Value = Array.Empty<UnifiedAuditLogRecord>(),
                ResultCount = 0,
                HasMoreData = false
            };
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
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var page = 1;
            bool hasMoreData;

            do
            {
                await ThrottleRequestAsync(cancellationToken);

                var parameters = new Dictionary<string, object>
                {
                    ["StartDate"] = startDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    ["EndDate"] = endDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    ["PageSize"] = pageSize,
                    ["Page"] = page
                };

                if (!string.IsNullOrEmpty(senderAddress))
                    parameters["SenderAddress"] = senderAddress;
                if (!string.IsNullOrEmpty(recipientAddress))
                    parameters["RecipientAddress"] = recipientAddress;
                if (!string.IsNullOrEmpty(messageId))
                    parameters["MessageId"] = messageId;

                var result = await InvokeCommandAsync("Get-MessageTrace", parameters, cancellationToken);

                // Parse the result and convert to MessageTraceResult
                MessageTraceResult? messageTraceResult = null;
                if (result.Results != null && result.Results.Length > 0)
                {
                    var firstResult = result.Results[0];
                    if (firstResult.Output != null)
                    {
                        try
                        {
                            var outputJson = firstResult.Output.ToString();
                            if (!string.IsNullOrEmpty(outputJson))
                            {
                                messageTraceResult = JsonSerializer.Deserialize<MessageTraceResult>(outputJson, _jsonOptions);
                            }
                        }
                        catch (JsonException ex)
                        {
                            Console.WriteLine($"Warning: Failed to parse Get-MessageTrace output: {ex.Message}");
                        }
                    }
                }

                // Fallback to empty result if parsing failed
                if (messageTraceResult == null)
                {
                    messageTraceResult = new MessageTraceResult
                    {
                        Value = Array.Empty<MessageTrace>()
                    };
                }

                hasMoreData = messageTraceResult.Value?.Length == pageSize;
                page++;

                yield return messageTraceResult;

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
                .GetAsync(requestConfiguration => {
                    requestConfiguration.QueryParameters.Select = new string[] { "id", "displayName", "mail", "mailboxSettings", "assignedLicenses" };
                }, cancellationToken);

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
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var sessionId = Guid.NewGuid().ToString();
            string? resultSetId = null;
            bool hasMoreData;

            do
            {
                await ThrottleRequestAsync(cancellationToken);

                var parameters = new Dictionary<string, object>
                {
                    ["Identity"] = userPrincipalName,
                    ["StartDate"] = startDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    ["EndDate"] = endDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    ["ResultSize"] = 10000,
                    ["SessionId"] = sessionId
                };

                if (operations != null && operations.Length > 0)
                    parameters["Operations"] = operations;

                if (!string.IsNullOrEmpty(resultSetId))
                    parameters["ResultSetId"] = resultSetId;

                var result = await InvokeCommandAsync("Search-MailboxAuditLog", parameters, cancellationToken);

                // Parse the result and convert to MailboxAuditLogResult
                MailboxAuditLogResult? mailboxAuditLogResult = null;
                if (result.Results != null && result.Results.Length > 0)
                {
                    var firstResult = result.Results[0];
                    if (firstResult.Output != null)
                    {
                        try
                        {
                            var outputJson = firstResult.Output.ToString();
                            if (!string.IsNullOrEmpty(outputJson))
                            {
                                mailboxAuditLogResult = JsonSerializer.Deserialize<MailboxAuditLogResult>(outputJson, _jsonOptions);
                            }
                        }
                        catch (JsonException ex)
                        {
                            Console.WriteLine($"Warning: Failed to parse Search-MailboxAuditLog output: {ex.Message}");
                        }
                    }
                }

                // Fallback to empty result if parsing failed
                if (mailboxAuditLogResult == null)
                {
                    mailboxAuditLogResult = new MailboxAuditLogResult
                    {
                        Records = Array.Empty<MailboxAuditLogRecord>(),
                        HasMoreData = false
                    };
                }

                if (mailboxAuditLogResult.Records != null)
                {
                    foreach (var record in mailboxAuditLogResult.Records)
                    {
                        yield return record;
                    }
                }

                resultSetId = mailboxAuditLogResult.ResultSetId;
                hasMoreData = mailboxAuditLogResult.HasMoreData;

            } while (hasMoreData && !cancellationToken.IsCancellationRequested);
        }

        #endregion

        #region Transport Rules via REST

        public async Task<TransportRule[]> GetTransportRulesTypedAsync(CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);

            var result = await InvokeCommandAsync("Get-TransportRule", cancellationToken: cancellationToken);

            // Parse the result and convert to TransportRule[]
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            var transportRuleResult = JsonSerializer.Deserialize<TransportRuleResult>(outputJson, _jsonOptions);
                            return transportRuleResult?.Value ?? Array.Empty<TransportRule>();
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Get-TransportRule output: {ex.Message}");
                    }
                }
            }

            // Fallback to empty result if parsing failed
            return Array.Empty<TransportRule>();
        }

        #endregion

        #region Inbox Rules via REST

        public async Task<InboxRule[]> GetInboxRulesAsync(
            string userPrincipalName,
            CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);

            var parameters = new Dictionary<string, object>
            {
                ["Mailbox"] = userPrincipalName
            };

            var result = await InvokeCommandAsync("Get-InboxRule", parameters, cancellationToken);

            // Parse the result and convert to InboxRule[]
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            var inboxRuleResult = JsonSerializer.Deserialize<InboxRuleResult>(outputJson, _jsonOptions);
                            return inboxRuleResult?.Value ?? Array.Empty<InboxRule>();
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Get-InboxRule output: {ex.Message}");
                    }
                }
            }

            // Fallback to empty result if parsing failed
            return Array.Empty<InboxRule>();
        }

        public async IAsyncEnumerable<InboxRule> GetAllMailboxInboxRulesAsync(
            string[]? specificUsers = null,
            int maxDegreeOfParallelism = 10,
            IProgress<(int processed, int total, string currentUser)>? progress = null,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
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

            var result = await InvokeCommandAsync("Get-Mailbox", cancellationToken: cancellationToken);

            var users = new List<string>();

            // Parse the result and extract user principal names
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            var mailboxes = JsonSerializer.Deserialize<ExchangeMailbox[]>(outputJson, _jsonOptions);
                            if (mailboxes != null)
                            {
                                users.AddRange(mailboxes.Select(m => m.UserPrincipalName).Where(u => !string.IsNullOrEmpty(u)));
                            }
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Get-Mailbox output: {ex.Message}");

                        // Fallback to Graph API if InvokeCommand fails
                        try
                        {
                            var graphClient = _authManager.GraphClient
                                ?? throw new InvalidOperationException("Graph client not initialized");

                            var response = await graphClient.Users
                                .GetAsync(requestConfiguration => {
                                    requestConfiguration.QueryParameters.Select = new string[] { "userPrincipalName", "mail", "assignedLicenses" };
                                    requestConfiguration.QueryParameters.Filter = "assignedLicenses/any()"; // Only licensed users
                                    requestConfiguration.QueryParameters.Top = 999;
                                }, cancellationToken);

                            if (response?.Value != null)
                            {
                                users.AddRange(response.Value.Select(u => u.UserPrincipalName ?? u.Mail).Where(u => !string.IsNullOrEmpty(u)));
                            }
                        }
                        catch (Exception graphEx)
                        {
                            Console.WriteLine($"Fallback to Graph API also failed: {graphEx.Message}");
                        }
                    }
                }
            }

            return users.ToArray();
        }

        #endregion

        #region Missing Methods

        /// <summary>
        /// Gets all mailboxes in the tenant
        /// </summary>
        public async Task<string[]> GetMailboxesAsync(CancellationToken cancellationToken = default)
        {
            return await GetAllMailboxesAsync(cancellationToken);
        }

        /// <summary>
        /// Gets mailbox permissions for a specific mailbox
        /// </summary>
        public async Task<object[]> GetMailboxPermissionsAsync(string mailbox, CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);

            var parameters = new Dictionary<string, object>
            {
                ["Identity"] = mailbox
            };

            var result = await InvokeCommandAsync("Get-MailboxPermission", parameters, cancellationToken);

            // Parse the result and return as object array
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            var parsedResult = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(outputJson, _jsonOptions);
                            return parsedResult?["value"].EnumerateArray().Select(x => (object)x).ToArray() ?? Array.Empty<object>();
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Get-MailboxPermission output: {ex.Message}");
                    }
                }
            }

            // Fallback to empty result if parsing failed
            return Array.Empty<object>();
        }

        /// <summary>
        /// Gets recipient permissions for a specific recipient
        /// </summary>
        public async Task<object[]> GetRecipientPermissionsAsync(string recipient, CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);

            var parameters = new Dictionary<string, object>
            {
                ["Identity"] = recipient
            };

            var result = await InvokeCommandAsync("Get-RecipientPermission", parameters, cancellationToken);

            // Parse the result and return as object array
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            var parsedResult = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(outputJson, _jsonOptions);
                            return parsedResult?["value"].EnumerateArray().Select(x => (object)x).ToArray() ?? Array.Empty<object>();
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Get-RecipientPermission output: {ex.Message}");
                    }
                }
            }

            // Fallback to empty result if parsing failed
            return Array.Empty<object>();
        }

        /// <summary>
        /// Gets send-as permissions for a specific mailbox
        /// </summary>
        public async Task<object[]> GetSendAsPermissionsAsync(string mailbox, CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);

            var parameters = new Dictionary<string, object>
            {
                ["Identity"] = mailbox
            };

            var result = await InvokeCommandAsync("Get-SendAsPermission", parameters, cancellationToken);

            // Parse the result and return as object array
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            var parsedResult = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(outputJson, _jsonOptions);
                            return parsedResult?["value"].EnumerateArray().Select(x => (object)x).ToArray() ?? Array.Empty<object>();
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Get-SendAsPermission output: {ex.Message}");
                    }
                }
            }

            // Fallback to empty result if parsing failed
            return Array.Empty<object>();
        }

        /// <summary>
        /// Gets mailbox rules for a specific mailbox
        /// </summary>
        public async Task<object[]> GetMailboxRulesAsync(string mailbox, CancellationToken cancellationToken = default)
        {
            var rules = await GetInboxRulesAsync(mailbox, cancellationToken);
            return rules.Cast<object>().ToArray();
        }

        /// <summary>
        /// Gets transport rules (alternative overload)
        /// </summary>
        public async Task<object[]> GetTransportRulesAsync(CancellationToken cancellationToken = default)
        {
            var rules = await GetTransportRulesInternalAsync(cancellationToken);
            return rules.Cast<object>().ToArray();
        }

        private async Task<TransportRule[]> GetTransportRulesInternalAsync(CancellationToken cancellationToken = default)
        {
            return await GetTransportRulesTypedAsync(cancellationToken);
        }

        /// <summary>
        /// Searches message trace logs
        /// </summary>
        public async IAsyncEnumerable<object> SearchMessageTraceAsync(
            DateTime startDate,
            DateTime endDate,
            string? senderAddress = null,
            string? recipientAddress = null,
            string? messageId = null,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await foreach (var result in GetMessageTraceAsync(startDate, endDate, senderAddress, recipientAddress, messageId, cancellationToken: cancellationToken))
            {
                yield return result;
            }
        }

        /// <summary>
        /// Gets admin audit log entries
        /// </summary>
        public async IAsyncEnumerable<object> GetAdminAuditLogEntriesAsync(
            DateTime startDate,
            DateTime endDate,
            string[]? operations = null,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);

            var parameters = new Dictionary<string, object>
            {
                ["StartDate"] = startDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ["EndDate"] = endDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ["ResultSize"] = 5000
            };

            if (operations != null && operations.Length > 0)
                parameters["Operations"] = operations;

            var result = await InvokeCommandAsync("Search-AdminAuditLog", parameters, cancellationToken);

            // Parse the result and yield entries
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            var parsedResult = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(outputJson, _jsonOptions);
                            if (parsedResult?["value"].EnumerateArray() != null)
                            {
                                foreach (var entry in parsedResult["value"].EnumerateArray())
                                {
                                    yield return entry;
                                }
                            }
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Search-AdminAuditLog output: {ex.Message}");
                    }
                }
            }
        }

        /// <summary>
        /// Searches mailbox audit logs
        /// </summary>
        public async IAsyncEnumerable<object> SearchMailboxAuditLogAsync(
            string mailbox,
            DateTime startDate,
            DateTime endDate,
            string[]? operations = null,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await foreach (var record in GetMailboxAuditLogAsync(mailbox, startDate, endDate, operations, cancellationToken))
            {
                yield return record;
            }
        }

        #endregion

        #region Connection Status Methods

        /// <summary>
        /// Checks if the Exchange REST client is properly connected
        /// </summary>
        public async Task<bool> IsConnectedAsync()
        {
            try
            {
                var token = await _authManager.GetExchangeOnlineTokenAsync();
                return !string.IsNullOrEmpty(token) && _authManager.IsGraphConnected;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Synchronous check for Exchange connection
        /// </summary>
        public bool IsExchangeConnected => _authManager.IsGraphConnected;

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
                throw new InvalidOperationException(
                    "Failed to obtain Exchange Online access token. " +
                    "Please ensure you have the necessary Exchange permissions. " +
                    "Try running Connect-M365 with Exchange scopes or use Graph API alternatives.");
            }

            _httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", token);

            try
            {
                var response = await _retryPolicy.ExecuteAsync(async () =>
                {
                    var result = await operation();

                    // Handle rate limiting
                    if (result.StatusCode == (HttpStatusCode)429)
                    {
                        if (result.Headers.RetryAfter != null)
                        {
                            var delay = result.Headers.RetryAfter.Delta ?? TimeSpan.FromSeconds(60);
                            await Task.Delay(delay, cancellationToken);
                        }
                    }

                    // Log the response status for debugging
                    if (!result.IsSuccessStatusCode)
                    {
                        var content = await result.Content.ReadAsStringAsync();
                        Console.WriteLine($"Exchange API error - Status: {result.StatusCode}");
                        Console.WriteLine($"Response headers: {string.Join(", ", result.Headers.Select(h => $"{h.Key}={string.Join(",", h.Value)}"))}");
                        Console.WriteLine($"Response content preview: {content.Substring(0, Math.Min(500, content.Length))}");
                    }

                    // Handle specific Exchange errors
                    if (result.StatusCode == HttpStatusCode.Forbidden)
                    {
                        var content = await result.Content.ReadAsStringAsync();
                        throw new UnauthorizedAccessException(
                            $"Access denied to Exchange Online Management API. " +
                            $"This may require Exchange Administrator role or specific Exchange permissions. " +
                            $"Status: {result.StatusCode}, Content: {content.Substring(0, Math.Min(500, content.Length))}");
                    }

                    if (result.StatusCode == HttpStatusCode.NotFound)
                    {
                        var content = await result.Content.ReadAsStringAsync();
                        throw new InvalidOperationException(
                            $"Exchange Online Management API endpoint not found. " +
                            $"The endpoint may not exist or Exchange Online may not be properly configured. " +
                            $"Status: {result.StatusCode}, URL was: {result.RequestMessage?.RequestUri}");
                    }

                    if (result.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        var content = await result.Content.ReadAsStringAsync();
                        throw new UnauthorizedAccessException(
                            $"Authentication failed for Exchange API. " +
                            $"Token may be expired or invalid. Try reconnecting with Connect-M365 -ExchangeOnline. " +
                            $"Response: {content.Substring(0, Math.Min(500, content.Length))}");
                    }

                    result.EnsureSuccessStatusCode();
                    return result;
                });

                return response;
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException(
                    $"Failed to connect to Exchange Online API. " +
                    $"Error: {ex.Message}. " +
                    $"Please verify Exchange Online connectivity and permissions.", ex);
            }
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

        #region Additional Exchange Operations via InvokeCommand

        /// <summary>
        /// Get distribution groups
        /// </summary>
        public async Task<object[]> GetDistributionGroupsAsync(CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);

            var result = await InvokeCommandAsync("Get-DistributionGroup", cancellationToken: cancellationToken);

            // Parse the result and return as object array
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            var parsedResult = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(outputJson, _jsonOptions);
                            return parsedResult?["value"].EnumerateArray().Select(x => (object)x).ToArray() ?? Array.Empty<object>();
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Get-DistributionGroup output: {ex.Message}");
                    }
                }
            }

            // Fallback to empty result if parsing failed
            return Array.Empty<object>();
        }

        /// <summary>
        /// Get mail flow rules
        /// </summary>
        public async Task<object[]> GetMailFlowRulesAsync(CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);

            var result = await InvokeCommandAsync("Get-MailFlowRule", cancellationToken: cancellationToken);

            // Parse the result and return as object array
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            var parsedResult = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(outputJson, _jsonOptions);
                            return parsedResult?["value"].EnumerateArray().Select(x => (object)x).ToArray() ?? Array.Empty<object>();
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Get-MailFlowRule output: {ex.Message}");
                    }
                }
            }

            // Fallback to empty result if parsing failed
            return Array.Empty<object>();
        }

        /// <summary>
        /// Get retention policies
        /// </summary>
        public async Task<object[]> GetRetentionPoliciesAsync(CancellationToken cancellationToken = default)
        {
            await ThrottleRequestAsync(cancellationToken);

            var result = await InvokeCommandAsync("Get-RetentionPolicy", cancellationToken: cancellationToken);

            // Parse the result and return as object array
            if (result.Results != null && result.Results.Length > 0)
            {
                var firstResult = result.Results[0];
                if (firstResult.Output != null)
                {
                    try
                    {
                        var outputJson = firstResult.Output.ToString();
                        if (!string.IsNullOrEmpty(outputJson))
                        {
                            var parsedResult = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(outputJson, _jsonOptions);
                            return parsedResult?["value"].EnumerateArray().Select(x => (object)x).ToArray() ?? Array.Empty<object>();
                        }
                    }
                    catch (JsonException ex)
                    {
                        Console.WriteLine($"Warning: Failed to parse Get-RetentionPolicy output: {ex.Message}");
                    }
                }
            }

            // Fallback to empty result if parsing failed
            return Array.Empty<object>();
        }

        /// <summary>
        /// Generic method to invoke any Exchange Online PowerShell cmdlet
        /// </summary>
        public async Task<InvokeCommandResult> InvokeExchangeCmdletAsync(
            string cmdlet,
            Dictionary<string, object>? parameters = null,
            CancellationToken cancellationToken = default)
        {
            return await InvokeCommandAsync(cmdlet, parameters, cancellationToken);
        }

        #endregion

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
