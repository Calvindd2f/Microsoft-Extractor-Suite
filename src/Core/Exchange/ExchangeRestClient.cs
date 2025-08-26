namespace Microsoft.ExtractorSuite.Core.Exchange
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core.Authentication;
    using Microsoft.ExtractorSuite.Models.Exchange;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;
    using Newtonsoft.Json.Linq;
    using Newtonsoft.Json.Serialization;
    using Polly;
    using Polly.Extensions.Http;


    /// <summary>
    /// Direct REST API client for Exchange Online without ExchangeOnlineManagement module dependency
    /// Uses Exchange REST API v2.0 and Admin API endpoints
    /// </summary>
    public class ExchangeRestClient : IDisposable
    {

        private readonly HttpClient _httpClient;


        private readonly Core.Authentication.AuthenticationManager _authManager;


        private readonly IAsyncPolicy<HttpResponseMessage> _retryPolicy;


        private readonly JsonSerializerSettings _jsonOptions;


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

            _jsonOptions = new JsonSerializerSettings
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver(),
                Converters =
                {
                    new StringEnumConverter(),
                    new DateTimeOffsetConverter()
                }
            };

        }

        #region Unified Audit Log via REST API

        /// <summary>
        /// Invoke Exchange Online PowerShell cmdlets via the beta admin API
        /// Replicates the functionality of the PowerShell ExoCommand function
        /// </summary>
        public async Task<InvokeCommandResult> InvokeCommandAsync(
            string cmdlet,
            Dictionary<string, object>? parameters = null,
            CancellationToken cancellationToken = default)
        {

            await ThrottleRequestAsync(cancellationToken);


            // Generate connection ID for this session (similar to PowerShell script)
            var connectionId = Guid.NewGuid().ToString();

            var requestBody = new
            {
                CmdletInput = new
                {
                    CmdletName = cmdlet, // Note: PowerShell script uses CmdletName, not Cmdlet
                    Parameters = parameters ?? new Dictionary<string, object>()
                }
            };


            var url = $"{ExchangeAdminApiUrl}/{_authManager.CurrentTenantId}/InvokeCommand";


            // Build friendly command string for logging (like PowerShell script)
            var commandFriendly = cmdlet;
            if (parameters != null)
            {
                foreach (var param in parameters)
                {
                    var value = param.Value is string strValue ? $"\"{strValue}\"" : param.Value?.ToString() ?? "";
                    commandFriendly += $" -{param.Key} {value}".TrimEnd();
                }
            }

            Console.WriteLine($"Executing: {commandFriendly}");

            Console.WriteLine($"Request body: {JsonConvert.SerializeObject(requestBody, _jsonOptions)}");



            using var content = new StringContent(
                JsonConvert.SerializeObject(requestBody, _jsonOptions),
                Encoding.UTF8,
                "application/json");


            // Set up request with proper headers (replicating PowerShell script)
            var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = content
            };

            // Add headers that match the PowerShell script
            request.Headers.Add("x-serializationlevel", "Partial");

            request.Headers.Add("X-AnchorMailbox", $"UPN:SystemMailbox{{bb558c35-97f1-4cb9-8ff7-d53741dc928c}}@{_authManager.CurrentTenantId}");

            request.Headers.Add("X-prefer", "odata.maxpagesize=1000");
            request.Headers.Add("X-ResponseFormat", "json");
            request.Headers.Add("connection-id", connectionId);
            request.Headers.Add("accept-charset", "UTF-8");
            request.Headers.Add("warningaction", "");

            // Get Exchange token for authorization

            var token = await _authManager.GetExchangeOnlineTokenAsync(cancellationToken);

            if (string.IsNullOrEmpty(token))
            {
                throw new InvalidOperationException(
                    "Failed to obtain Exchange Online access token. " +
                    "Please ensure you have the necessary Exchange permissions. " +
                    "Try running Connect-M365 with Exchange scopes.");
            }

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);


            var response = await ExecuteWithRetryAsync(
                () => _httpClient.SendAsync(request, cancellationToken),
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

                return JsonConvert.DeserializeObject<InvokeCommandResult>(responseContent, _jsonOptions)!;

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

                            return JsonConvert.DeserializeObject<UnifiedAuditLogResult>(outputJson, _jsonOptions)!;

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

                            return JsonConvert.DeserializeObject<UnifiedAuditLogResult>(outputJson, _jsonOptions)!;

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

                                messageTraceResult = JsonConvert.DeserializeObject<MessageTraceResult>(outputJson, _jsonOptions);

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

            var exchangeData = JsonConvert.DeserializeObject<Dictionary<string, JToke

_jsonOptions);

            return new MailboxInfo
            {
                UserPrincipalName = userPrincipalName,
                DisplayName = user.DisplayName,
                Email = user.Mail,
                MailboxGuid = exchangeData?["ExchangeGuid"].ToString(),
                RecipientTypeDetails = exchangeData?["RecipientTypeDetails"].ToString(),
                WhenCreated = exchangeData?["WhenCreated"].ToObject<DateTime>(),
                LitigationHoldEnabled = exchangeData?["LitigationHoldEnabled"].ToObject<bool>() ?? false
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

                                mailboxAuditLogResult = JsonConvert.DeserializeObject<MailboxAuditLogResult>(outputJson, _jsonOptions);

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

                            var transportRuleResult = JsonConvert.DeserializeObject<TransportRuleResult>(outputJson, _jsonOptions);

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

                            var inboxRuleResult = JsonConvert.DeserializeObject<InboxRuleResult>(outputJson, _jsonOptions);


                            return inboxRuleResult?.Value ?? Array.Empty<Inbox

documentedRule>();
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

                            var mailboxes = JsonConvert.DeserializeObject<ExchangeMailbox[]>(outputJson, _jsonOptions);

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

                            var parsedResult = JsonConvert.DeserializeObject<Dictionary<string, JToken>>(outputJson, _jsonOptions);

                            return parsedResult?["value"].ToObject<object[]>() ?? Array.Empty<object>();
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

                            var parsedResult = JsonConvert.DeserializeObject<Dictionary<string, JToken>>(outputJson, _jsonOptions);

                            return parsedResult?["value"].ToObject<object[]>() ?? Array.Empty<object>();
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

                            var parsedResult = JsonConvert.DeserializeObject<Dictionary<string, JToken>>(outputJson, _jsonOptions);

                            return parsedResult?["value"].ToObject<object[]>() ?? Array.Empty<object>();
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

                            var parsedResult = JsonConvert.DeserializeObject<Dictionary<string, JToken>>(outputJson, _jsonOptions);

                            if (parsedResult?["value"].ToObject<JArray>() != null)
                            {
                                foreach (var entry in parsedResult["value"].ToObject<JArray>())
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

        #region Direct API Operations (Alternative to PowerShell Cmdlets)

        /// <summary>
        /// Get product licenses directly through Graph API (alternative to Get-ProductLicenses cmdlet)
        /// </summary>
        public async Task<object[]> GetProductLicensesDirectAsync(
            string[]? userIds = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Use Graph API directly instead of PowerShell cmdlet

                var graphClient = _authManager.GraphClient
                    ?? throw new InvalidOperationException("Graph client not initialized");


                var users = new List<object>();

                if (userIds != null && userIds.Length > 0)
                {
                    // Get specific users
                    foreach (var userId in userIds)
                    {
                        try
                        {
                            var user = await graphClient.Users[userId]
                                .GetAsync(config =>
                                {
                                    config.QueryParameters.Select = new[] { "id", "userPrincipalName", "displayName", "assignedLicenses" };
                                }, cancellationToken);

                            if (user?.AssignedLicenses != null)
                            {
                                users.Add(new
                                {
                                    UserId = user.Id,
                                    UserPrincipalName = user.UserPrincipalName,
                                    DisplayName = user.DisplayName,
                                    AssignedLicenses = user.AssignedLicenses
                                });
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning: Failed to get licenses for user {userId}: {ex.Message}");
                        }
                    }
                }
                else
                {
                    // Get all users with licenses
                    var response = await graphClient.Users
                        .GetAsync(config =>
                        {
                            config.QueryParameters.Select = new[] { "id", "userPrincipalName", "displayName", "assignedLicenses" };
                            config.QueryParameters.Filter = "assignedLicenses/any()"; // Only users with licenses
                            config.QueryParameters.Top = 999;
                        }, cancellationToken);

                    if (response?.Value != null)
                    {
                        foreach (var user in response.Value)
                        {
                            if (user.AssignedLicenses != null)
                            {
                                users.Add(new
                                {
                                    UserId = user.Id,
                                    UserPrincipalName = user.UserPrincipalName,
                                    DisplayName = user.DisplayName,
                                    AssignedLicenses = user.AssignedLicenses
                                });
                            }
                        }
                    }
                }

                return users.ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting product licenses: {ex.Message}");
                return Array.Empty<object>();
            }
        }

        /// <summary>
        /// Get directory roles directly through Graph API (alternative to Get-Roles cmdlet)
        /// </summary>
        public async Task<object[]> GetRolesDirectAsync(CancellationToken cancellationToken = default)
        {
            try
            {

                var graphClient = _authManager.GraphClient
                    ?? throw new InvalidOperationException("Graph client not initialized");


                var roles = new List<object>();

                // Get directory roles
                var rolesResponse = await graphClient.DirectoryRoles
                    .GetAsync(config =>
                    {
                        config.QueryParameters.Select = new string[] { "id", "displayName", "description", "roleTemplateId" };
                        config.QueryParameters.Top = 999;
                    }, cancellationToken);

                if (rolesResponse?.Value != null)
                {
                    foreach (var role in rolesResponse.Value)
                    {
                        try
                        {
                            // Get members for each role
                            var membersResponse = await graphClient.DirectoryRoles[role.Id].Members
                                .GetAsync(config =>
                                {
                                    config.QueryParameters.Top = 999;
                                }, cancellationToken);

                            roles.Add(new
                            {
                                RoleId = role.Id,
                                DisplayName = role.DisplayName,
                                Description = role.Description,
                                RoleTemplateId = role.RoleTemplateId,
                                MemberCount = membersResponse?.Value?.Count ?? 0,
                                Members = membersResponse?.Value?.Select(m => new
                                {
                                    Id = m.Id,
                                    DisplayName = m.DisplayName,
                                    UserPrincipalName = m.UserPrincipalName
                                }).ToArray() ?? Array.Empty<object>()
                            });
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning: Failed to get members for role {role.DisplayName}: {ex.Message}");
                            // Add role without members
                            roles.Add(new
                            {
                                RoleId = role.Id,
                                DisplayName = role.DisplayName,
                                Description = role.Description,
                                RoleTemplateId = role.RoleTemplateId,
                                MemberCount = 0,
                                Members = Array.Empty<object>()
                            });
                        }
                    }
                }

                return roles.ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting roles: {ex.Message}");
                return Array.Empty<object>();
            }
        }

        /// <summary>
        /// Get OAuth permissions directly through Graph API (alternative to Get-OAuthPermissions cmdlet)
        /// </summary>
        public async Task<object[]> GetOAuthPermissionsDirectAsync(CancellationToken cancellationToken = default)
        {
            try
            {

                var graphClient = _authManager.GraphClient
                    ?? throw new InvalidOperationException("Graph client not initialized");


                var permissions = new List<object>();

                // Get service principals (applications)
                var servicePrincipalsResponse = await graphClient.ServicePrincipals
                    .GetAsync(config =>
                    {
                        config.QueryParameters.Select = new string[] { "id", "appId", "displayName", "appRoles", "oauth2PermissionScopes" };
                        config.QueryParameters.Top = 999;
                    }, cancellationToken);

                if (servicePrincipalsResponse?.Value != null)
                {
                    foreach (var sp in servicePrincipalsResponse.Value)
                    {
                        try
                        {
                            permissions.Add(new
                            {
                                ServicePrincipalId = sp.Id,
                                AppId = sp.AppId,
                                DisplayName = sp.DisplayName,
                                AppRoles = sp.AppRoles?.Select(ar => new
                                {
                                    Id = ar.Id,
                                    DisplayName = ar.DisplayName,
                                    Description = ar.Description,
                                    Value = ar.Value
                                }).ToArray() ?? Array.Empty<object>(),
                                OAuth2PermissionScopes = sp.Oauth2PermissionScopes?.Select(scope => new
                                {
                                    Id = scope.Id,
                                    Value = scope.Value,
                                    DisplayName = scope.DisplayName,
                                    Description = scope.Description,
                                    Type = scope.Type
                                }).ToArray() ?? Array.Empty<object>()
                            });
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning: Failed to process service principal {sp.DisplayName}: {ex.Message}");
                        }
                    }
                }

                return permissions.ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting OAuth permissions: {ex.Message}");
                return Array.Empty<object>();
            }
        }

        #endregion

        #region PowerShell-like Command Execution

        /// <summary>
        /// PowerShell-like command execution with retry logic and proper error handling
        /// Replicates the ExoCommand function from the PowerShell script
        /// </summary>
        public async Task<InvokeCommandResult> ExecutePowerShellCommandAsync(
            string command,
            Dictionary<string, object>? arguments = null,
            int retryCount = 5,
            CancellationToken cancellationToken = default)
        {
            var success = false;
            var count = 0;

            // Build friendly command string for logging (like PowerShell script)
            var commandFriendly = PowerShellCommandBuilder.BuildCommandString(command, arguments);
            Console.WriteLine($"Executing PowerShell command: {commandFriendly}");

            // Convert parameters to PowerShell format if needed
            var powerShellArgs = arguments != null ?
                PowerShellCommandBuilder.ConvertToPowerShellParameters(arguments) : null;

            {
                try
                {

                    var result = await InvokeCommandAsync(command, powerShellArgs, cancellationToken);

                    success = true;
                    return result;
                }
                catch (Exception ex)
                {
                    count++;

                    // Check for timeout or connection issues (like PowerShell script)
                    if (ex.Message.Contains("timed out", StringComparison.OrdinalIgnoreCase) ||
                        ex.Message.Contains("Unable to connect to the remote server", StringComparison.OrdinalIgnoreCase))
                    {
                        if (count <= retryCount)
                        {
                            Console.WriteLine($"TIMEOUT: Will retry in 10 seconds. Attempt {count}/{retryCount}");
                            await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);
                        }
                        else
                        {
                            throw new InvalidOperationException($"Timeout retry limit reached after {retryCount} attempts", ex);
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Failed to execute Exchange command: {commandFriendly}");
                        Console.WriteLine($"Error: {ex.Message}");
                        throw;
                    }
                }
            } while (count <= retryCount && !success);

            return null!;
        }

        /// <summary>
        /// Get blocked and allowed sender lists using PowerShell commands
        /// Replicates the GetLists function from the PowerShell script
        /// </summary>
        public async Task<(Dictionary<string, object> blocked, Dictionary<string, object> allowed, bool success)>
            GetSenderListsAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                Console.WriteLine("Begin Get Blocked List on O365");

                // Get the default hosted content filter policy

                var defaultPolicy = await ExecutePowerShellCommandAsync(
                    "Get-HostedContentFilterPolicy",
                    new Dictionary<string, object> { ["Identity"] = "Default" },
                    cancellationToken: cancellationToken);


                if (defaultPolicy?.Results == null || defaultPolicy.Results.Length == 0)
                {
                    Console.WriteLine("Warning: No hosted content filter policy found");
                    return (new Dictionary<string, object>(), new Dictionary<string, object>(), false);
                }

                var firstResult = defaultPolicy.Results[0];
                if (firstResult.Output == null)
                {
                    Console.WriteLine("Warning: No output from Get-HostedContentFilterPolicy");
                    return (new Dictionary<string, object>(), new Dictionary<string, object>(), false);
                }

                // Parse the output to extract blocked and allowed lists
                var outputJson = firstResult.Output.ToString();
                if (string.IsNullOrEmpty(outputJson))
                {
                    return (new Dictionary<string, object>(), new Dictionary<string, object>(), false);
                }

                try
                {

                    var policyData = JsonConvert.DeserializeObject<Dictionary<string, JToken>>(outputJson, _jsonOptions);


                    var blockedSenders = policyData?.GetValueOrDefault("BlockedSenders")?.ToObject<object>();
                    var blockedDomains = policyData?.GetValueOrDefault("BlockedSenderDomains")?.ToObject<object>();
                    var allowedSenders = policyData?.GetValueOrDefault("AllowedSenders")?.ToObject<object>();
                    var allowedDomains = policyData?.GetValueOrDefault("AllowedSenderDomains")?.ToObject<object>();

                    var resultBlocked = new Dictionary<string, object>
                    {
                        ["sender_list"] = blockedSenders ?? new object(),
                        ["domain_list"] = blockedDomains ?? new object()
                    };

                    var resultAllowed = new Dictionary<string, object>
                    {
                        ["sender_list"] = allowedSenders ?? new object(),
                        ["domain_list"] = allowedDomains ?? new object()
                    };

                    return (resultBlocked, resultAllowed, true);
                }
                catch (JsonException ex)
                {
                    Console.WriteLine($"Warning: Failed to parse policy output: {ex.Message}");
                    return (new Dictionary<string, object>(), new Dictionary<string, object>(), false);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting sender lists: {ex.Message}");
                return (new Dictionary<string, object>(), new Dictionary<string, object>(), false);
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

                            var parsedResult = JsonConvert.DeserializeObject<Dictionary<string, JToken>>(outputJson, _jsonOptions);

                            return parsedResult?["value"].ToObject<object[]>() ?? Array.Empty<object>();
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

                            var parsedResult = JsonConvert.DeserializeObject<Dictionary<string, JToken>>(outputJson, _jsonOptions);

                            return parsedResult?["value"].ToObject<object[]>() ?? Array.Empty<object>();
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

                            var parsedResult = JsonConvert.DeserializeObject<Dictionary<string, JToken>>(outputJson, _jsonOptions);

                            return parsedResult?["value"].ToObject<object[]>() ?? Array.Empty<object>();
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

        #region PowerShell Command Builder

        /// <summary>
        /// Helper class for building PowerShell commands with proper parameter formatting
        /// </summary>
        public static class PowerShellCommandBuilder
        {
            /// <summary>
            /// Build a PowerShell command string for logging/debugging
            /// </summary>
            public static string BuildCommandString(string cmdlet, Dictionary<string, object>? parameters)
            {
                if (parameters == null || parameters.Count == 0)
                    return cmdlet;

                var command = cmdlet;
                foreach (var param in parameters)
                {
                    var value = FormatParameterValue(param.Value);
                    command += $" -{param.Key} {value}";
                }
                return command;
            }

            /// <summary>
            /// Format parameter values for PowerShell command string
            /// </summary>
            private static string FormatParameterValue(object value)
            {
                if (value == null) return "$null";

                switch (value)
                {
                    case string str:
                        return $"\"{str}\"";
                    case DateTime dt:
                        return $"\"{dt:yyyy-MM-ddTHH:mm:ssZ}\"";
                    case DateTimeOffset dto:
                        return $"\"{dto:yyyy-MM-ddTHH:mm:ssZ}\"";
                    case bool b:
                        return b ? "$true" : "$false";
                    case Array arr:
                        var elements = arr.Cast<object>().Select(FormatParameterValue);
                        return $"@({string.Join(", ", elements)})";
                    case IEnumerable<object> enumerable:
                        var items = enumerable.Select(FormatParameterValue);
                        return $"@({string.Join(", ", items)})";
                    default:
                        return value.ToString() ?? "$null";
                }
            }

            /// <summary>
            /// Convert C# dictionary to PowerShell-style parameters
            /// </summary>
            public static Dictionary<string, object> ConvertToPowerShellParameters(Dictionary<string, object> parameters)
            {
                var result = new Dictionary<string, object>();

                foreach (var param in parameters)
                {
                    var key = param.Key;
                    var value = param.Value;

                    if (value is DateTime dateTime)
                    {
                        value = dateTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
                    }
                    else if (value is bool boolValue)
                    {
                        value = boolValue;
                    }
                    else if (value is Array array)
                    {
                        value = array;
                    }

                    result[key] = value;
                }

                return result;
            }
        }

        #endregion

        #region Direct API Operations (Alternative to PowerShell Cmdlets)

        /// <summary>
        /// Get product licenses directly through Graph API (alternative to Get-ProductLicenses cmdlet)
        /// </summary>

        public async Task<object[]> GetProductLicensesDirectAsync(

            string[]? userIds = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // Use Graph API directly instead of PowerShell cmdlet

                var graphClient = _authManager.GraphClient
                    ?? throw new InvalidOperationException("Graph client not initialized");


                var users = new List<object>();

                if (userIds != null && userIds.Length > 0)
                {
                    // Get specific users
                    foreach (var userId in userIds)
                    {
                        try
                        {
                            var user = await graphClient.Users[userId]
                                .GetAsync(config =>
                                {
                                    config.QueryParameters.Select = new[] { "id", "userPrincipalName", "displayName", "assignedLicenses" };
                                }, cancellationToken);

                            if (user?.AssignedLicenses != null)
                            {
                                users.Add(new
                                {
                                    UserId = user.Id,
                                    UserPrincipalName = user.UserPrincipalName,
                                    DisplayName = user.DisplayName,
                                    AssignedLicenses = user.AssignedLicenses
                                });
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning: Failed to get licenses for user {userId}: {ex.Message}");
                        }
                    }
                }
                else
                {
                    // Get all users with licenses
                    var response = await graphClient.Users
                        .GetAsync(config =>
                        {
                            config.QueryParameters.Select = new[] { "id", "userPrincipalName", "displayName", "assignedLicenses" };
                            config.QueryParameters.Filter = "assignedLicenses/any()"; // Only users with licenses
                            config.QueryParameters.Top = 999;
                        }, cancellationToken);

                    if (response?.Value != null)
                    {
                        foreach (var user in response.Value)
                        {
                            if (user.AssignedLicenses != null)
                            {
                                users.Add(new
                                {
                                    UserId = user.Id,
                                    UserPrincipalName = user.UserPrincipalName,
                                    DisplayName = user.DisplayName,
                                    AssignedLicenses = user.AssignedLicenses
                                });
                            }
                        }
                    }
                }

                return users.ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting product licenses: {ex.Message}");
                return Array.Empty<object>();
            }
        }

        /// <summary>
        /// Get directory roles directly through Graph API (alternative to Get-Roles cmdlet)
        /// </summary>
        public async Task<object[]> GetRolesDirectAsync(CancellationToken cancellationToken = default)
        {
            try
            {

                var graphClient = _authManager.GraphClient
                    ?? throw new InvalidOperationException("Graph client not initialized");


                var roles = new List<object>();

                // Get directory roles
                var rolesResponse = await graphClient.DirectoryRoles
                    .GetAsync(config =>
                    {
                        config.QueryParameters.Select = new string[] { "id", "displayName", "description", "roleTemplateId" };
                        config.QueryParameters.Top = 999;
                    }, cancellationToken);

                if (rolesResponse?.Value != null)
                {
                    foreach (var role in rolesResponse.Value)
                    {
                        try
                        {
                            // Get members for each role
                            var membersResponse = await graphClient.DirectoryRoles[role.Id].Members
                                .GetAsync(config =>
                                {
                                    config.QueryParameters.Top = 999;
                                }, cancellationToken);

                            roles.Add(new
                            {
                                RoleId = role.Id,
                                DisplayName = role.DisplayName,
                                Description = role.Description,
                                RoleTemplateId = role.RoleTemplateId,
                                MemberCount = membersResponse?.Value?.Count ?? 0,
                                Members = membersResponse?.Value?.Select(m => new
                                {
                                    Id = m.Id,
                                    DisplayName = m.DisplayName,
                                    UserPrincipalName = m.UserPrincipalName
                                }).ToArray() ?? Array.Empty<object>()
                            });
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning: Failed to get members for role {role.DisplayName}: {ex.Message}");
                            // Add role without members
                            roles.Add(new
                            {
                                RoleId = role.Id,
                                DisplayName = role.DisplayName,
                                Description = role.Description,
                                RoleTemplateId = role.RoleTemplateId,
                                MemberCount = 0,
                                Members = Array.Empty<object>()
                            });
                        }
                    }
                }

                return roles.ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting roles: {ex.Message}");
                return Array.Empty<object>();
            }
        }

        /// <summary>
        /// Get OAuth permissions directly through Graph API (alternative to Get-OAuthPermissions cmdlet)
        /// </summary>
        public async Task<object[]> GetOAuthPermissionsDirectAsync(CancellationToken cancellationToken = default)
        {
            try
            {

                var graphClient = _authManager.GraphClient
                    ?? throw new InvalidOperationException("Graph client not initialized");


                var permissions = new List<object>();

                // Get service principals (applications)
                var servicePrincipalsResponse = await graphClient.ServicePrincipals
                    .GetAsync(config =>
                    {
                        config.QueryParameters.Select = new string[] { "id", "appId", "displayName", "appRoles", "oauth2PermissionScopes" };
                        config.QueryParameters.Top = 999;
                    }, cancellationToken);

                if (servicePrincipalsResponse?.Value != null)
                {
                    foreach (var sp in servicePrincipalsResponse.Value)
                    {
                        try
                        {
                            permissions.Add(new
                            {
                                ServicePrincipalId = sp.Id,
                                AppId = sp.AppId,
                                DisplayName = sp.DisplayName,
                                AppRoles = sp.AppRoles?.Select(ar => new
                                {
                                    Id = ar.Id,
                                    DisplayName = ar.DisplayName,
                                    Description = ar.Description,
                                    Value = ar.Value
                                }).ToArray() ?? Array.Empty<object>(),
                                OAuth2PermissionScopes = sp.Oauth2PermissionScopes?.Select(scope => new
                                {
                                    Id = scope.Id,
                                    Value = scope.Value,
                                    DisplayName = scope.DisplayName,
                                    Description = scope.Description,
                                    Type = scope.Type
                                }).ToArray() ?? Array.Empty<object>()
                            });
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning: Failed to process service principal {sp.DisplayName}: {ex.Message}");
                        }
                    }
                }

                return permissions.ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting OAuth permissions: {ex.Message}");
                return Array.Empty<object>();
            }
        }

        #endregion

        #region Unified Client Operations

        /// <summary>
        /// Unified method to get data either through PowerShell cmdlets or direct API calls
        /// Automatically falls back to API calls when PowerShell cmdlets fail
        /// </summary>
        public async Task<object[]> GetDataUnifiedAsync(
            string operation,
            Dictionary<string, object>? parameters = null,
            bool preferApi = false,
            CancellationToken cancellationToken = default)
        {
            try
            {
                // If preferApi is true or if we're not in PowerShell context, use direct API
                if (preferApi)
                {

                    return await GetDataViaApiAsync(operation, parameters, cancellationToken);

                }

                // Try PowerShell cmdlet first
                try
                {
                    var result = await ExecutePowerShellCommandAsync(operation, parameters, cancellationToken);
                    if (result?.Results != null && result.Results.Length > 0)
                    {
                        var firstResult = result.Results[0];
                        if (firstResult.Output != null)
                        {
                            var outputJson = firstResult.Output.ToString();
                            if (!string.IsNullOrEmpty(outputJson))
                            {
                                try
                                {

                                    var parsedResult = JsonConvert.DeserializeObject<Dictionary<string, JToken>>(outputJson, _jsonOptions);

                                    return parsedResult?["value"]?.ToObject<object[]>() ?? Array.Empty<object>();
                                }
                                catch (JsonException)
                                {
                                    // If parsing fails, return the raw output
                                    return new object[] { firstResult.Output };
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"PowerShell cmdlet failed for {operation}, falling back to API: {ex.Message}");
                }

                // Fall back to direct API call

                return await GetDataViaApiAsync(operation, parameters, cancellationToken);

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in unified data retrieval for {operation}: {ex.Message}");
                return Array.Empty<object>();
            }
        }

        /// <summary>
        /// Get data via direct API calls based on operation type
        /// </summary>
        private async Task<object[]> GetDataViaApiAsync(
            string operation,
            Dictionary<string, object>? parameters,
            CancellationToken cancellationToken)
        {
            // Map PowerShell cmdlets to their API equivalents
            switch (operation.ToLowerInvariant())
            {
                case "get-productlicenses":
                    var userIds = parameters?.GetValueOrDefault("UserIds") as string[];
                    return await GetProductLicensesDirectAsync(userIds, cancellationToken);

                case "get-roles":
                    return await GetRolesDirectAsync(cancellationToken);

                case "get-oauthpermissions":
                    return await GetOAuthPermissionsDirectAsync(cancellationToken);

                case "get-mailbox":

                    return await GetMailboxesAsync(cancellationToken);


                case "get-transportrule":

                    return await GetTransportRulesAsync(cancellationToken);


                case "get-inboxrule":
                    var mailbox = parameters?.GetValueOrDefault("Mailbox") as string;
                    if (!string.IsNullOrEmpty(mailbox))
                    {

                        var rules = await GetInboxRulesAsync(mailbox, cancellationToken);

                        return rules.Cast<object>().ToArray();
                    }
                    return Array.Empty<object>();

                case "get-mailboxpermission":
                    var mailboxForPerms = parameters?.GetValueOrDefault("Identity") as string;
                    if (!string.IsNullOrEmpty(mailboxForPerms))
                    {

                        return await GetMailboxPermissionsAsync(mailboxForPerms, cancellationToken);

                    }
                    return Array.Empty<object>();

                case "get-recipientpermission":
                    var recipient = parameters?.GetValueOrDefault("Identity") as string;
                    if (!string.IsNullOrEmpty(recipient))
                    {

                        return await GetRecipientPermissionsAsync(recipient, cancellationToken);

                    }
                    return Array.Empty<object>();

                case "get-sendaspermission":
                    var mailboxForSendAs = parameters?.GetValueOrDefault("Identity") as string;
                    if (!string.IsNullOrEmpty(mailboxForSendAs))
                    {

                        return await GetSendAsPermissionsAsync(mailboxForSendAs, cancellationToken);

                    }
                    return Array.Empty<object>();

                case "get-distributiongroup":

                    return await GetDistributionGroupsAsync(cancellationToken);


                case "get-mailflowrule":

                    return await GetMailFlowRulesAsync(cancellationToken);


                case "get-retentionpolicy":

                    return await GetRetentionPoliciesAsync(cancellationToken);


                default:
                    // For unknown operations, try to execute as a generic cmdlet
                    try
                    {

                        var result = await InvokeCommandAsync(operation, parameters, cancellationToken);

                        if (result?.Results != null && result.Results.Length > 0)
                        {
                            var firstResult = result.Results[0];
                            if (firstResult.Output != null)
                            {
                                var outputJson = firstResult.Output.ToString();
                                if (!string.IsNullOrEmpty(outputJson))
                                {
                                    try
                                    {

                                        var parsedResult = JsonConvert.DeserializeObject<Dictionary<string, JToken>>(outputJson, _jsonOptions);

                                        return parsedResult?["value"]?.ToObject<object[]>() ?? Array.Empty<object>();
                                    }
                                    catch (JsonException)
                                    {
                                        return new object[] { firstResult.Output };
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to execute {operation} via API: {ex.Message}");
                    }
                    return Array.Empty<object>();
            }
        }

        #endregion

        #region Usage Examples and Documentation

        /// <summary>
        /// Example usage of the unified client approach
        /// This demonstrates how to use the client both in PowerShell and API contexts
        /// </summary>
        public static class UsageExamples
        {
            /// <summary>
            /// Example: Get product licenses using the unified approach
            /// </summary>
            public static async Task<object[]> GetProductLicensesExample(
                ExchangeRestClient client,
                CancellationToken cancellationToken = default)
            {
                // This will automatically try PowerShell cmdlets first, then fall back to API calls
                return await client.GetDataUnifiedAsync("Get-ProductLicenses", cancellationToken: cancellationToken);
            }

            /// <summary>
            /// Example: Get roles using the unified approach
            /// </summary>
            public static async Task<object[]> GetRolesExample(
                ExchangeRestClient client,
                CancellationToken cancellationToken = default)
            {
                // This will automatically try PowerShell cmdlets first, then fall back to API calls
                return await client.GetDataUnifiedAsync("Get-Roles", cancellationToken: cancellationToken);
            }

            /// <summary>
            /// Example: Get OAuth permissions using the unified approach
            /// </summary>
            public static async Task<object[]> GetOAuthPermissionsExample(
                ExchangeRestClient client,
                CancellationToken cancellationToken = default)
            {
                // This will automatically try PowerShell cmdlets first, then fall back to API calls
                return await client.GetDataUnifiedAsync("Get-OAuthPermissions", cancellationToken: cancellationToken);
            }

            /// <summary>
            /// Example: Force API usage instead of PowerShell cmdlets
            /// </summary>
            public static async Task<object[]> ForceApiUsageExample(
                ExchangeRestClient client,
                CancellationToken cancellationToken = default)
            {
                // This will skip PowerShell cmdlets and go directly to API calls
                return await client.GetDataUnifiedAsync("Get-ProductLicenses", preferApi: true, cancellationToken: cancellationToken);
            }

            /// <summary>
            /// Example: Execute custom PowerShell cmdlets with parameters
            /// </summary>
            public static async Task<object[]> CustomCmdletExample(
                ExchangeRestClient client,
                CancellationToken cancellationToken = default)
            {
                var parameters = new Dictionary<string, object>
                {
                    ["Identity"] = "user@domain.com",
                    ["ResultSize"] = 1000
                };

                return await client.GetDataUnifiedAsync("Get-MailboxAuditLog", parameters, cancellationToken: cancellationToken);
            }
        }

        /// <summary>
        /// Troubleshooting guide for common issues
        /// </summary>
        public static class Troubleshooting
        {
            /// <summary>
            /// Common error: PowerShell cmdlet execution fails
            /// Solution: Use preferApi: true or the direct API methods
            /// </summary>
            public static string PowerShellCmdletFailureSolution =>
                "When PowerShell cmdlets fail with 'WriteObject and WriteError methods cannot be called' errors, " +
                "use the direct API methods or set preferApi: true in GetDataUnifiedAsync calls.";

            /// <summary>
            /// Common error: Authentication issues
            /// Solution: Ensure proper Exchange Online connection
            /// </summary>
            public static string AuthenticationIssueSolution =>
                "Ensure you have connected to Exchange Online using ConnectGraphAsync(includeExchangeOnline: true) " +
                "or ConnectExchangeOnlineAsync().";

            /// <summary>
            /// Common error: Permission denied
            /// Solution: Check Exchange Online permissions
            /// </summary>
            public static string PermissionIssueSolution =>

                "Ensure your

permissions. " +
                "Try using Graph API alternatives for basic operations.";

            /// <summary>
            /// Common error: Rate limiting
            /// Solution: The client automatically handles rate limiting
            /// </summary>
            public static string RateLimitSolution =>

                "The client automatically handles rate limiting with exp

backoff. " +
                "If you encounter issues, increase the retry count or add delays between operations.";

        }


        #endregion


        public void Dispose()

        {

            _httpClient?.Dispose();


            _rateLimitSemaphore?.Dispose();

        }
    }


    // Custom DateTime converter for Newtonsoft.Json

    public class DateTimeOffsetConverter : JsonConverter<DateTimeOffset>
    {
        public override DateTimeOffset ReadJson(JsonReader reader, Type objectType, DateTimeOffset existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.String)
            {
                var value = reader.Value?.ToString();
                if (DateTimeOffset.TryParse(value, out var result))
                    return result;
            }
            return DateTimeOffset.MinValue;
        }

        public override void WriteJson(JsonWriter writer, DateTimeOffset value, JsonSerializer serializer)
        {
            writer.WriteValue(value.ToString("yyyy-MM-ddTHH:mm:ssZ"));
        }
    }
}
