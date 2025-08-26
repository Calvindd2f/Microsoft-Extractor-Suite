namespace Microsoft.ExtractorSuite.Core.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net.Http.Headers;
    using System.Threading;
    using System.Threading.Tasks;
    using Azure.Core;
    using Azure.Identity;
    using Microsoft.Graph;
    using Microsoft.Identity.Client;
    using Microsoft.Identity.Client.Extensions.Msal;


#pragma warning disable SA1600
#pragma warning disable SA1649
name
    public class AuthenticationInfo
#pragma warning restore SA1649
name
    {
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsGraphConnected { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsAzureConnected { get; set; }
        public string? TenantId { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? UserPrincipalName { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class MsalTokenCredential : TokenCredential
#pragma warning restore SA1600
    {
#pragma warning disable SA1309
        private readonly IPublicClientApplication _clientApp;
#pragma warning restore SA1309
#pragma warning disable SA1600
#pragma warning disable SA1309
#pragma warning restore SA1600
        private readonly string[] _scopes;
#pragma warning restore SA1309

        public MsalTokenCredential(IPublicClientApplication clientApp, string[] scopes)
        {
#pragma warning disable SA1600
#pragma warning disable SA1101
            _clientApp = clientApp;
#pragma warning restore SA1101
#pragma warning disable SA1101
            _scopes = scopes;
#pragma warning restore SA1101
        }

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
#pragma warning disable SA1600
        {
#pragma warning restore SA1600
#pragma warning disable SA1101
            return new ValueTask<AccessToken>(GetTokenInternalAsync(requestContext, cancellationToken));
#pragma warning restore SA1101
        }

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            // Run on thread pool to avoid STA thread issues
#pragma warning disable SA1101
            return Task.Run(async () => await GetTokenAsync(requestContext, cancellationToken).ConfigureAwait(false))
                .GetAwaiter().GetResult();
#pragma warning restore SA1101
        }

        private async Task<AccessToken> GetTokenInternalAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var accounts = await _clientApp.GetAccountsAsync();
#pragma warning restore SA1101

            try
            {
#pragma warning disable SA1101
                var result = await _clientApp.AcquireTokenSilent(_scopes, accounts.FirstOrDefault())
                    .ExecuteAsync(cancellationToken);
#pragma warning restore SA1101

                return new AccessToken(result.AccessToken, result.ExpiresOn);
            }
            catch (MsalUiRequiredException)
            {
#pragma warning disable SA1101
                var result = await _clientApp.AcquireTokenInteractive(_scopes)
                    .ExecuteAsync(cancellationToken);
#pragma warning restore SA1101

                return new AccessToken(result.AccessToken, result.ExpiresOn);
#pragma warning disable SA1600
            }
#pragma warning restore SA1600
        }
    }

    public class AuthenticationManager
    {
#pragma warning disable SA1309
        private static AuthenticationManager? _instance;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private static readonly object _lock = new object();
#pragma warning restore SA1309

#pragma warning disable SA1309
        private IPublicClientApplication? _publicClientApp;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private GraphServiceClient? _graphClient;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private GraphServiceClient? _betaGraphClient;
#pragma warning restore SA1309
#pragma warning disable SA1600
#pragma warning disable SA1309
#pragma warning restore SA1600
        private TokenCredential? _azureCredential;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private AuthenticationResult? _currentAuthResult;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private AuthenticationResult? _exchangeAuthResult;
#pragma warning restore SA1309
#pragma warning disable SA1309
        private string? _currentTenantId;
#pragma warning restore SA1309

        // Use Exchange Online Management app ID for Exchange operations
        private const string GraphClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"; // Microsoft Graph PowerShell client ID
        private const string ExchangeClientId = "fb78d390-0c51-40cd-8e17-fdbfab77341b"; // Exchange Online Management client ID
        private const string Authority = "https://login.microsoftonline.com/organizations";

        private const string ExchangeScope = "https://outlook.office365.com/.default";

        private const string[] GraphScopes = new[] { "User.Read.All", "Group.Read.All", "Directory.Read.All", "AuditLog.Read.All", "SecurityEvents.Read.All", "IdentityRiskyUser.Read.All", "Policy.Read.All", "Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings.Read", "MailboxSettings.ReadWrite", "Calendars.Read", "Calendars.ReadWrite", "Reports.Read.All" };

        public static AuthenticationManager Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        if (_instance == null)
                        {
                            _instance = new AuthenticationManager();
                        }
                    }
                }
                return _instance;
            }
        }

#pragma warning disable SA1201
        private AuthenticationManager()
#pragma warning restore SA1201
        {
#pragma warning disable SA1101
            InitializePublicClient();
#pragma warning restore SA1101
        }

        private void InitializePublicClient()
        {
            var builder = PublicClientApplicationBuilder
                .Create(GraphClientId)
                .WithAuthority(Authority)
                .WithDefaultRedirectUri();

#pragma warning disable SA1101
            _publicClientApp = builder.Build();
#pragma warning restore SA1101

            // Enable token cache serialization for persistence
#pragma warning disable SA1101
            Task.Run(async () => await EnableTokenCacheSerialization());
#pragma warning restore SA1101
        }

        private async Task EnableTokenCacheSerialization()
        {
#pragma warning disable SA1101
            if (_publicClientApp == null) return;
#pragma warning restore SA1101

            var cacheDirectory = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft-Extractor-Suite",
                ".cache");

            Directory.CreateDirectory(cacheDirectory);

            var storageProperties = new StorageCreationPropertiesBuilder("msal.cache", cacheDirectory);

            // Configure platform-specific storage
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Linux))
            {
                storageProperties = storageProperties.WithLinuxKeyring(
                    schemaName: "com.microsoft.adalcache",
                    collection: "default",
                    secretLabel: "MSALCache",
                    attribute1: new KeyValuePair<string, string>("MsalClientID", GraphClientId),
                    attribute2: new KeyValuePair<string, string>("Microsoft.Developer.IdentityService", "1.0.0.0"));
            }
            else if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.OSX))
            {
                storageProperties = storageProperties.WithMacKeyChain("Microsoft.Developer.IdentityService", "MSALCache");
            }

            var cacheHelper = await MsalCacheHelper.CreateAsync(storageProperties.Build());

#pragma warning disable SA1101
            cacheHelper.RegisterCache(_publicClientApp.UserTokenCache);
#pragma warning restore SA1101
        }

        /// <summary>
        /// Connect to Exchange Online Management using the official Exchange client ID
        /// This provides access to Exchange Admin API endpoints
        /// </summary>
        public async Task<bool> ConnectExchangeOnlineAsync(
            string? tenantId = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
#pragma warning disable SA1101
                _currentTenantId = tenantId ?? "organizations";
#pragma warning restore SA1101

                // Create a separate app for Exchange Online Management
#pragma warning disable SA1101
                var exchangeApp = PublicClientApplicationBuilder
                    .Create(ExchangeClientId)
                    .WithAuthority($"https://login.microsoftonline.com/{_currentTenantId}")
                    .WithDefaultRedirectUri()
                    .Build();
#pragma warning restore SA1101

                // Exchange Online Management uses specific scopes
                var scopes = new[] { "https://outlook.office365.com/.default" };

                var accounts = await exchangeApp.GetAccountsAsync();
                AuthenticationResult result;

                try
                {
                    result = await exchangeApp.AcquireTokenSilent(scopes, accounts.FirstOrDefault())
                        .ExecuteAsync(cancellationToken);
                }
                catch (MsalUiRequiredException)
                {
                    // Interactive authentication required
                    result = await exchangeApp.AcquireTokenInteractive(scopes)
                        .WithPrompt(Microsoft.Identity.Client.Prompt.SelectAccount)
                        .ExecuteAsync(cancellationToken);
                }

                // Store the Exchange token for later use
#pragma warning disable SA1101
                _exchangeAuthResult = result;
#pragma warning restore SA1101

#pragma warning disable SA1101
                Console.WriteLine($"Successfully connected to Exchange Online for tenant: {_currentTenantId}");
#pragma warning restore SA1101
                Console.WriteLine($"Token expires: {result.ExpiresOn}");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to connect to Exchange Online: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Enhanced method to connect to Graph with optional Exchange Online support
        /// </summary>
        public async Task<bool> ConnectGraphAsync(
            string[]? scopes = null,
            string? tenantId = null,
            bool useBeta = false,
            bool includeExchangeOnline = false,
            CancellationToken cancellationToken = default)
        {
            try
            {
#pragma warning disable SA1101
                _currentTenantId = tenantId ?? "organizations";
#pragma warning restore SA1101

                var defaultScopes = new[]
                {
                    "User.Read",
                    "User.Read.All",
                    "Group.Read.All",
                    "Directory.Read.All",
                    "AuditLog.Read.All",
                    "SecurityEvents.Read.All",
                    "IdentityRiskyUser.Read.All",
                    "Policy.Read.All",
                    "Mail.Read",
                    "Mail.ReadWrite",
                    "Mail.Send",
                    "MailboxSettings.Read",
                    "MailboxSettings.ReadWrite",
                    "Calendars.Read",
                    "Calendars.ReadWrite",
                    "Reports.Read.All"
                };

                // If Exchange Online access is requested, also get the Exchange token
                if (includeExchangeOnline)
                {
                    Console.WriteLine("Connecting to Exchange Online as part of Graph connection...");
#pragma warning disable SA1101
                    var exchangeConnected = await ConnectExchangeOnlineAsync(_currentTenantId, cancellationToken);
#pragma warning restore SA1101
                    if (!exchangeConnected)
                    {
                        Console.WriteLine("Warning: Failed to connect to Exchange Online. Some Exchange operations may not work.");
                    }
                }

                var requestedScopes = scopes ?? defaultScopes;

                // Try silent authentication first
#pragma warning disable SA1101
                var accounts = await _publicClientApp!.GetAccountsAsync();
#pragma warning restore SA1101

                try
                {
#pragma warning disable SA1101
                    _currentAuthResult = await _publicClientApp.AcquireTokenSilent(
                        requestedScopes,
                        accounts.FirstOrDefault()
                    ).ExecuteAsync(cancellationToken);
#pragma warning restore SA1101
                }
                catch (MsalUiRequiredException)
                {
                    // Interactive authentication required
#pragma warning disable SA1101
                    _currentAuthResult = await _publicClientApp.AcquireTokenInteractive(requestedScopes)
                        .WithAuthority($"https://login.microsoftonline.com/{_currentTenantId}")
                        .ExecuteAsync(cancellationToken);
#pragma warning restore SA1101
                }

#pragma warning disable SA1600
                // Create Graph client using the t
#pragma warning restore SA1600
credential
#pragma warning disable SA1101
                var tokenCredential = new MsalTokenCredential(_publicClientApp, requestedScopes.ToArray());
#pragma warning restore SA1101

                if (useBeta)
                {
#pragma warning disable SA1101
                    _betaGraphClient = new GraphServiceClient(tokenCredential, scopes: null, baseUrl: "https://graph.microsoft.com/beta");
#pragma warning restore SA1101
                }
                else
                {
#pragma warning disable SA1101
                    _graphClient = new GraphServiceClient(tokenCredential);
#pragma warning restore SA1101
                }

#pragma warning disable SA1101
                Console.WriteLine($"Successfully connected to Microsoft Graph for tenant: {_currentTenantId}");
#pragma warning restore SA1101
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Authentication failed: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> ConnectAzureAsync(
            string? tenantId = null,
            CancellationToken cancellationToken = default)
        {
            try
            {
#pragma warning disable SA1101
                _currentTenantId = tenantId ?? "organizations";
#pragma warning restore SA1101

#pragma warning disable SA1101
                var options = new InteractiveBrowserCredentialOptions
                {
                    TenantId = _currentTenantId,
                    ClientId = GraphClientId,
#pragma warning disable SA1600
                    RedirectUri = new Uri("http://localhost"),
#pragma warning restore SA1600
                    AuthorityHost = AzureAuthorityHosts.AzurePublicCloud
                };
#pragma warning restore SA1101

#pragma warning disable SA1101
                _azureCredential = new InteractiveBrowserCredential(options);
#pragma warning restore SA1101

                // Test the credential
                var tokenRequestContext = new TokenRequestContext(
                    new[] { "https://management.azure.com/.default" }
                );

#pragma warning disable SA1101
                var token = await _azureCredential.GetTokenAsync(tokenRequestContext, cancellationToken);
#pragma warning restore SA1101

                return !string.IsNullOrEmpty(token.Token);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Azure authentication failed: {ex.Message}");
                return false;
            }
        }

        public async Task<string?> GetExchangeOnlineTokenAsync(CancellationToken cancellationToken = default)
        {
            try
            {
#pragma warning disable SA1101
                if (_exchangeAuthResult != null && _exchangeAuthResult.ExpiresOn > DateTimeOffset.UtcNow)
                {
#pragma warning disable SA1101
                    return _exchangeAuthResult.AccessToken;
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

#pragma warning disable SA1101
                var connected = await ConnectExchangeOnlineAsync(_currentTenantId, cancellationToken);
#pragma warning restore SA1101
#pragma warning disable SA1101
                if (connected && _exchangeAuthResult != null)
#pragma warning disable SA1600
                {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning disable SA1101
                    return _exchangeAuthResult.AccessToken;
#pragma warning restore SA1101
#pragma warning disable SA1600
                }
#pragma warning restore SA1101
#pragma warning disable SA1600

#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning disable SA1101
                if (_currentAuthResult != null && _currentAuthResult.ExpiresOn > DateTimeOffset.UtcNow)
#pragma warning restore SA1600
#pragma warning disable SA1600
                {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning disable SA1101
                    if (_currentAuthResult.Scopes.Any(s => s.Contains("Mail.")))
#pragma warning restore SA1600
#pragma warning disable SA1600
                    {
#pragma warning restore SA1600
#pragma warning disable SA1600
                        Console.WriteLine("Using Graph token for Exchange operations (limited functionality)");
#pragma warning restore SA1600
#pragma warning disable SA1101
                        return _currentAuthResult.AccessToken;
#pragma warning restore SA1101
                    }
#pragma warning restore SA1101
#pragma warning disable SA1600
                }
#pragma warning restore SA1101
#pragma warning restore SA1600

                return null;
            }
            catch (Exception ex)
#pragma warning disable SA1600
            {
#pragma warning restore SA1600
                Console.WriteLine($"Failed to get Exchange Online token: {ex.Message}");
                return null;
            }
        }

#pragma warning disable SA1101
#pragma warning disable SA1201
        public GraphServiceClient? GraphClient => _graphClient;
#pragma warning restore SA1201
#pragma warning disable SA1101
        public GraphServiceClient? BetaGraphClient => _betaGraphClient;
#pragma warning restore SA1101
#pragma warning disable SA1101
        public TokenCredential? AzureCredential => _azureCredential;
#pragma warning restore SA1101
#pragma warning disable SA1101
        public string? CurrentTenantId => _currentTenantId;
#pragma warning restore SA1101
#pragma warning disable SA1101
        public string? CurrentTenantDomain => _currentTenantId; // For compatibility, can be enhanced later
#pragma warning restore SA1101
#pragma warning disable SA1101
        public string CurrentLevel => IsGraphConnected ? "Graph" : "None"; // For compatibility
#pragma warning restore SA1101
#pragma warning disable SA1600
#pragma warning disable SA1101
        public bool IsGraphConnected => _graphClient != null || _betaGraphClient != null;
#pragma warning restore SA1101
#pragma warning restore SA1600
#pragma warning disable SA1101
        public bool IsAzureConnected => _azureCredential != null;
#pragma warning restore SA1101
#pragma warning disable SA1101
        public bool IsExchangeConnected => _exchangeAuthResult != null && _exchangeAuthResult.ExpiresOn > DateTimeOffset.UtcNow;
#pragma warning restore SA1101

        // Additional async methods for compatibility
        public Task<bool> IsConnectedAsync()
        {
#pragma warning disable SA1101
            return Task.FromResult(IsGraphConnected || IsAzureConnected);
#pragma warning restore SA1101
        }

        public Task<AuthenticationInfo> GetAuthenticationInfoAsync()
        {
#pragma warning disable SA1101
            var info = new AuthenticationInfo
            {
                IsGraphConnected = IsGraphConnected,
                IsAzureConnected = IsAzureConnected,
                TenantId = CurrentTenantId,
                UserPrincipalName = _currentAuthResult?.Account?.Username
            };
#pragma warning restore SA1101
            return Task.FromResult(info);
        }

        public Task<string?> GetAccessTokenAsync(string[] scopes, CancellationToken cancellationToken = default)
        {
#pragma warning disable SA1101
            if (_currentAuthResult != null && _currentAuthResult.ExpiresOn.Subtract(TimeSpan.FromMinutes(5)) > DateTimeOffset.UtcNow)
            {
#pragma warning disable SA1101
                return Task.FromResult<string?>(_currentAuthResult.AccessToken);
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            // Token expired or not available, need to refresh
#pragma warning disable SA1101
            return RefreshAccessTokenAsync(scopes, cancellationToken);
#pragma warning restore SA1101
        }

        private async Task<string?> RefreshAccessTokenAsync(string[] scopes, CancellationToken cancellationToken)
        {
            try
            {
#pragma warning disable SA1101
                var accounts = await _publicClientApp!.GetAccountsAsync();
#pragma warning restore SA1101
#pragma warning disable SA1600
                var result = awa
#pragma warning restore SA1600
accounts.FirstOrDefault())
                    .ExecuteAsync(cancellationToken);

#pragma warning disable SA1101
                _currentAuthResult = result;
#pragma warning restore SA1101
                return result.AccessToken;
            }
            catch (MsalUiRequiredException)
            {
                // Silent acquisition failed, interactive auth required
#pragma warning disable SA1101
                var result = await _publicClientApp!.AcquireTokenInteractive(scopes)
                    .WithAuthority($"https://login.microsoftonline.com/{_currentTenantId ?? "organizations"}")
                    .ExecuteAsync(cancellationToken);
#pragma warning restore SA1101

#pragma warning disable SA1101
                _currentAuthResult = result;
#pragma warning restore SA1101
                return result.AccessToken;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public void Disconnect()
        {
#pragma warning disable SA1101
            _graphClient = null;
#pragma warning restore SA1101
#pragma warning disable SA1101
            _betaGraphClient = null;
#pragma warning restore SA1101
#pragma warning disable SA1101
            _azureCredential = null;
#pragma warning restore SA1101
#pragma warning disable SA1101
            _currentAuthResult = null;
#pragma warning restore SA1101
#pragma warning disable SA1101
            _currentTenantId = null;
#pragma warning restore SA1101

            // Clear token cache
#pragma warning disable SA1101
            if (_publicClientApp != null)
            {
                // Run on thread pool to avoid STA thread issues
                Task.Run(async () =>
                {
#pragma warning disable SA1101
                    var accounts = await _publicClientApp.GetAccountsAsync().ConfigureAwait(false);
#pragma warning restore SA1101
                    foreach (var account in accounts)
                    {
#pragma warning disable SA1101
                        await _publicClientApp.RemoveAsync(account).ConfigureAwait(false);
#pragma warning restore SA1101
                    }
                }).GetAwaiter().GetResult();
            }
#pragma warning restore SA1101
        }
    }
}
