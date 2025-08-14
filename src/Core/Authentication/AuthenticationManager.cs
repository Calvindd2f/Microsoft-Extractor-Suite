using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Microsoft.Graph;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;
using System.Net.Http.Headers;

namespace Microsoft.ExtractorSuite.Core.Authentication
{
    public class AuthenticationInfo
    {
        public bool IsGraphConnected { get; set; }
        public bool IsAzureConnected { get; set; }
        public string? TenantId { get; set; }
        public string? UserPrincipalName { get; set; }
    }

    public class MsalTokenCredential : TokenCredential
    {
        private readonly IPublicClientApplication _clientApp;
        private readonly string[] _scopes;

        public MsalTokenCredential(IPublicClientApplication clientApp, string[] scopes)
        {
            _clientApp = clientApp;
            _scopes = scopes;
        }

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return new ValueTask<AccessToken>(GetTokenInternalAsync(requestContext, cancellationToken));
        }

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            // Run on thread pool to avoid STA thread issues
            return Task.Run(async () => await GetTokenAsync(requestContext, cancellationToken).ConfigureAwait(false))
                .GetAwaiter().GetResult();
        }

        private async Task<AccessToken> GetTokenInternalAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            var accounts = await _clientApp.GetAccountsAsync();
            
            try
            {
                var result = await _clientApp.AcquireTokenSilent(_scopes, accounts.FirstOrDefault())
                    .ExecuteAsync(cancellationToken);
                
                return new AccessToken(result.AccessToken, result.ExpiresOn);
            }
            catch (MsalUiRequiredException)
            {
                var result = await _clientApp.AcquireTokenInteractive(_scopes)
                    .ExecuteAsync(cancellationToken);
                
                return new AccessToken(result.AccessToken, result.ExpiresOn);
            }
        }
    }

    public class AuthenticationManager
    {
        private static AuthenticationManager? _instance;
        private static readonly object _lock = new object();

        private IPublicClientApplication? _publicClientApp;
        private GraphServiceClient? _graphClient;
        private GraphServiceClient? _betaGraphClient;
        private TokenCredential? _azureCredential;
        private AuthenticationResult? _currentAuthResult;
        private AuthenticationResult? _exchangeAuthResult;
        private string? _currentTenantId;

        // Use Exchange Online Management app ID for Exchange operations
        private const string GraphClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"; // Microsoft Graph PowerShell client ID
        private const string ExchangeClientId = "fb78d390-0c51-40cd-8e17-fdbfab77341b"; // Exchange Online Management client ID
        private const string Authority = "https://login.microsoftonline.com/organizations";

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

        private AuthenticationManager()
        {
            InitializePublicClient();
        }

        private void InitializePublicClient()
        {
            var builder = PublicClientApplicationBuilder
                .Create(GraphClientId)
                .WithAuthority(Authority)
                .WithDefaultRedirectUri();

            _publicClientApp = builder.Build();

            // Enable token cache serialization for persistence
            Task.Run(async () => await EnableTokenCacheSerialization());
        }

        private async Task EnableTokenCacheSerialization()
        {
            if (_publicClientApp == null) return;

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

            cacheHelper.RegisterCache(_publicClientApp.UserTokenCache);
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
                _currentTenantId = tenantId ?? "organizations";

                // Create a separate app for Exchange Online Management
                var exchangeApp = PublicClientApplicationBuilder
                    .Create(ExchangeClientId)
                    .WithAuthority($"https://login.microsoftonline.com/{_currentTenantId}")
                    .WithDefaultRedirectUri()
                    .Build();

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
                _exchangeAuthResult = result;
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to connect to Exchange Online: {ex.Message}");
                return false;
            }
        }

        public async Task<bool> ConnectGraphAsync(
            string[]? scopes = null,
            string? tenantId = null,
            bool useBeta = false,
            bool includeExchangeOnline = false,
            CancellationToken cancellationToken = default)
        {
            try
            {
                _currentTenantId = tenantId ?? "organizations";

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
                    // Exchange Online uses a different resource ID
                    await GetExchangeOnlineTokenAsync(cancellationToken);
                }

                var requestedScopes = scopes ?? defaultScopes;

                // Try silent authentication first
                var accounts = await _publicClientApp!.GetAccountsAsync();

                try
                {
                    _currentAuthResult = await _publicClientApp.AcquireTokenSilent(
                        requestedScopes,
                        accounts.FirstOrDefault()
                    ).ExecuteAsync(cancellationToken);
                }
                catch (MsalUiRequiredException)
                {
                    // Interactive authentication required
                    _currentAuthResult = await _publicClientApp.AcquireTokenInteractive(requestedScopes)
                        .WithAuthority($"https://login.microsoftonline.com/{_currentTenantId}")
                        .ExecuteAsync(cancellationToken);
                }

                // Create Graph client using the token credential
                var tokenCredential = new MsalTokenCredential(_publicClientApp, requestedScopes.ToArray());

                if (useBeta)
                {
                    _betaGraphClient = new GraphServiceClient(tokenCredential, scopes: null, baseUrl: "https://graph.microsoft.com/beta");
                }
                else
                {
                    _graphClient = new GraphServiceClient(tokenCredential);
                }

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
                _currentTenantId = tenantId ?? "organizations";

                var options = new InteractiveBrowserCredentialOptions
                {
                    TenantId = _currentTenantId,
                    ClientId = GraphClientId,
                    RedirectUri = new Uri("http://localhost"),
                    AuthorityHost = AzureAuthorityHosts.AzurePublicCloud
                };

                _azureCredential = new InteractiveBrowserCredential(options);

                // Test the credential
                var tokenRequestContext = new TokenRequestContext(
                    new[] { "https://management.azure.com/.default" }
                );

                var token = await _azureCredential.GetTokenAsync(tokenRequestContext, cancellationToken);

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
                // First check if we have a valid Exchange token from ConnectExchangeOnlineAsync
                if (_exchangeAuthResult != null && _exchangeAuthResult.ExpiresOn > DateTimeOffset.UtcNow)
                {
                    return _exchangeAuthResult.AccessToken;
                }

                // If no Exchange token, try to connect to Exchange Online
                var connected = await ConnectExchangeOnlineAsync(_currentTenantId, cancellationToken);
                if (connected && _exchangeAuthResult != null)
                {
                    return _exchangeAuthResult.AccessToken;
                }

                // Fall back to Graph token if available (for basic mail operations)
                if (_currentAuthResult != null && _currentAuthResult.ExpiresOn > DateTimeOffset.UtcNow)
                {
                    // Check if the token has Mail permissions for basic operations
                    if (_currentAuthResult.Scopes.Any(s => s.Contains("Mail.")))
                    {
                        Console.WriteLine("Using Graph token for Exchange operations (limited functionality)");
                        return _currentAuthResult.AccessToken;
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to get Exchange Online token: {ex.Message}");
                return null;
            }
        }

        public GraphServiceClient? GraphClient => _graphClient;
        public GraphServiceClient? BetaGraphClient => _betaGraphClient;
        public TokenCredential? AzureCredential => _azureCredential;
        public string? CurrentTenantId => _currentTenantId;
        public string? CurrentTenantDomain => _currentTenantId; // For compatibility, can be enhanced later
        public string CurrentLevel => IsGraphConnected ? "Graph" : "None"; // For compatibility
        public bool IsGraphConnected => _graphClient != null || _betaGraphClient != null;
        public bool IsAzureConnected => _azureCredential != null;
        public bool IsExchangeConnected => _exchangeAuthResult != null && _exchangeAuthResult.ExpiresOn > DateTimeOffset.UtcNow;

        // Additional async methods for compatibility
        public Task<bool> IsConnectedAsync()
        {
            return Task.FromResult(IsGraphConnected || IsAzureConnected);
        }

        public Task<AuthenticationInfo> GetAuthenticationInfoAsync()
        {
            var info = new AuthenticationInfo
            {
                IsGraphConnected = IsGraphConnected,
                IsAzureConnected = IsAzureConnected,
                TenantId = CurrentTenantId,
                UserPrincipalName = _currentAuthResult?.Account?.Username
            };
            return Task.FromResult(info);
        }

        public Task<string?> GetAccessTokenAsync(string[] scopes, CancellationToken cancellationToken = default)
        {
            if (_currentAuthResult != null && _currentAuthResult.ExpiresOn.Subtract(TimeSpan.FromMinutes(5)) > DateTimeOffset.UtcNow)
            {
                return Task.FromResult<string?>(_currentAuthResult.AccessToken);
            }

            // Token expired or not available, need to refresh
            return RefreshAccessTokenAsync(scopes, cancellationToken);
        }

        private async Task<string?> RefreshAccessTokenAsync(string[] scopes, CancellationToken cancellationToken)
        {
            try
            {
                var accounts = await _publicClientApp!.GetAccountsAsync();
                var result = await _publicClientApp.AcquireTokenSilent(scopes, accounts.FirstOrDefault())
                    .ExecuteAsync(cancellationToken);
                
                _currentAuthResult = result;
                return result.AccessToken;
            }
            catch (MsalUiRequiredException)
            {
                // Silent acquisition failed, interactive auth required
                var result = await _publicClientApp!.AcquireTokenInteractive(scopes)
                    .WithAuthority($"https://login.microsoftonline.com/{_currentTenantId ?? "organizations"}")
                    .ExecuteAsync(cancellationToken);
                
                _currentAuthResult = result;
                return result.AccessToken;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public void Disconnect()
        {
            _graphClient = null;
            _betaGraphClient = null;
            _azureCredential = null;
            _currentAuthResult = null;
            _currentTenantId = null;

            // Clear token cache
            if (_publicClientApp != null)
            {
                // Run on thread pool to avoid STA thread issues
                Task.Run(async () =>
                {
                    var accounts = await _publicClientApp.GetAccountsAsync().ConfigureAwait(false);
                    foreach (var account in accounts)
                    {
                        await _publicClientApp.RemoveAsync(account).ConfigureAwait(false);
                    }
                }).GetAwaiter().GetResult();
            }
        }
    }
}
