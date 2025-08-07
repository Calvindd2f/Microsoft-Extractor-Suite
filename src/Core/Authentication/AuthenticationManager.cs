using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Microsoft.Graph;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;

namespace Microsoft.ExtractorSuite.Core.Authentication
{
    public class AuthenticationManager
    {
        private static AuthenticationManager? _instance;
        private static readonly object _lock = new object();
        
        private IPublicClientApplication? _publicClientApp;
        private GraphServiceClient? _graphClient;
        private GraphServiceClient? _betaGraphClient;
        private TokenCredential? _azureCredential;
        private AuthenticationResult? _currentAuthResult;
        private string? _currentTenantId;
        
        private const string ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"; // Microsoft Graph PowerShell client ID
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
                .Create(ClientId)
                .WithAuthority(Authority)
                .WithDefaultRedirectUri();
            
            _publicClientApp = builder.Build();
            
            // Enable token cache serialization for persistence
            Task.Run(async () => await EnableTokenCacheSerialization());
        }
        
        private async Task EnableTokenCacheSerialization()
        {
            if (_publicClientApp == null) return;
            
            var cacheHelper = await MsalCacheHelper.CreateAsync(
                new StorageCreationProperties(
                    "msal.cache",
                    System.IO.Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "Microsoft-Extractor-Suite",
                        ".cache"
                    )
                )
            );
            
            cacheHelper.RegisterCache(_publicClientApp.UserTokenCache);
        }
        
        public async Task<bool> ConnectGraphAsync(
            string[]? scopes = null,
            string? tenantId = null,
            bool useBeta = false,
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
                    "MailboxSettings.Read"
                };
                
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
                
                // Create Graph client
                var authProvider = new DelegateAuthenticationProvider(async (request) =>
                {
                    request.Headers.Authorization = 
                        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _currentAuthResult.AccessToken);
                });
                
                if (useBeta)
                {
                    _betaGraphClient = new GraphServiceClient(authProvider)
                    {
                        BaseUrl = "https://graph.microsoft.com/beta"
                    };
                }
                else
                {
                    _graphClient = new GraphServiceClient(authProvider);
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
                    ClientId = ClientId,
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
                var scopes = new[] { "https://outlook.office365.com/.default" };
                
                var accounts = await _publicClientApp!.GetAccountsAsync();
                AuthenticationResult result;
                
                try
                {
                    result = await _publicClientApp.AcquireTokenSilent(scopes, accounts.FirstOrDefault())
                        .ExecuteAsync(cancellationToken);
                }
                catch (MsalUiRequiredException)
                {
                    result = await _publicClientApp.AcquireTokenInteractive(scopes)
                        .WithAuthority($"https://login.microsoftonline.com/{_currentTenantId ?? "organizations"}")
                        .ExecuteAsync(cancellationToken);
                }
                
                return result.AccessToken;
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
        public bool IsGraphConnected => _graphClient != null || _betaGraphClient != null;
        public bool IsAzureConnected => _azureCredential != null;
        
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
                var accounts = _publicClientApp.GetAccountsAsync().GetAwaiter().GetResult();
                foreach (var account in accounts)
                {
                    _publicClientApp.RemoveAsync(account).GetAwaiter().GetResult();
                }
            }
        }
    }
}