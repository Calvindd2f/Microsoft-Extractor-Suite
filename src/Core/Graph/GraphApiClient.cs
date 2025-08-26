namespace Microsoft.ExtractorSuite.Core.Graph
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;
    using Azure.Identity;
    using Microsoft.Extensions.Logging;
    using Microsoft.ExtractorSuite.Core.Logging;
    using Microsoft.Graph;
    using Microsoft.Graph.Models;
    using Newtonsoft.Json;


#pragma warning disable SA1600
    public class GraphApiClient
#pragma warning restore SA1600
    {
#pragma warning disable SA1309
        private readonly GraphServiceClient _graphClient;
#pragma warning restore SA1309
#pragma warning disable SA1309
#pragma warning disable SA1600
        private readonly HttpClient _httpClient;
#pragma warning restore SA1600
#pragma warning disable SA1309
        private readonly Microsoft.ExtractorSuite.Core.Logging.ILogger? _logger;
#pragma warning restore SA1309

        public GraphApiClient(string tenantId, string clientId, string clientSecret, Microsoft.ExtractorSuite.Core.Logging.ILogger? logger = null)
        {
#pragma warning disable SA1101
            _logger = logger;
#pragma warning restore SA1101

#pragma warning disable SA1600
            var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
#pragma warning restore SA1600
#pragma warning disable SA1101
            _graphClient = new GraphServiceClient(credential);
#pragma warning restore SA1101

#pragma warning disable SA1101
            _httpClient = new HttpClient();
#pragma warning restore SA1101
        }

        public GraphApiClient(GraphServiceClient graphClient, Microsoft.ExtractorSuite.Core.Logging.ILogger? logger = null)
#pragma warning disable SA1600
        {
#pragma warning restore SA1600
#pragma warning disable SA1101
            _graphClient = graphClient ?? throw new ArgumentNullException(nameof(graphClient));
#pragma warning restore SA1101
#pragma warning disable SA1101
            _logger = logger;
#pragma warning restore SA1101
#pragma warning disable SA1101
            _httpClient = new HttpClient();
#pragma warning restore SA1101
        }

#pragma warning disable SA1101
        public GraphServiceClient Client => _graphClient;
#pragma warning restore SA1101

        /// <summary>
        /// Check if the Graph client is authenticated and connected
        /// </summary>
        public async Task<bool> IsConnectedAsync()
        {
            try
            {
#pragma warning disable SA1101
                await _graphClient.Me.GetAsync();
#pragma warning restore SA1101
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Get all applications from Azure AD
        /// </summary>
        public async Task<IEnumerable<Application>> GetApplicationsAsync()
        {
            try
            {
#pragma warning disable SA1101
                var applications = await _graphClient.Applications.GetAsync();
#pragma warning restore SA1101
                return applications?.Value ?? new List<Application>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting applications", ex);
#pragma warning restore SA1101
                return new List<Application>();
            }
        }

        /// <summary>
        /// Get all service principals from Azure AD
        /// </summary>
        public async Task<IEnumerable<ServicePrincipal>> GetServicePrincipalsAsync()
        {
            try
            {
#pragma warning disable SA1101
                var servicePrincipals = await _graphClient.ServicePrincipals.GetAsync();
#pragma warning restore SA1101
                return servicePrincipals?.Value ?? new List<ServicePrincipal>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting service principals", ex);
#pragma warning restore SA1101
                return new List<ServicePrincipal>();
            }
        }

        /// <summary>
        /// Get OAuth2 permission grants with optional filter
        /// </summary>
        public async Task<IEnumerable<OAuth2PermissionGrant>> GetOAuth2PermissionGrantsAsync(string? filter = null)
        {
            try
            {
#pragma warning disable SA1101
                var grants = await _graphClient.Oauth2PermissionGrants.GetAsync(requestConfig =>
                {
                    if (!string.IsNullOrEmpty(filter))
                    {
                        requestConfig.QueryParameters.Filter = filter;
                    }
                });
#pragma warning restore SA1101
                return grants?.Value ?? new List<OAuth2PermissionGrant>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting OAuth2 permission grants", ex);
#pragma warning restore SA1101
                return new List<OAuth2PermissionGrant>();
            }
        }

        /// <summary>
        /// Get app role assignments for a service principal
        /// </summary>
        public async Task<IEnumerable<AppRoleAssignment>> GetAppRoleAssignmentsAsync(string servicePrincipalId)
        {
            try
            {
#pragma warning disable SA1101
                var assignments = await _graphClient.ServicePrincipals[servicePrincipalId].AppRoleAssignments.GetAsync();
#pragma warning restore SA1101
                return assignments?.Value ?? new List<AppRoleAssignment>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp($"Error getting app role assignments for {servicePrincipalId}", ex);
#pragma warning restore SA1101
                return new List<AppRoleAssignment>();
            }
        }

        /// <summary>
        /// Get all users from Azure AD
        /// </summary>
        public async Task<IEnumerable<User>> GetUsersAsync()
        {
            try
            {
#pragma warning disable SA1101
                var users = await _graphClient.Users.GetAsync();
#pragma warning restore SA1101
                return users?.Value ?? new List<User>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting users", ex);
#pragma warning restore SA1101
                return new List<User>();
            }
        }

        /// <summary>
        /// Get a specific user by ID with optional select properties
        /// </summary>
        public async Task<User?> GetUserAsync(string userId, string[]? selectProperties = null)
        {
            try
            {
#pragma warning disable SA1101
                return await _graphClient.Users[userId].GetAsync(requestConfig =>
                {
                    if (selectProperties != null && selectProperties.Length > 0)
                    {
                        requestConfig.QueryParameters.Select = selectProperties;
                    }
                });
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp($"Error getting user {userId}", ex);
#pragma warning restore SA1101
                return null;
            }
        }

        /// <summary>
        /// Get all groups from Azure AD
        /// </summary>
        public async Task<IEnumerable<Group>> GetGroupsAsync()
        {
            try
            {
#pragma warning disable SA1101
                var groups = await _graphClient.Groups.GetAsync();
#pragma warning restore SA1101
                return groups?.Value ?? new List<Group>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting groups", ex);
#pragma warning restore SA1101
                return new List<Group>();
            }
        }

        /// <summary>
        /// Get all conditional access policies
        /// </summary>
        public async Task<IEnumerable<ConditionalAccessPolicy>> GetConditionalAccessPoliciesAsync()
        {
            try
            {
#pragma warning disable SA1101
                var policies = await _graphClient.Identity.ConditionalAccess.Policies.GetAsync();
#pragma warning restore SA1101
                return policies?.Value ?? new List<ConditionalAccessPolicy>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting conditional access policies", ex);
#pragma warning restore SA1101
                return new List<ConditionalAccessPolicy>();
            }
        }

        /// <summary>
        /// Get all devices from Azure AD
        /// </summary>
        public async Task<IEnumerable<Device>> GetDevicesAsync()
        {
            try
            {
#pragma warning disable SA1101
                var devices = await _graphClient.Devices.GetAsync();
#pragma warning restore SA1101
                return devices?.Value ?? new List<Device>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting devices", ex);
#pragma warning restore SA1101
                return new List<Device>();
            }
        }

        /// <summary>
        /// Get all directory roles
        /// </summary>
        public async Task<IEnumerable<DirectoryRole>> GetDirectoryRolesAsync()
        {
            try
            {
#pragma warning disable SA1101
                var roles = await _graphClient.DirectoryRoles.GetAsync();
#pragma warning restore SA1101
                return roles?.Value ?? new List<DirectoryRole>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting directory roles", ex);
#pragma warning restore SA1101
                return new List<DirectoryRole>();
            }
        }

        /// <summary>
        /// Get security alerts
        /// </summary>
        public async Task<IEnumerable<Alert>> GetSecurityAlertsAsync()
        {
            try
            {
#pragma warning disable SA1101
                var alerts = await _graphClient.Security.Alerts.GetAsync();
#pragma warning restore SA1101
                return alerts?.Value ?? new List<Alert>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting security alerts", ex);
#pragma warning restore SA1101
                return new List<Alert>();
            }
        }

        /// <summary>
        /// Get subscribed SKUs (licenses)
        /// </summary>
        public async Task<IEnumerable<SubscribedSku>> GetSubscribedSkusAsync()
        {
            try
            {
#pragma warning disable SA1101
                var skus = await _graphClient.SubscribedSkus.GetAsync();
#pragma warning restore SA1101
                return skus?.Value ?? new List<SubscribedSku>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting subscribed SKUs", ex);
#pragma warning restore SA1101
                return new List<SubscribedSku>();
            }
        }

        /// <summary>
        /// Get users with licenses assigned
        /// </summary>
        public async Task<IEnumerable<User>> GetUsersWithLicensesAsync()
        {
            try
            {
#pragma warning disable SA1101
                var users = await _graphClient.Users.GetAsync(requestConfig =>
                {
                    requestConfig.QueryParameters.Filter = "assignedLicenses/$count ne 0";
                    requestConfig.QueryParameters.Select = new[] { "id", "displayName", "userPrincipalName", "assignedLicenses" };
                });
#pragma warning restore SA1101
                return users?.Value ?? new List<User>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting users with licenses", ex);
#pragma warning restore SA1101
                return new List<User>();
            }
        }

        /// <summary>
        /// Get authentication information for current context
        /// </summary>
        public async Task<object> GetAuthenticationInfoAsync()
        {
            try
            {
#pragma warning disable SA1101
                var me = await _graphClient.Me.GetAsync();
#pragma warning restore SA1101
                return new {
                    UserId = me?.Id,
                    UserPrincipalName = me?.UserPrincipalName,
                    DisplayName = me?.DisplayName
                };
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting authentication info", ex);
#pragma warning restore SA1101
                return new { Error = ex.Message };
            }
        }

        /// <summary>
        /// Get risky user by ID
        /// </summary>
        public async Task<RiskyUser?> GetRiskyUserAsync(string userId)
        {
            try
            {
#pragma warning disable SA1101
                var riskyUsers = await _graphClient.IdentityProtection.RiskyUsers.GetAsync(requestConfig =>
                {
                    requestConfig.QueryParameters.Filter = $"userId eq '{userId}'";
                });
#pragma warning restore SA1101
                return riskyUsers?.Value?.FirstOrDefault();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp($"Error getting risky user {userId}", ex);
#pragma warning restore SA1101
                return null;
            }
        }

        /// <summary>
        /// Get all risky users
        /// </summary>
        public async Task<IEnumerable<RiskyUser>> GetRiskyUsersAsync()
        {
            try
            {
#pragma warning disable SA1101
                var riskyUsers = await _graphClient.IdentityProtection.RiskyUsers.GetAsync();
#pragma warning restore SA1101
                return riskyUsers?.Value ?? new List<RiskyUser>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting risky users", ex);
#pragma warning restore SA1101
                return new List<RiskyUser>();
            }
        }

        /// <summary>
        /// Get risk detections with optional filter
        /// </summary>
        public async Task<IEnumerable<RiskDetection>> GetRiskDetectionsAsync(string? filter = null)
        {
            try
            {
#pragma warning disable SA1101
                var detections = await _graphClient.IdentityProtection.RiskDetections.GetAsync(requestConfig =>
                {
                    if (!string.IsNullOrEmpty(filter))
                    {
                        requestConfig.QueryParameters.Filter = filter;
                    }
                });
#pragma warning restore SA1101
                return detections?.Value ?? new List<RiskDetection>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting risk detections", ex);
#pragma warning restore SA1101
                return new List<RiskDetection>();
            }
        }

        /// <summary>
        /// Get members of a directory role
        /// </summary>
        public async Task<IEnumerable<DirectoryObject>> GetDirectoryRoleMembersAsync(string roleId)
        {
            try
            {
#pragma warning disable SA1101
                var members = await _graphClient.DirectoryRoles[roleId].Members.GetAsync();
#pragma warning restore SA1101
                return members?.Value ?? new List<DirectoryObject>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp($"Error getting directory role members for {roleId}", ex);
#pragma warning restore SA1101
                return new List<DirectoryObject>();
            }
        }

        /// <summary>
        /// Get PIM active assignments
        /// </summary>
        public async Task<IEnumerable<object>> GetPIMActiveAssignmentsAsync()
        {
            try
            {
                // This is a placeholder - actual PIM endpoints may vary
#pragma warning disable SA1101
                _logger?.WriteWarningWithTimestamp("PIM active assignments not implemented - returning empty list");
#pragma warning restore SA1101
                return new List<object>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting PIM active assignments", ex);
#pragma warning restore SA1101
                return new List<object>();
            }
        }

        /// <summary>
        /// Get PIM eligible assignments
        /// </summary>
        public async Task<IEnumerable<object>> GetPIMEligibleAssignmentsAsync()
        {
            try
            {
                // This is a placeholder - actual PIM endpoints may vary
#pragma warning disable SA1101
                _logger?.WriteWarningWithTimestamp("PIM eligible assignments not implemented - returning empty list");
#pragma warning restore SA1101
                return new List<object>();
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp("Error getting PIM eligible assignments", ex);
#pragma warning restore SA1101
                return new List<object>();
            }
        }

        /// <summary>
        /// Get members of a group
        /// </summary>
        public async Task<IEnumerable<DirectoryObject>> GetGroupMembersAsync(string groupId)
        {
            try
            {
#pragma warning disable SA1101
                var members = await _graphClient.Groups[groupId].Members.GetAsync();
#pragma warning restore SA1101
                return members?.Value ?? new List<DirectoryObject>();
            }
            catch (Exception ex)
#pragma warning disable SA1600
            {
#pragma warning restore SA1600
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp($"Error getting group members for {groupId}", ex);
#pragma warning restore SA1101
                return new List<DirectoryObject>();
            }
        }

        public async Task<T> GetAsync<T>(string endpoint)
        {
            try
            {
#pragma warning disable SA1101
                var response = await _httpClient.GetAsync($"https://graph.microsoft.com/v1.0/{endpoint}");
#pragma warning restore SA1101
                response.EnsureSuccessStatusCode();

                var content = await response.Content.ReadAsStringAsync();
                return JsonConvert.DeserializeObject<T>(content) ?? throw new InvalidOperationException("Failed to deserialize response");
            }
            catch (Exception ex)
#pragma warning disable SA1600
            {
#pragma warning restore SA1600
#pragma warning disable SA1101
                _logger?.WriteErrorWithTimestamp($"Error calling Graph API endpoint: {endpoint}", ex);
#pragma warning restore SA1101
                throw;
            }
        }

        public async Task<IEnumerable<T>> GetAllPagesAsync<T>(string endpoint)
        {
            var results = new List<T>();
            var nextLink = $"https://graph.microsoft.com/v1.0/{endpoint}";

            while (!string.IsNullOrEmpty(nextLink))
            {
#pragma warning disable SA1101
                var response = await _httpClient.GetAsync(nextLink);
#pragma warning restore SA1101
                response.EnsureSuccessStatusCode();

                var content = await response.Content.ReadAsStringAsync();
                var data = JsonConvert.DeserializeObject<dynamic>(content);

                if (data?.value != null)
                {
                    foreach (var item in data.value)
                    {
                        var itemResult = JsonConvert.DeserializeObject<T>(item.ToString());
                        if (itemResult != null)
                        {
                            results.Add(itemResult);
                        }
                    }
                }

                nextLink = data?["@odata.nextLink"]?.ToString();
            }

            return results;
        }
    }
}
