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



    public class GraphApiClient

    {

        private readonly GraphServiceClient _graphClient;



        private readonly HttpClient _httpClient;


        private readonly Microsoft.ExtractorSuite.Core.Logging.ILogger? _logger;


        public GraphApiClient(string tenantId, string clientId, string clientSecret, Microsoft.ExtractorSuite.Core.Logging.ILogger? logger = null)
        {

            _logger = logger;



            var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);


            _graphClient = new GraphServiceClient(credential);



            _httpClient = new HttpClient();

        }

        public GraphApiClient(GraphServiceClient graphClient, Microsoft.ExtractorSuite.Core.Logging.ILogger? logger = null)

        {


            _graphClient = graphClient ?? throw new ArgumentNullException(nameof(graphClient));


            _logger = logger;


            _httpClient = new HttpClient();

        }


        public GraphServiceClient Client => _graphClient;


        /// <summary>
        /// Check if the Graph client is authenticated and connected
        /// </summary>
        public async Task<bool> IsConnectedAsync()
        {
            try
            {

                await _graphClient.Me.GetAsync();

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

                var applications = await _graphClient.Applications.GetAsync();

                return applications?.Value ?? new List<Application>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting applications", ex);

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

                var servicePrincipals = await _graphClient.ServicePrincipals.GetAsync();

                return servicePrincipals?.Value ?? new List<ServicePrincipal>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting service principals", ex);

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

                var grants = await _graphClient.Oauth2PermissionGrants.GetAsync(requestConfig =>
                {
                    if (!string.IsNullOrEmpty(filter))
                    {
                        requestConfig.QueryParameters.Filter = filter;
                    }
                });

                return grants?.Value ?? new List<OAuth2PermissionGrant>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting OAuth2 permission grants", ex);

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

                var assignments = await _graphClient.ServicePrincipals[servicePrincipalId].AppRoleAssignments.GetAsync();

                return assignments?.Value ?? new List<AppRoleAssignment>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp($"Error getting app role assignments for {servicePrincipalId}", ex);

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

                var users = await _graphClient.Users.GetAsync();

                return users?.Value ?? new List<User>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting users", ex);

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

                return await _graphClient.Users[userId].GetAsync(requestConfig =>
                {
                    if (selectProperties != null && selectProperties.Length > 0)
                    {
                        requestConfig.QueryParameters.Select = selectProperties;
                    }
                });

            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp($"Error getting user {userId}", ex);

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

                var groups = await _graphClient.Groups.GetAsync();

                return groups?.Value ?? new List<Group>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting groups", ex);

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

                var policies = await _graphClient.Identity.ConditionalAccess.Policies.GetAsync();

                return policies?.Value ?? new List<ConditionalAccessPolicy>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting conditional access policies", ex);

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

                var devices = await _graphClient.Devices.GetAsync();

                return devices?.Value ?? new List<Device>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting devices", ex);

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

                var roles = await _graphClient.DirectoryRoles.GetAsync();

                return roles?.Value ?? new List<DirectoryRole>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting directory roles", ex);

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

                var alerts = await _graphClient.Security.Alerts.GetAsync();

                return alerts?.Value ?? new List<Alert>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting security alerts", ex);

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

                var skus = await _graphClient.SubscribedSkus.GetAsync();

                return skus?.Value ?? new List<SubscribedSku>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting subscribed SKUs", ex);

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

                var users = await _graphClient.Users.GetAsync(requestConfig =>
                {
                    requestConfig.QueryParameters.Filter = "assignedLicenses/$count ne 0";
                    requestConfig.QueryParameters.Select = new[] { "id", "displayName", "userPrincipalName", "assignedLicenses" };
                });

                return users?.Value ?? new List<User>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting users with licenses", ex);

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

                var me = await _graphClient.Me.GetAsync();

                return new {
                    UserId = me?.Id,
                    UserPrincipalName = me?.UserPrincipalName,
                    DisplayName = me?.DisplayName
                };
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting authentication info", ex);

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

                var riskyUsers = await _graphClient.IdentityProtection.RiskyUsers.GetAsync(requestConfig =>
                {
                    requestConfig.QueryParameters.Filter = $"userId eq '{userId}'";
                });

                return riskyUsers?.Value?.FirstOrDefault();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp($"Error getting risky user {userId}", ex);

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

                var riskyUsers = await _graphClient.IdentityProtection.RiskyUsers.GetAsync();

                return riskyUsers?.Value ?? new List<RiskyUser>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting risky users", ex);

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

                var detections = await _graphClient.IdentityProtection.RiskDetections.GetAsync(requestConfig =>
                {
                    if (!string.IsNullOrEmpty(filter))
                    {
                        requestConfig.QueryParameters.Filter = filter;
                    }
                });

                return detections?.Value ?? new List<RiskDetection>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting risk detections", ex);

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

                var members = await _graphClient.DirectoryRoles[roleId].Members.GetAsync();

                return members?.Value ?? new List<DirectoryObject>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp($"Error getting directory role members for {roleId}", ex);

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

                _logger?.WriteWarningWithTimestamp("PIM active assignments not implemented - returning empty list");

                return new List<object>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting PIM active assignments", ex);

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

                _logger?.WriteWarningWithTimestamp("PIM eligible assignments not implemented - returning empty list");

                return new List<object>();
            }
            catch (Exception ex)
            {

                _logger?.WriteErrorWithTimestamp("Error getting PIM eligible assignments", ex);

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

                var members = await _graphClient.Groups[groupId].Members.GetAsync();

                return members?.Value ?? new List<DirectoryObject>();
            }
            catch (Exception ex)

            {


                _logger?.WriteErrorWithTimestamp($"Error getting group members for {groupId}", ex);

                return new List<DirectoryObject>();
            }
        }

        public async Task<T> GetAsync<T>(string endpoint)
        {
            try
            {

                var response = await _httpClient.GetAsync($"https://graph.microsoft.com/v1.0/{endpoint}");

                response.EnsureSuccessStatusCode();

                var content = await response.Content.ReadAsStringAsync();
                return JsonConvert.DeserializeObject<T>(content) ?? throw new InvalidOperationException("Failed to deserialize response");
            }
            catch (Exception ex)

            {


                _logger?.WriteErrorWithTimestamp($"Error calling Graph API endpoint: {endpoint}", ex);

                throw;
            }
        }

        public async Task<IEnumerable<T>> GetAllPagesAsync<T>(string endpoint)
        {
            var results = new List<T>();
            var nextLink = $"https://graph.microsoft.com/v1.0/{endpoint}";

            while (!string.IsNullOrEmpty(nextLink))
            {

                var response = await _httpClient.GetAsync(nextLink);

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
