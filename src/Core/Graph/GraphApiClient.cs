using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.Graph;
using Azure.Identity;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Microsoft.ExtractorSuite.Core.Logging;

namespace Microsoft.ExtractorSuite.Core.Graph
{
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
