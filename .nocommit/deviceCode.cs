using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

public static class DeviceCodeHelper
{
    public static Func<DeviceCodeResult, Task> GetDeviceCodeResultCallback(bool isExchange)
    {
        return async deviceCodeResult =>
        {
            await Task.Run(() =>
            {
                if (deviceCodeResult == null)
                {
                    throw new ArgumentNullException(nameof(deviceCodeResult));
                }

                Console.WriteLine(deviceCodeResult.Message);
            });

            if (deviceCodeResult.ExpiresOn == null)
            {
                throw new ArgumentNullException(nameof(deviceCodeResult.ExpiresOn));
            }

            Console.WriteLine("ExpiresOn: " + deviceCodeResult.ExpiresOn.Value.ToLocalTime());

            try
            {
                if (string.IsNullOrEmpty(deviceCodeResult.VerificationUrl))
                {
                    throw new ArgumentException("VerificationUrl is null or empty", nameof(deviceCodeResult.VerificationUrl));
                }

                Process.Start(new ProcessStartInfo { UseShellExecute = true, FileName = deviceCodeResult.VerificationUrl });

                if (string.IsNullOrEmpty(deviceCodeResult.UserCode))
                {
                    throw new ArgumentException("UserCode is null or empty", nameof(deviceCodeResult.UserCode));
                }

                Process.Start(new ProcessStartInfo { UseShellExecute = false, FileName = "cmd", Arguments = "/c echo " + deviceCodeResult.UserCode + " | clip" });

                var continuePolling = true;
                while (continuePolling)
                {
                    var body = new
                    {
                        client_id = deviceCodeResult.ClientId,
                        grant_type = "urn:ietf:params:oauth:grant-type:device_code",
                        code = deviceCodeResult.DeviceCode,
                        scope = isExchange ? "https://outlook.office.com/.default" : "openid"
                    };

                    var tokens = await GetTokensAsync(deviceCodeResult.VerificationUrl, body);

                    if (tokens != null)
                    {
                        var tokenPayload = tokens.access_token.Split('.')[1].Replace('-', '+').Replace('_', '/');
                        while (tokenPayload.Length % 4) { tokenPayload += "="; }
                        var tokenByteArray = Convert.FromBase64String(tokenPayload);
                        var tokenArray = Encoding.ASCII.GetString(tokenByteArray);
                        var tokenObject = JsonConvert.DeserializeObject<JsonToken>(tokenArray);
                        var baseDate = new DateTime(1970, 1, 1);
                        var tokenExpire = baseDate.AddSeconds(tokenObject.exp).ToLocalTime();
                        Console.WriteLine("Decoded JWT payload:");
                        Console.WriteLine(tokenObject);
                        Console.WriteLine($"Your access token is set to expire on: {tokenExpire}");
                        continuePolling = false;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            return Task.FromResult(0);
        };
    }

    private static async Task<T> GetTokensAsync<T>(string url, object body)
    {
        using (var client = new HttpClient())
        {
            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = new StringContent(JsonConvert.SerializeObject(body));
            request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            var responseBody = await response.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<T>(responseBody);
        }
    }

    private class JsonToken
    {
        public string tid { get; set; }
        public long exp { get; set; }
    }
}


public class AutoTokenRefresh
{
    private string _RefreshToken;
    private string _tenantid;
    private int _RefreshInterval;
    private int _InitializationDelay;
    private bool _DisplayToken;
    private string _Outfile;
    private bool _isExchange;

    public AutoTokenRefresh(string refreshToken, string tenantid, int refreshInterval, int initializationDelay, bool displayToken, string outfile, bool isExchange)
    {
        _RefreshToken = refreshToken;
        _tenantid = tenantid;
        _RefreshInterval = refreshInterval;
        _InitializationDelay = initializationDelay;
        _DisplayToken = displayToken;
        _Outfile = outfile;
        _isExchange = isExchange;
    }

    private Timer tokenRefreshTimer;
    private void StartAutoRefresh()
    {
        tokenRefreshTimer = new Timer(RefreshToken, null, _InitializationDelay, _RefreshInterval);
    }

    private async void RefreshToken(object state)
    {
        var tokenResponse = await DeviceCodeHelper.GetTokenAsync(new DeviceCodeResult
        {
            UserCode = _RefreshToken,
            VerificationUrl = "https://login.microsoftonline.com/" + _tenantid + "/oauth2/v2.0/token",
            ClientId = "1b730954-1685-4b74-9bfd-dac224a76dca",
            Scopes = new string[] { _isExchange ? "https://outlook.office.com/.default" : "https://graph.microsoft.com/.default" }
        }, _isExchange);

        if (_DisplayToken)
        {
            Console.WriteLine($"New token: {tokenResponse.AccessToken}");
        }

        if (!String.IsNullOrEmpty(_Outfile))
        {
            File.WriteAllText(_Outfile, tokenResponse.AccessToken);
        }
    }
}

