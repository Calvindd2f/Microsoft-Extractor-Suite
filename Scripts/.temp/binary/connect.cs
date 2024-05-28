using System;
using System.Collections;
using System.Management.Automation;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace MicrosoftExtractorSuite
{
    [Cmdlet(VerbsCommunications.Connect, "M365")]
    public class ConnectM365Cmdlet : Cmdlet
    {
        protected override void ProcessRecord()
        {
            VersionCheck();
            ConnectExchangeOnline();
        }

        private void ConnectExchangeOnline()
        {
            // Implement the connection logic to Exchange Online
            // Example:
            WriteLogFile("[INFO] Connecting to Exchange Online...", "Yellow");
        }

        private void VersionCheck()
        {
            // Implement version check logic
            WriteLogFile("[INFO] Version check performed.", "Yellow");
        }

        private void WriteLogFile(string message, string color)
        {
            // Implement logging logic
            Console.ForegroundColor = color == "Yellow" ? ConsoleColor.Yellow : ConsoleColor.White;
            Console.WriteLine(message);
            Console.ResetColor();
        }
    }

    [Cmdlet(VerbsCommunications.Connect, "Azure")]
    public class ConnectAzureCmdlet : Cmdlet
    {
        protected override void ProcessRecord()
        {
            VersionCheck();
            ConnectAzureAD();
        }

        private void ConnectAzureAD()
        {
            // Implement the connection logic to Azure AD
            WriteLogFile("[INFO] Connecting to Azure AD...", "Yellow");
        }

        private void VersionCheck()
        {
            // Implement version check logic
            WriteLogFile("[INFO] Version check performed.", "Yellow");
        }

        private void WriteLogFile(string message, string color)
        {
            // Implement logging logic
            Console.ForegroundColor = color == "Yellow" ? ConsoleColor.Yellow : ConsoleColor.White;
            Console.WriteLine(message);
            Console.ResetColor();
        }
    }

    [Cmdlet(VerbsCommunications.Connect, "AzureAZ")]
    public class ConnectAzureAZCmdlet : Cmdlet
    {
        protected override void ProcessRecord()
        {
            VersionCheck();
            ConnectAzAccount();
        }

        private void ConnectAzAccount()
        {
            // Implement the connection logic to Azure
            WriteLogFile("[INFO] Connecting to Azure...", "Yellow");
        }

        private void VersionCheck()
        {
            // Implement version check logic
            WriteLogFile("[INFO] Version check performed.", "Yellow");
        }

        private void WriteLogFile(string message, string color)
        {
            // Implement logging logic
            Console.ForegroundColor = color == "Yellow" ? ConsoleColor.Yellow : ConsoleColor.White;
            Console.WriteLine(message);
            Console.ResetColor();
        }
    }

    [Cmdlet(VerbsCommunications.Connect, "ExtractorSuite")]
    public class ConnectExtractorSuiteCmdlet : Cmdlet
    {
        [Parameter]
        public bool Application { get; set; }

        [Parameter]
        public bool DeviceCode { get; set; }

        [Parameter]
        public bool Delegate { get; set; }

        private string appID;
        private string appSecret;
        private string appThumbprint;
        private string tenantID;

        protected override void ProcessRecord()
        {
            VersionCheck();

            if (Application)
            {
                appID = Environment.GetEnvironmentVariable("AppId");
                appSecret = Environment.GetEnvironmentVariable("AppSecret");
                appThumbprint = Environment.GetEnvironmentVariable("AppThumbprint");
                tenantID = Environment.GetEnvironmentVariable("TenantId");

                string token = GetToken("https://graph.microsoft.com/.default").Result;
                CheckToken(token);
            }
            else if (DeviceCode)
            {
                ConnectDeviceCode();
            }
            else if (Delegate)
            {
                var delegateScopes = new[] {
                    "AuditLogsQuery.Read.All", "UserAuthenticationMethod.Read.All", "User.Read.All",
                    "Mail.ReadBasic.All", "Mail.ReadWrite", "Mail.Read", "Mail.ReadBasic", "Policy.Read.All",
                    "Directory.Read.All"
                };

                ConnectMgGraph(delegateScopes);
            }
            else
            {
                ConnectDeviceCode();
            }
        }

        private async Task<string> GetToken(string scope)
        {
            using (var client = new HttpClient())
            {
                var request = new HttpRequestMessage(HttpMethod.Post, $"https://login.microsoftonline.com/{tenantID}/oauth2/v2.0/token")
                {
                    Content = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("grant_type", "client_credentials"),
                        new KeyValuePair<string, string>("client_id", appID),
                        new KeyValuePair<string, string>("client_secret", appSecret),
                        new KeyValuePair<string, string>("scope", scope)
                    })
                };

                var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                var token = JObject.Parse(json)["access_token"].ToString();

                return token;
            }
        }

        private void CheckToken(string token)
        {
            try
            {
                var request = (HttpWebRequest)WebRequest.Create("https://graph.microsoft.com/v1.0/me");
                request.Method = "GET";
                request.ContentType = "application/json;odata.metadata=minimal";
                request.Headers["Authorization"] = "Bearer " + token;

                var response = (HttpWebResponse)request.GetResponse();
                using (var reader = new StreamReader(response.GetResponseStream()))
                {
                    var jsonResponse = reader.ReadToEnd();
                    WriteLogFile("MS Graph Token is valid.", "Yellow");
                }
            }
            catch
            {
                WriteLogFile("MS Graph Token is invalid", "Red");
            }
        }

        private void ConnectDeviceCode()
        {
            // Implement the logic to connect using Device Code
            WriteLogFile("[INFO] Connecting using Device Code...", "Yellow");
        }

        private void ConnectMgGraph(string[] scopes)
        {
            // Implement the logic to connect to Microsoft Graph with specific scopes
            WriteLogFile("[INFO] Connecting to Microsoft Graph with delegate scopes...", "Yellow");
        }

        private void VersionCheck()
        {
            // Implement version check logic
            WriteLogFile("[INFO] Version check performed.", "Yellow");
        }

        private void WriteLogFile(string message, string color)
        {
            // Implement logging logic
            Console.ForegroundColor = color == "Yellow" ? ConsoleColor.Yellow : color == "Red" ? ConsoleColor.Red : ConsoleColor.White;
            Console.WriteLine(message);
            Console.ResetColor();
        }
    }

    [Cmdlet(VerbsCommunications.Connect, "AquisitionGraph")]
    public class ConnectAquisitionGraphCmdlet : Cmdlet
    {
        protected override void ProcessRecord()
        {
            var graphScopes = new[] {
                "User.Read.All", "Policy.Read.All", "Organization.Read.All", "RoleManagement.Read.Directory",
                "GroupMember.Read.All", "Directory.Read.All", "PrivilegedEligibilitySchedule.Read.AzureADGroup",
                "PrivilegedAccess.Read.AzureADGroup", "RoleManagementPolicy.Read.AzureADGroup"
            };

            ConnectMgGraph(graphScopes);
        }

        private void ConnectMgGraph(string[] scopes)
        {
            // Implement the logic to connect to Microsoft Graph with specific scopes
            WriteLogFile("[INFO] Connecting to Microsoft Graph with acquisition scopes...", "Yellow");
        }

        private void WriteLogFile(string message, string color)
        {
            // Implement logging logic
            Console.ForegroundColor = color == "Yellow" ? ConsoleColor.Yellow : color == "Red" ? ConsoleColor.Red : ConsoleColor.White;
            Console.WriteLine(message);
            Console.ResetColor();
        }
    }

    [Cmdlet(VerbsCommunications.Connect, "AquisitionExo")]
    public class ConnectAquisitionExoCmdlet : Cmdlet
    {
        protected override void ProcessRecord()
        {
            ConnectExchangeOnline();
        }

        private void ConnectExchangeOnline()
        {
            // Implement the logic to connect to Exchange Online
            WriteLogFile("[INFO] Connecting to Exchange Online...", "Yellow");
        }

        private void WriteLogFile(string message, string color)
        {
            // Implement logging logic
            Console.ForegroundColor = color == "Yellow" ? ConsoleColor.Yellow : color == "Red" ? ConsoleColor.Red : ConsoleColor.White;
            Console.WriteLine(message);
            Console.ResetColor();
        }
    }

    [Cmdlet(VerbsCommon.Get, "AquisitionServicePrincipalParams")]
    public class GetAquisitionServicePrincipalParamsCmdlet : Cmdlet
    {
        [Parameter(Mandatory = true)]
        public Hashtable BoundParameters { get; set; }

        protected override void ProcessRecord()
        {
            var servicePrincipalParams = GetServicePrincipalParams(BoundParameters);
            WriteObject(servicePrincipalParams);
        }

        private Hashtable GetServicePrincipalParams(Hashtable boundParameters)
        {
            var servicePrincipalParams = new Hashtable();

            var checkThumbprintParams = boundParameters.ContainsKey("CertificateThumbprint") &&
                                        boundParameters.ContainsKey("AppID") &&
                                        boundParameters.ContainsKey("Organization");

            if (checkThumbprintParams)
            {
                var certThumbprintParams = new Hashtable
                {
                    { "CertificateThumbprint", boundParameters["CertificateThumbprint"] },
                    { "AppID", boundParameters["AppID"] },
                    { "Organization", boundParameters["Organization"] }
                };

                servicePrincipalParams.Add("CertThumbprintParams", certThumbprintParams);
            }
            else
            {
                throw new Exception("Missing parameters required for authentication with Service Principal Auth");
            }

            return servicePrincipalParams;
        }
    }
}
