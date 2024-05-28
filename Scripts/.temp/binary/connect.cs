using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace MicrosoftExtractorSuite
{
    public abstract class BaseConnectCmdlet : Cmdlet
    {
        protected virtual void VersionCheck() { }
        protected virtual void WriteLogFile(string message, ConsoleColor color) { }
    }

    public static class ConnectHelper
    {
        public static async Task ConnectExchangeOnline(Action writeLogFile)
        {
            writeLogFile("Connecting to Exchange Online...");
            // Add actual implementation here
            await Task.CompletedTask;
        }

        public static async Task ConnectAzureAD(Action writeLogFile)
        {
            writeLogFile("Connecting to Azure AD...");
            // Add actual implementation here
            await Task.CompletedTask;
        }

        public static async Task ConnectAzAccount(Action writeLogFile)
        {
            writeLogFile("Connecting to Azure...");
            // Add actual implementation here
            await Task.CompletedTask;
        }

        public static async Task<string> GetToken(string resource, Action<string> writeLogFile)
        {
            writeLogFile("Getting token...");
            // Add actual implementation here
            return await Task.FromResult<string>(default);
        }

        public static void CheckToken(string token, Action<string> writeLogFile)
        {
            writeLogFile("Checking token...");
            // Add actual implementation here
        }

        public static async Task ConnectMgGraph(string[] scopes, Action<string> writeLogFile)
        {
            writeLogFile("Connecting to Microsoft Graph...");
            // Add actual implementation here
            await Task.CompletedTask;
        }
    }

    public class ConnectM365Cmdlet : BaseConnectCmdlet
    {
        protected override void Connect() => ConnectHelper.ConnectExchangeOnline(WriteLogFile);
        protected override void VersionCheck() => WriteLogFile("Version check performed.", ConsoleColor.Yellow);
        protected override void WriteLogFile(string message, ConsoleColor color) => Console.ForegroundColor = color;
    }

    public class ConnectAzureCmdlet : BaseConnectCmdlet
    {
        protected override void Connect() => ConnectHelper.ConnectAzureAD(WriteLogFile);
        protected override void VersionCheck() => WriteLogFile("Version check performed.", ConsoleColor.Yellow);
        protected override void WriteLogFile(string message, ConsoleColor color) => Console.ForegroundColor = color;
    }

    public class ConnectAzureAZCmdlet : BaseConnectCmdlet
    {
        protected override void Connect() => ConnectHelper.ConnectAzAccount(WriteLogFile);
        protected override void VersionCheck() => WriteLogFile("Version check performed.", ConsoleColor.Yellow);
        protected override void WriteLogFile(string message, ConsoleColor color) => Console.ForegroundColor = color;
    }

    public class ConnectExtractorSuiteCmdlet : BaseConnectCmdlet
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

        protected override void Connect()
        {
            VersionCheck();

            if (Application)
            {
                appID = Environment.GetEnvironmentVariable("AppId");
                appSecret = Environment.GetEnvironmentVariable("AppSecret");
                appThumbprint = Environment.GetEnvironmentVariable("AppThumbprint");
                tenantID = Environment.GetEnvironmentVariable("TenantId");

                if (appID == null || appSecret == null || appThumbprint == null || tenantID == null)
                {
                    throw new Exception("Missing environment variables required for authentication with Application Auth");
                }

                Task.Run(async () =>
                {
                    string token = await ConnectHelper.GetToken("https://graph.microsoft.com/.default", WriteLogFile);
                    ConnectHelper.CheckToken(token, WriteLogFile);
                }).Wait();
            }
            else if (DeviceCode)
            {
                ConnectHelper.ConnectDeviceCode(WriteLogFile);
            }
            else if (Delegate)
            {
                await ConnectHelper.ConnectMgGraph(new[] {
                    "AuditLogsQuery.Read.All", "UserAuthenticationMethod.Read.All", "User.Read.All",
                    "Mail.ReadBasic.All", "Mail.ReadWrite", "Mail.Read", "Mail.ReadBasic", "Policy.Read.All",
                    "Directory.Read.All"
                }, WriteLogFile);
            }
            else
            {
                ConnectHelper.ConnectDeviceCode(WriteLogFile);
            }
        }

        // ... (other methods remain the same)

        protected override void WriteLogFile(string message, ConsoleColor color) => Console.ForegroundColor = color;
    }

    public class ConnectAquisitionGraphCmdlet : BaseConnectCmdlet
    {
        protected override void Connect() => ConnectHelper.ConnectMgGraph(new[] {
            "User.Read.All", "Policy.Read.All", "Organization.Read.All", "RoleManagement.Read.Directory",
            "GroupMember.Read.All", "Directory.Read.All", "PrivilegedEligibilitySchedule.Read.AzureADGroup",
            "PrivilegedAccess.Read.AzureADGroup", "RoleManagementPolicy.Read.AzureADGroup"
        }, WriteLogFile);
    }

    public class ConnectAquisitionExoCmdlet : BaseConnectCmdlet
    {
        protected override void Connect() => ConnectHelper.ConnectExchangeOnline(WriteLogFile);
    }

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
