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
        protected virtual void Connect() { }
        protected virtual void VersionCheck() { }
        protected virtual void WriteLogFile(string message, ConsoleColor color) { }
    }

    public class ConnectM365Cmdlet : BaseConnectCmdlet
    {
        protected override void Connect() => ConnectExchangeOnline();
        private void ConnectExchangeOnline() => WriteLogFile("Connecting to Exchange Online...", ConsoleColor.Yellow);
        private void VersionCheck() => WriteLogFile("Version check performed.", ConsoleColor.Yellow);
        private void WriteLogFile(string message, ConsoleColor color) => Console.ForegroundColor = color;
    }

    public class ConnectAzureCmdlet : BaseConnectCmdlet
    {
        protected override void Connect() => ConnectAzureAD();
        private void ConnectAzureAD() => WriteLogFile("Connecting to Azure AD...", ConsoleColor.Yellow);
        private void VersionCheck() => WriteLogFile("Version check performed.", ConsoleColor.Yellow);
        private void WriteLogFile(string message, ConsoleColor color) => Console.ForegroundColor = color;
    }

    public class ConnectAzureAZCmdlet : BaseConnectCmdlet
    {
        protected override void Connect() => ConnectAzAccount();
        private void ConnectAzAccount() => WriteLogFile("Connecting to Azure...", ConsoleColor.Yellow);
        private void VersionCheck() => WriteLogFile("Version check performed.", ConsoleColor.Yellow);
        private void WriteLogFile(string message, ConsoleColor color) => Console.ForegroundColor = color;
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

                string token = GetToken("https://graph.microsoft.com/.default").Result;
                CheckToken(token);
            }
            else if (DeviceCode)
            {
                ConnectDeviceCode();
            }
            else if (Delegate)
            {
                ConnectMgGraph(new[] {
                    "AuditLogsQuery.Read.All", "UserAuthenticationMethod.Read.All", "User.Read.All",
                    "Mail.ReadBasic.All", "Mail.ReadWrite", "Mail.Read", "Mail.ReadBasic", "Policy.Read.All",
                    "Directory.Read.All"
                });
            }
            else
            {
                ConnectDeviceCode();
            }
        }

        // ... (other methods remain the same)

        private void WriteLogFile(string message, ConsoleColor color) => Console.ForegroundColor = color;
    }

    public class ConnectAquisitionGraphCmdlet : BaseConnectCmdlet
    {
        protected override void Connect() => ConnectMgGraph(new[] {
            "User.Read.All", "Policy.Read.All", "Organization.Read.All", "RoleManagement.Read.Directory",
            "GroupMember.Read.All", "Directory.Read.All", "PrivilegedEligibilitySchedule.Read.AzureADGroup",
            "PrivilegedAccess.Read.AzureADGroup", "RoleManagementPolicy.Read.AzureADGroup"
        });

        private void ConnectMgGraph(string[] scopes) => WriteLogFile("Connecting to Microsoft Graph with acquisition scopes...", ConsoleColor.Yellow);
        private void WriteLogFile(string message, ConsoleColor color) => Console.ForegroundColor = color;
    }

    public class ConnectAquisitionExoCmdlet : BaseConnectCmdlet
    {
        protected override void Connect() => ConnectExchangeOnline();
        private void ConnectExchangeOnline() => WriteLogFile("Connecting to Exchange Online...", ConsoleColor.Yellow);
        private void WriteLogFile(string message, ConsoleColor color) => Console.ForegroundColor = color;
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
