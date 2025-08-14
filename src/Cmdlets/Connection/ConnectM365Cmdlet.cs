using System;
using System.Management.Automation;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;

namespace Microsoft.ExtractorSuite.Cmdlets.Connection
{
    [Cmdlet(VerbsCommunications.Connect, "M365")]
    [OutputType(typeof(bool))]
    public class ConnectM365Cmdlet : BaseCmdlet
    {
        [Parameter(Position = 0)]
        public string? TenantId { get; set; }

        [Parameter]
        public string[]? Scopes { get; set; }

        [Parameter]
        public SwitchParameter UseBeta { get; set; }

        [Parameter]
        public SwitchParameter ExchangeOnline { get; set; }

        protected override void ProcessRecord()
        {
            try
            {
                WriteVerboseWithTimestamp("Connecting to Microsoft 365...");

                // Connect to Microsoft Graph (including Exchange if requested)
                var graphTask = Task.Run(async () =>
                    await AuthManager.ConnectGraphAsync(Scopes, TenantId, UseBeta.IsPresent, ExchangeOnline.IsPresent, CancellationToken));

                var graphConnected = RunAsync(graphTask);

                if (!graphConnected)
                {
                    WriteErrorWithTimestamp("Failed to connect to Microsoft Graph");
                    WriteObject(false);
                    return;
                }

                WriteVerboseWithTimestamp($"Successfully connected to Microsoft Graph (Beta: {UseBeta.IsPresent})");

                // Connect to Exchange Online if requested
                if (ExchangeOnline.IsPresent)
                {
                    WriteVerboseWithTimestamp("Connecting to Exchange Online Management...");
                    WriteVerboseWithTimestamp("This will use the official Exchange Online Management client ID");

                    var exchangeTask = Task.Run(async () =>
                        await AuthManager.ConnectExchangeOnlineAsync(TenantId, CancellationToken));

                    var exchangeConnected = RunAsync(exchangeTask);

                    if (!exchangeConnected)
                    {
                        WriteWarningWithTimestamp("Failed to connect to Exchange Online Management");
                        WriteWarningWithTimestamp("You may need Exchange Administrator role to use Exchange Admin API");
                        WriteWarningWithTimestamp("Basic mail operations will still work through Graph API");
                    }
                    else
                    {
                        WriteVerboseWithTimestamp("Successfully connected to Exchange Online Management");
                        WriteVerboseWithTimestamp("You can now use Exchange Admin API cmdlets");
                    }
                }

                // Output connection info
                var connectionInfo = new PSObject();
                connectionInfo.Properties.Add(new PSNoteProperty("GraphConnected", true));
                connectionInfo.Properties.Add(new PSNoteProperty("TenantId", AuthManager.CurrentTenantId));
                connectionInfo.Properties.Add(new PSNoteProperty("UseBeta", UseBeta.IsPresent));
                connectionInfo.Properties.Add(new PSNoteProperty("ExchangeOnline", ExchangeOnline.IsPresent));

                WriteObject(connectionInfo);
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Connection failed: {ex.Message}", ex);
                WriteObject(false);
            }
        }
    }
}
