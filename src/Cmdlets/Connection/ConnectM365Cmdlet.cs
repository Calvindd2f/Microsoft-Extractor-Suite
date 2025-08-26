namespace Microsoft.ExtractorSuite.Cmdlets.Connection
{
    using System;
    using System.Management.Automation;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;

    [Cmdlet(VerbsCommunications.Connect, "M365")]
    [OutputType(typeof(bool))]
#pragma warning disable SA1600
    public class ConnectM365Cmdlet : BaseCmdlet
#pragma warning restore SA1600
    {
        [Parameter(Position = 0)]
#pragma warning disable SA1600
        public string? TenantId { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
        public string[]? Scopes { get; set; }
#pragma warning restore SA1600

        [Parameter]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter UseBeta { get; set; }

        [Parameter]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public SwitchParameter ExchangeOnline { get; set; }
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
            try
            {
#pragma warning disable SA1101
                WriteVerboseWithTimestamp("Connecting to Microsoft 365...");
#pragma warning restore SA1101

                // Connect to Microsoft Graph (including Exchange if requested)
#pragma warning disable SA1101
                var graphTask = Task.Run(async () =>
                    await AuthManager.ConnectGraphAsync(Scopes, TenantId, UseBeta.IsPresent, ExchangeOnline.IsPresent, CancellationToken));
#pragma warning restore SA1101

#pragma warning disable SA1101
                var graphConnected = RunAsync(graphTask);
#pragma warning restore SA1101

                if (!graphConnected)
                {
#pragma warning disable SA1101
                    WriteErrorWithTimestamp("Failed to connect to Microsoft Graph");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    WriteObject(false);
#pragma warning restore SA1101
                    return;
                }

#pragma warning disable SA1101
                WriteVerboseWithTimestamp($"Successfully connected to Microsoft Graph (Beta: {UseBeta.IsPresent})");
#pragma warning restore SA1101

                // Connect to Exchange Online if requested
#pragma warning disable SA1101
                if (ExchangeOnline.IsPresent)
                {
#pragma warning disable SA1101
                    WriteVerboseWithTimestamp("Connecting to Exchange Online Management...");
#pragma warning restore SA1101
#pragma warning disable SA1101
                    WriteVerboseWithTimestamp("This will use the official Exchange Online Management client ID");
#pragma warning restore SA1101

#pragma warning disable SA1101
                    var exchangeTask = Task.Run(async () =>
                        await AuthManager.ConnectExchangeOnlineAsync(TenantId, CancellationToken));
#pragma warning restore SA1101

#pragma warning disable SA1101
                    var exchangeConnected = RunAsync(exchangeTask);
#pragma warning restore SA1101

                    if (!exchangeConnected)
                    {
#pragma warning disable SA1101
                        WriteWarningWithTimestamp("Failed to connect to Exchange Online Management");
#pragma warning restore SA1101
#pragma warning disable SA1101
                        WriteWarningWithTimestamp("You may need Exchange Administrator role to use Exchange Admin API");
#pragma warning restore SA1101
#pragma warning disable SA1101
                        WriteWarningWithTimestamp("Basic mail operations will still work through Graph API");
#pragma warning restore SA1101
                    }
                    else
                    {
#pragma warning disable SA1101
                        WriteVerboseWithTimestamp("Successfully connected to Exchange Online Management");
#pragma warning restore SA1101
#pragma warning disable SA1101
                        WriteVerboseWithTimestamp("You can now use Exchange Admin API cmdlets");
#pragma warning restore SA1101
                    }
                }
#pragma warning restore SA1101

                // Output connection info
                var connectionInfo = new PSObject();
                connectionInfo.Properties.Add(new PSNoteProperty("GraphConnected", true));
#pragma warning disable SA1101
                connectionInfo.Properties.Add(new PSNoteProperty("TenantId", AuthManager.CurrentTenantId));
#pragma warning restore SA1101
#pragma warning disable SA1101
                connectionInfo.Properties.Add(new PSNoteProperty("UseBeta", UseBeta.IsPresent));
#pragma warning restore SA1101
#pragma warning disable SA1101
                connectionInfo.Properties.Add(new PSNoteProperty("ExchangeOnline", ExchangeOnline.IsPresent));
#pragma warning restore SA1101

#pragma warning disable SA1101
                WriteObject(connectionInfo);
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Connection failed: {ex.Message}", ex);
#pragma warning restore SA1101
#pragma warning disable SA1101
                WriteObject(false);
#pragma warning restore SA1101
            }
        }
    }
}
