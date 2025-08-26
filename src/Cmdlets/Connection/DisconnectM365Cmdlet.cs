namespace Microsoft.ExtractorSuite.Cmdlets.Connection
{
    using System.Management.Automation;
    using Microsoft.ExtractorSuite.Core;

    [Cmdlet(VerbsCommunications.Disconnect, "M365")]
#pragma warning disable SA1600
    public class DisconnectM365Cmdlet : BaseCmdlet
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
#pragma warning disable SA1101
            WriteVerboseWithTimestamp("Disconnecting from Microsoft 365...");
#pragma warning restore SA1101

#pragma warning disable SA1101
            AuthManager.Disconnect();
#pragma warning restore SA1101

#pragma warning disable SA1101
            WriteVerboseWithTimestamp("Successfully disconnected from all Microsoft 365 services");
#pragma warning restore SA1101

            var result = new PSObject();
            result.Properties.Add(new PSNoteProperty("Status", "Disconnected"));
            result.Properties.Add(new PSNoteProperty("Message", "Successfully disconnected from all services"));

#pragma warning disable SA1101
            WriteObject(result);
#pragma warning restore SA1101
        }
    }
}
