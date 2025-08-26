namespace Microsoft.ExtractorSuite.Cmdlets.Connection
{
    using System.Management.Automation;
    using Microsoft.ExtractorSuite.Core;

    [Cmdlet(VerbsCommunications.Disconnect, "M365")]

    public class DisconnectM365Cmdlet : BaseCmdlet

    {

        protected override void ProcessRecord()

        {

            WriteVerboseWithTimestamp("Disconnecting from Microsoft 365...");



            AuthManager.Disconnect();



            WriteVerboseWithTimestamp("Successfully disconnected from all Microsoft 365 services");


            var result = new PSObject();
            result.Properties.Add(new PSNoteProperty("Status", "Disconnected"));
            result.Properties.Add(new PSNoteProperty("Message", "Successfully disconnected from all services"));


            WriteObject(result);

        }
    }
}
