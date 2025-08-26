namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Logging;


    [Cmdlet(VerbsCommon.Get, "AdminAuditLog")]
    [OutputType(typeof(PSObject))]
#pragma warning disable SA1600
    public class GetAdminAuditLogCmdlet : AsyncBaseCmdlet
#pragma warning restore SA1600
    {
        [Parameter(HelpMessage = "UserIds parameter filtering the log entries by the account of the user who performed the actions.")]
#pragma warning disable SA1600
        public string UserIds { get; set; } = "*";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "The start date of the date range.")]
#pragma warning disable SA1600
        public DateTime? StartDate { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "The end date of the date range.")]
#pragma warning disable SA1600
        public DateTime? EndDate { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "The interval in which the logs are being gathered.")]
#pragma warning disable SA1600
        public decimal? Interval { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "The output directory.")]
#pragma warning disable SA1600
        public new string OutputDirectory { get; set; } = "Output\\AdminAuditLog";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "The output format (CSV, JSON, SOF-ELK, JSONL).")]
        [ValidateSet("CSV", "JSON", "SOF-ELK", "JSONL")]
#pragma warning disable SA1600
        public string Output { get; set; } = "CSV";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Merge CSV outputs to a single file.")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public SwitchParameter MergeOutput { get; set; }

        [Parameter(HelpMessage = "The encoding of the output file.")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "The level of logging.")]
        [ValidateSet("None", "Minimal", "Standard", "Debug")]
#pragma warning disable SA1600
        public new string LogLevel { get; set; } = "Standard";
#pragma warning restore SA1600

#pragma warning disable SA1600
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
            var dateStr = DateTime.Now.ToString("yyyyMMddHHmmss");
#pragma warning disable SA1101
            if (OutputDirectory == "Output\\AdminAuditLog")
            {
#pragma warning disable SA1101
                OutputDirectory = $"Output\\AdminAuditLog\\{dateStr}";
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            try
            {
#pragma warning disable SA1101
                if (!Directory.Exists(OutputDirectory))
                {
#pragma warning disable SA1101
                    Directory.CreateDirectory(OutputDirectory);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to create directory: {OutputDirectory}", ex);
#pragma warning restore SA1101
                return;
            }

            WriteVerboseWithTimestamp("== Starting the Admin Audit Log Collection (utilizing Get-UAL) ==");

#pragma warning disable SA1101
            var parameters = new Dictionary<string, object>
            {
                { "RecordType", "ExchangeAdmin" },
                { "UserIds", UserIds },
                { "Output", Output },
                { "OutputDir", OutputDirectory },
                { "LogLevel", LogLevel },
                { "Encoding", Encoding }
            };
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (StartDate.HasValue)
            {
#pragma warning disable SA1101
                parameters["StartDate"] = StartDate.Value.ToString("MM/dd/yyyy");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (EndDate.HasValue)
            {
#pragma warning disable SA1101
                parameters["EndDate"] = EndDate.Value.ToString("MM/dd/yyyy");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (Interval.HasValue)
            {
#pragma warning disable SA1101
                parameters["Interval"] = Interval.Value;
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            if (MergeOutput.IsPresent)
            {
                parameters["MergeOutput"] = true;
            }
#pragma warning restore SA1101

            try
            {
                using (var ps = System.Management.Automation.PowerShell.Create(RunspaceMode.CurrentRunspace))
                {
                    ps.AddCommand("Get-UAL");

                    foreach (var param in parameters)
                    {
                        ps.AddParameter(param.Key, param.Value);
                    }

                    var results = ps.Invoke();

                    if (ps.HadErrors)
                    {
                        foreach (var error in ps.Streams.Error)
                        {
#pragma warning disable SA1101
                            WriteError(error);
#pragma warning restore SA1101
                        }
                    }

                    foreach (var result in results)
                    {
#pragma warning disable SA1101
                        WriteObject(result);
#pragma warning restore SA1101
                    }
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Error executing Get-UAL: {ex.Message}", ex);
#pragma warning restore SA1101
            }
        }
    }
}
