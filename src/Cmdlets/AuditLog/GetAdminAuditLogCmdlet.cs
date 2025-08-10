using System;
using System.Collections.Generic;
using System.IO;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Logging;

namespace Microsoft.ExtractorSuite.Cmdlets.AuditLog
{
    [Cmdlet(VerbsCommon.Get, "AdminAuditLog")]
    [OutputType(typeof(PSObject))]
    public class GetAdminAuditLogCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "UserIds parameter filtering the log entries by the account of the user who performed the actions.")]
        public string UserIds { get; set; } = "*";

        [Parameter(HelpMessage = "The start date of the date range.")]
        public DateTime? StartDate { get; set; }

        [Parameter(HelpMessage = "The end date of the date range.")]
        public DateTime? EndDate { get; set; }

        [Parameter(HelpMessage = "The interval in which the logs are being gathered.")]
        public decimal? Interval { get; set; }

        [Parameter(HelpMessage = "The output directory.")]
        public new string OutputDirectory { get; set; } = "Output\\AdminAuditLog";

        [Parameter(HelpMessage = "The output format (CSV, JSON, SOF-ELK, JSONL).")]
        [ValidateSet("CSV", "JSON", "SOF-ELK", "JSONL")]
        public string Output { get; set; } = "CSV";

        [Parameter(HelpMessage = "Merge CSV outputs to a single file.")]
        public SwitchParameter MergeOutput { get; set; }

        [Parameter(HelpMessage = "The encoding of the output file.")]
        public string Encoding { get; set; } = "UTF8";

        [Parameter(HelpMessage = "The level of logging.")]
        [ValidateSet("None", "Minimal", "Standard", "Debug")]
        public new string LogLevel { get; set; } = "Standard";

        protected override void ProcessRecord()
        {
            var dateStr = DateTime.Now.ToString("yyyyMMddHHmmss");
            if (OutputDirectory == "Output\\AdminAuditLog")
            {
                OutputDirectory = $"Output\\AdminAuditLog\\{dateStr}";
            }

            try
            {
                if (!Directory.Exists(OutputDirectory))
                {
                    Directory.CreateDirectory(OutputDirectory);
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Failed to create directory: {OutputDirectory}", ex);
                return;
            }

            WriteVerboseWithTimestamp("== Starting the Admin Audit Log Collection (utilizing Get-UAL) ==");

            var parameters = new Dictionary<string, object>
            {
                { "RecordType", "ExchangeAdmin" },
                { "UserIds", UserIds },
                { "Output", Output },
                { "OutputDir", OutputDirectory },
                { "LogLevel", LogLevel },
                { "Encoding", Encoding }
            };

            if (StartDate.HasValue)
            {
                parameters["StartDate"] = StartDate.Value.ToString("MM/dd/yyyy");
            }

            if (EndDate.HasValue)
            {
                parameters["EndDate"] = EndDate.Value.ToString("MM/dd/yyyy");
            }

            if (Interval.HasValue)
            {
                parameters["Interval"] = Interval.Value;
            }

            if (MergeOutput.IsPresent)
            {
                parameters["MergeOutput"] = true;
            }

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
                            WriteError(error);
                        }
                    }

                    foreach (var result in results)
                    {
                        WriteObject(result);
                    }
                }
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Error executing Get-UAL: {ex.Message}", ex);
            }
        }
    }
}
