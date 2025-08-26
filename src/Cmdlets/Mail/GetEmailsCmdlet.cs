namespace Microsoft.ExtractorSuite.Cmdlets.Mail
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.Graph;
    using Microsoft.Graph.Models;

    /// <summary>
    /// Gets specific emails based on Internet Message IDs and saves them as EML or TXT files.
    /// Supports single email retrieval or batch processing from an input file.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "Emails")]
    [OutputType(typeof(EmailExportResult))]
    public class GetEmailsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "The user ID or email address of the mailbox to search")]
#pragma warning disable SA1600
        public string UserId { get; set; } = string.Empty;
#pragma warning restore SA1600

        [Parameter(ParameterSetName = "SingleEmail", HelpMessage = "Internet Message ID of the specific email to retrieve")]
#pragma warning disable SA1600
        public string? InternetMessageId { get; set; }
#pragma warning restore SA1600

        [Parameter(ParameterSetName = "BatchFile", HelpMessage = "Path to text file containing multiple Internet Message IDs (one per line)")]
#pragma warning disable SA1600
        public string? InputFile { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Output format for emails. Default: EML")]
        [ValidateSet("EML", "TXT")]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "EML";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Include email attachments in the export")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public SwitchParameter IncludeAttachments { get; set; }
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
            var results = RunAsyncOperation(GetEmailsAsync, "Getting Emails");

#pragma warning disable SA1101
            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
#pragma warning restore SA1101
        }

        private async Task<List<EmailExportResult>> GetEmailsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Email Export");

#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Not connected to Microsoft Graph. Please run Connect-M365 first.");
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            var graphClient = AuthManager.GraphClient!;
#pragma warning restore SA1101
            var results = new List<EmailExportResult>();
            var summary = new EmailExportSummary
            {
                StartTime = DateTime.UtcNow
            };

            // Set up output directory
#pragma warning disable SA1101
            if (string.IsNullOrEmpty(OutputDirectory))
            {
#pragma warning disable SA1101
                OutputDirectory = Path.Combine(Environment.CurrentDirectory, "Output", "EmailExport");
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            Directory.CreateDirectory(OutputDirectory);
#pragma warning restore SA1101

            // Determine which emails to process
            List<string> messageIds;
#pragma warning disable SA1101
            if (!string.IsNullOrEmpty(InternetMessageId))
            {
#pragma warning disable SA1101
                messageIds = new List<string> { InternetMessageId };
#pragma warning restore SA1101
            }
            else if (!string.IsNullOrEmpty(InputFile))
            {
#pragma warning disable SA1101
                messageIds = await ReadMessageIdsFromFileAsync(InputFile, cancellationToken);
#pragma warning restore SA1101
            }
            else
            {
                throw new ArgumentException("Either InternetMessageId or InputFile must be provided");
            }
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Processing {messageIds.Count} message ID(s)");
            summary.TotalMessages = messageIds.Count;

            var processedCount = 0;
            var duplicateTracker = new HashSet<string>();

            foreach (var messageId in messageIds)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                processedCount++;
                var progressPercent = (int)((processedCount / (double)messageIds.Count) * 90);

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = $"Processing message {processedCount}/{messageIds.Count}",
                    PercentComplete = progressPercent,
                    ItemsProcessed = processedCount
                });

                WriteVerboseWithTimestamp($"Processing Internet Message ID: {messageId}");

                try
                {
#pragma warning disable SA1101
                    var exportResult = await ProcessSingleEmailAsync(
                        graphClient, messageId.Trim(), duplicateTracker, cancellationToken);
#pragma warning restore SA1101

                    results.Add(exportResult);

                    if (exportResult.Success)
                    {
                        summary.SuccessfulExports++;
                        WriteVerboseWithTimestamp($"✓ Successfully exported: {exportResult.FileName}");
                    }
                    else
                    {
                        summary.FailedExports++;
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"✗ Failed to export: {messageId} - {exportResult.ErrorMessage}");
#pragma warning restore SA1101
                    }

                    if (exportResult.IsDuplicate)
                    {
                        summary.Duplicates++;
                    }

                    if (exportResult.AttachmentsProcessed > 0)
                    {
                        summary.TotalAttachments += exportResult.AttachmentsProcessed;
                    }
                }
                catch (Exception ex)
                {
                    var errorResult = new EmailExportResult
                    {
                        InternetMessageId = messageId,
                        Success = false,
                        ErrorMessage = ex.Message
                    };
                    results.Add(errorResult);
                    summary.FailedExports++;
#pragma warning disable SA1101
                    WriteErrorWithTimestamp($"Error processing message {messageId}: {ex.Message}", ex);
#pragma warning restore SA1101
                }
            }

            summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Export completed",
                PercentComplete = 100
            });

            // Log summary
            WriteVerboseWithTimestamp($"Email Export Summary:");
            WriteVerboseWithTimestamp($"  Total Messages: {summary.TotalMessages}");
            WriteVerboseWithTimestamp($"  Successful Exports: {summary.SuccessfulExports}");
            WriteVerboseWithTimestamp($"  Failed Exports: {summary.FailedExports}");
            WriteVerboseWithTimestamp($"  Duplicates Found: {summary.Duplicates}");
#pragma warning disable SA1101
            if (IncludeAttachments.IsPresent)
            {
                WriteVerboseWithTimestamp($"  Attachments Processed: {summary.TotalAttachments}");
            }
#pragma warning restore SA1101
#pragma warning disable SA1101
            WriteVerboseWithTimestamp($"  Output Directory: {OutputDirectory}");
#pragma warning restore SA1101
            WriteVerboseWithTimestamp($"  Processing Time: {summary.ProcessingTime:mm\\:ss}");

            return results;
        }

        private async Task<List<string>> ReadMessageIdsFromFileAsync(string filePath, CancellationToken cancellationToken)
        {
            try
            {
                var lines = await Task.Run(() => File.ReadAllLines(filePath), cancellationToken);
                var messageIds = lines
                    .Where(line => !string.IsNullOrWhiteSpace(line))
                    .Select(line => line.Trim())
                    .ToList();

                WriteVerboseWithTimestamp($"Read {messageIds.Count} message IDs from {filePath}");
                return messageIds;
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Failed to read input file: {ex.Message}", ex);
#pragma warning restore SA1101
                throw;
            }
        }

        private async Task<EmailExportResult> ProcessSingleEmailAsync(
            GraphServiceClient graphClient,
            string internetMessageId,
            HashSet<string> duplicateTracker,
            CancellationToken cancellationToken)
        {
            var result = new EmailExportResult
            {
                InternetMessageId = internetMessageId
            };

            try
            {
                // Search for the message by Internet Message ID
#pragma warning disable SA1101
                var messages = await graphClient.Users[UserId].Messages
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Filter = $"internetMessageId eq '{internetMessageId}'";
                        requestConfiguration.QueryParameters.Select = new[]
                        {
                            "id", "subject", "receivedDateTime", "from", "hasAttachments", "internetMessageId"
                        };
                    }, cancellationToken);
#pragma warning restore SA1101

                if (messages?.Value == null || !messages.Value.Any())
                {
                    result.Success = false;
                    result.ErrorMessage = "Message not found or may have been removed from the mailbox";
                    return result;
                }

                var message = messages.Value.First();
                var messageId = message.Id!;

                // Check for duplicates
                if (duplicateTracker.Contains(messageId))
                {
                    result.IsDuplicate = true;
                    result.Success = false;
                    result.ErrorMessage = "Duplicate message - already processed";
                    return result;
                }

                duplicateTracker.Add(messageId);

                // Generate filename
#pragma warning disable SA1101
                var fileName = await GenerateFileNameAsync(message, OutputFormat);
#pragma warning restore SA1101
#pragma warning disable SA1101
                var filePath = Path.Combine(OutputDirectory!, fileName);
#pragma warning restore SA1101

                // Ensure unique filename
                var counter = 1;
                var originalFileName = fileName;
                while (File.Exists(filePath))
                {
                    var extension = Path.GetExtension(originalFileName);
                    var nameWithoutExtension = Path.GetFileNameWithoutExtension(originalFileName);
                    fileName = $"{nameWithoutExtension}_{counter}{extension}";
#pragma warning disable SA1101
                    filePath = Path.Combine(OutputDirectory!, fileName);
#pragma warning restore SA1101
                    counter++;
                }

                // Download the email content
#pragma warning disable SA1101
                var emailStream = await graphClient.Users[UserId].Messages[messageId].Content
                    .GetAsync(cancellationToken: cancellationToken);
#pragma warning restore SA1101

                if (emailStream != null)
                {
                    using var fileStream = File.Create(filePath);
                    await emailStream.CopyToAsync(fileStream);
                }

                result.Success = true;
                result.FileName = fileName;
                result.FilePath = filePath;
                result.Subject = message.Subject ?? "";
                result.ReceivedDateTime = message.ReceivedDateTime?.DateTime;
                result.FromAddress = message.From?.EmailAddress?.Address ?? "";

                // Process attachments if requested
#pragma warning disable SA1101
                if (IncludeAttachments.IsPresent && message.HasAttachments == true)
                {
#pragma warning disable SA1101
                    var attachmentsProcessed = await ProcessAttachmentsAsync(
                        graphClient, messageId, fileName, cancellationToken);
#pragma warning restore SA1101
                    result.AttachmentsProcessed = attachmentsProcessed;
                }
#pragma warning restore SA1101
            }
            catch (ServiceException ex)
            {
                result.Success = false;
                result.ErrorMessage = $"Graph API error: {ex.ResponseStatusCode} - {ex.Message}";
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private async Task<string> GenerateFileNameAsync(Message message, string format)
        {
            var subject = message.Subject ?? "No Subject";
            var receivedDate = message.ReceivedDateTime?.DateTime ?? DateTime.UtcNow;

            // Sanitize subject for filename
#pragma warning disable SA1101
            var sanitizedSubject = SanitizeFileName(subject);
#pragma warning restore SA1101

            // Truncate if too long
            if (sanitizedSubject.Length > 100)
            {
                sanitizedSubject = sanitizedSubject.Substring(0, 100);
            }

            var extension = format.Equals("TXT", StringComparison.OrdinalIgnoreCase) ? "txt" : "eml";
            var fileName = $"{receivedDate:yyyyMMdd_HHmmss}-{sanitizedSubject}.{extension}";

            return fileName;
        }

        private string SanitizeFileName(string fileName)
        {
            var invalidChars = Path.GetInvalidFileNameChars();
            return string.Join("_", fileName.Split(invalidChars, StringSplitOptions.RemoveEmptyEntries));
        }

        private async Task<int> ProcessAttachmentsAsync(
            GraphServiceClient graphClient,
            string messageId,
            string emailFileName,
            CancellationToken cancellationToken)
        {
            var attachmentsProcessed = 0;

            try
            {
#pragma warning disable SA1101
                var attachments = await graphClient.Users[UserId].Messages[messageId].Attachments
                    .GetAsync(cancellationToken: cancellationToken);
#pragma warning restore SA1101

                if (attachments?.Value == null || !attachments.Value.Any())
                {
                    return 0;
                }

                var emailNameWithoutExtension = Path.GetFileNameWithoutExtension(emailFileName);
#pragma warning disable SA1101
                var attachmentDir = Path.Combine(OutputDirectory!, $"{emailNameWithoutExtension}_Attachments");
#pragma warning restore SA1101
                Directory.CreateDirectory(attachmentDir);

                foreach (var attachment in attachments.Value)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    try
                    {
                        if (attachment is FileAttachment fileAttachment)
                        {
#pragma warning disable SA1101
                            await SaveFileAttachmentAsync(fileAttachment, attachmentDir);
#pragma warning restore SA1101
                            attachmentsProcessed++;
                            WriteVerboseWithTimestamp($"Saved attachment: {fileAttachment.Name}");
                        }
                        else if (attachment is ItemAttachment itemAttachment)
                        {
#pragma warning disable SA1101
                            await SaveItemAttachmentAsync(graphClient, messageId, itemAttachment, attachmentDir, cancellationToken);
#pragma warning restore SA1101
                            attachmentsProcessed++;
                            WriteVerboseWithTimestamp($"Saved item attachment: {itemAttachment.Name}");
                        }
                    }
                    catch (Exception ex)
                    {
#pragma warning disable SA1101
                        WriteWarningWithTimestamp($"Failed to save attachment {attachment.Name}: {ex.Message}");
#pragma warning restore SA1101
                    }
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteWarningWithTimestamp($"Error processing attachments: {ex.Message}");
#pragma warning restore SA1101
            }

            return attachmentsProcessed;
        }

        private async Task SaveFileAttachmentAsync(FileAttachment attachment, string attachmentDir)
        {
            if (attachment.ContentBytes == null || string.IsNullOrEmpty(attachment.Name))
                return;

#pragma warning disable SA1101
            var fileName = SanitizeFileName(attachment.Name);
#pragma warning restore SA1101
            var filePath = Path.Combine(attachmentDir, fileName);

            // Ensure unique filename
            var counter = 1;
            var originalFileName = fileName;
            while (File.Exists(filePath))
            {
                var extension = Path.GetExtension(originalFileName);
                var nameWithoutExtension = Path.GetFileNameWithoutExtension(originalFileName);
                fileName = $"{nameWithoutExtension}_{counter}{extension}";
                filePath = Path.Combine(attachmentDir, fileName);
                counter++;
            }

            await Task.Run(() => File.WriteAllBytes(filePath, attachment.ContentBytes));
        }

        private async Task SaveItemAttachmentAsync(
            GraphServiceClient graphClient,
            string messageId,
            ItemAttachment attachment,
            string attachmentDir,
            CancellationToken cancellationToken)
        {
            try
            {
                // Get the full item attachment
#pragma warning disable SA1101
                var fullAttachment = await graphClient.Users[UserId]
                    .Messages[messageId]
                    .Attachments[attachment.Id]
                    .GetAsync(cancellationToken: cancellationToken);
#pragma warning restore SA1101

                if (fullAttachment is ItemAttachment itemAtt && itemAtt.Item is Message attachedMessage)
                {
#pragma warning disable SA1101
                    var fileName = SanitizeFileName($"{attachment.Name ?? "ItemAttachment"}.eml");
#pragma warning restore SA1101
                    var filePath = Path.Combine(attachmentDir, fileName);

                    // For item attachments, we'll save the message properties as JSON
                    var messageData = new
                    {
                        Subject = attachedMessage.Subject,
                        From = attachedMessage.From?.EmailAddress?.Address,
                        To = attachedMessage.ToRecipients?.Select(r => r.EmailAddress?.Address),
                        ReceivedDateTime = attachedMessage.ReceivedDateTime,
                        Body = attachedMessage.Body?.Content
                    };

                    var json = System.Text.Json.JsonSerializer.Serialize(messageData, new System.Text.Json.JsonSerializerOptions
                    {
                        WriteIndented = true
                    });

                    using (var writer = new StreamWriter(filePath)) { await writer.WriteAsync(json); }
                }
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteWarningWithTimestamp($"Error saving item attachment: {ex.Message}");
#pragma warning restore SA1101
            }
        }
    }

#pragma warning disable SA1600
    public class EmailExportResult
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string InternetMessageId { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? FileName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? FilePath { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Subject { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? ReceivedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string FromAddress { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsDuplicate { get; set; }
#pragma warning restore SA1600
        public int AttachmentsProcessed { get; set; }
    }

#pragma warning disable SA1600
    public class EmailExportSummary
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public TimeSpan ProcessingTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalMessages { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int SuccessfulExports { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int FailedExports { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int Duplicates { get; set; }
#pragma warning restore SA1600
        public int TotalAttachments { get; set; }
    }
}
