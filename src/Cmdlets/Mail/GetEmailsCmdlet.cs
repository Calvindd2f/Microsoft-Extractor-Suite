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

namespace Microsoft.ExtractorSuite.Cmdlets.Mail
{
    /// <summary>
    /// Gets specific emails based on Internet Message IDs and saves them as EML or TXT files.
    /// Supports single email retrieval or batch processing from an input file.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "Emails")]
    [OutputType(typeof(EmailExportResult))]
    public class GetEmailsCmdlet : AsyncBaseCmdlet
    {
        [Parameter(Mandatory = true, HelpMessage = "The user ID or email address of the mailbox to search")]
        public string UserId { get; set; } = string.Empty;

        [Parameter(ParameterSetName = "SingleEmail", HelpMessage = "Internet Message ID of the specific email to retrieve")]
        public string? InternetMessageId { get; set; }

        [Parameter(ParameterSetName = "BatchFile", HelpMessage = "Path to text file containing multiple Internet Message IDs (one per line)")]
        public string? InputFile { get; set; }

        [Parameter(HelpMessage = "Output format for emails. Default: EML")]
        [ValidateSet("EML", "TXT")]
        public string OutputFormat { get; set; } = "EML";

        [Parameter(HelpMessage = "Include email attachments in the export")]
        public SwitchParameter IncludeAttachments { get; set; }

        protected override void ProcessRecord()
        {
            var results = RunAsyncOperation(GetEmailsAsync, "Getting Emails");

            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
        }

        private async Task<List<EmailExportResult>> GetEmailsAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Email Export");

            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Not connected to Microsoft Graph. Please run Connect-M365 first.");
            }

            var graphClient = AuthManager.GraphClient!;
            var results = new List<EmailExportResult>();
            var summary = new EmailExportSummary
            {
                StartTime = DateTime.UtcNow
            };

            // Set up output directory
            if (string.IsNullOrEmpty(OutputDirectory))
            {
                OutputDirectory = Path.Combine(Environment.CurrentDirectory, "Output", "EmailExport");
            }

            Directory.CreateDirectory(OutputDirectory);

            // Determine which emails to process
            List<string> messageIds;
            if (!string.IsNullOrEmpty(InternetMessageId))
            {
                messageIds = new List<string> { InternetMessageId };
            }
            else if (!string.IsNullOrEmpty(InputFile))
            {
                messageIds = await ReadMessageIdsFromFileAsync(InputFile, cancellationToken);
            }
            else
            {
                throw new ArgumentException("Either InternetMessageId or InputFile must be provided");
            }

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
                    var exportResult = await ProcessSingleEmailAsync(
                        graphClient, messageId.Trim(), duplicateTracker, cancellationToken);

                    results.Add(exportResult);

                    if (exportResult.Success)
                    {
                        summary.SuccessfulExports++;
                        WriteVerboseWithTimestamp($"✓ Successfully exported: {exportResult.FileName}");
                    }
                    else
                    {
                        summary.FailedExports++;
                        WriteWarningWithTimestamp($"✗ Failed to export: {messageId} - {exportResult.ErrorMessage}");
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
                    WriteErrorWithTimestamp($"Error processing message {messageId}: {ex.Message}", ex);
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
            if (IncludeAttachments.IsPresent)
            {
                WriteVerboseWithTimestamp($"  Attachments Processed: {summary.TotalAttachments}");
            }
            WriteVerboseWithTimestamp($"  Output Directory: {OutputDirectory}");
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
                WriteErrorWithTimestamp($"Failed to read input file: {ex.Message}", ex);
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
                var messages = await graphClient.Users[UserId].Messages
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Filter = $"internetMessageId eq '{internetMessageId}'";
                        requestConfiguration.QueryParameters.Select = new[]
                        {
                            "id", "subject", "receivedDateTime", "from", "hasAttachments", "internetMessageId"
                        };
                    }, cancellationToken);

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
                var fileName = await GenerateFileNameAsync(message, OutputFormat);
                var filePath = Path.Combine(OutputDirectory!, fileName);

                // Ensure unique filename
                var counter = 1;
                var originalFileName = fileName;
                while (File.Exists(filePath))
                {
                    var extension = Path.GetExtension(originalFileName);
                    var nameWithoutExtension = Path.GetFileNameWithoutExtension(originalFileName);
                    fileName = $"{nameWithoutExtension}_{counter}{extension}";
                    filePath = Path.Combine(OutputDirectory!, fileName);
                    counter++;
                }

                // Download the email content
                var emailStream = await graphClient.Users[UserId].Messages[messageId].Content
                    .GetAsync(cancellationToken: cancellationToken);

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
                if (IncludeAttachments.IsPresent && message.HasAttachments == true)
                {
                    var attachmentsProcessed = await ProcessAttachmentsAsync(
                        graphClient, messageId, fileName, cancellationToken);
                    result.AttachmentsProcessed = attachmentsProcessed;
                }
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
            var sanitizedSubject = SanitizeFileName(subject);

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
                var attachments = await graphClient.Users[UserId].Messages[messageId].Attachments
                    .GetAsync(cancellationToken: cancellationToken);

                if (attachments?.Value == null || !attachments.Value.Any())
                {
                    return 0;
                }

                var emailNameWithoutExtension = Path.GetFileNameWithoutExtension(emailFileName);
                var attachmentDir = Path.Combine(OutputDirectory!, $"{emailNameWithoutExtension}_Attachments");
                Directory.CreateDirectory(attachmentDir);

                foreach (var attachment in attachments.Value)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    try
                    {
                        if (attachment is FileAttachment fileAttachment)
                        {
                            await SaveFileAttachmentAsync(fileAttachment, attachmentDir);
                            attachmentsProcessed++;
                            WriteVerboseWithTimestamp($"Saved attachment: {fileAttachment.Name}");
                        }
                        else if (attachment is ItemAttachment itemAttachment)
                        {
                            await SaveItemAttachmentAsync(graphClient, messageId, itemAttachment, attachmentDir, cancellationToken);
                            attachmentsProcessed++;
                            WriteVerboseWithTimestamp($"Saved item attachment: {itemAttachment.Name}");
                        }
                    }
                    catch (Exception ex)
                    {
                        WriteWarningWithTimestamp($"Failed to save attachment {attachment.Name}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                WriteWarningWithTimestamp($"Error processing attachments: {ex.Message}");
            }

            return attachmentsProcessed;
        }

        private async Task SaveFileAttachmentAsync(FileAttachment attachment, string attachmentDir)
        {
            if (attachment.ContentBytes == null || string.IsNullOrEmpty(attachment.Name))
                return;

            var fileName = SanitizeFileName(attachment.Name);
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
                var fullAttachment = await graphClient.Users[UserId]
                    .Messages[messageId]
                    .Attachments[attachment.Id]
                    .GetAsync(cancellationToken: cancellationToken);

                if (fullAttachment is ItemAttachment itemAtt && itemAtt.Item is Message attachedMessage)
                {
                    var fileName = SanitizeFileName($"{attachment.Name ?? "ItemAttachment"}.eml");
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
                WriteWarningWithTimestamp($"Error saving item attachment: {ex.Message}");
            }
        }
    }

    public class EmailExportResult
    {
        public string InternetMessageId { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public string? FileName { get; set; }
        public string? FilePath { get; set; }
        public string Subject { get; set; } = string.Empty;
        public DateTime? ReceivedDateTime { get; set; }
        public string FromAddress { get; set; } = string.Empty;
        public bool IsDuplicate { get; set; }
        public int AttachmentsProcessed { get; set; }
    }

    public class EmailExportSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public int TotalMessages { get; set; }
        public int SuccessfulExports { get; set; }
        public int FailedExports { get; set; }
        public int Duplicates { get; set; }
        public int TotalAttachments { get; set; }
    }
}
