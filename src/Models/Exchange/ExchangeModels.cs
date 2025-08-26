// <copyright file="ExchangeModels.cs" company="PlaceholderCompany">
// Copyright (c) PlaceholderCompany. All rights reserved.
// </copyright>

#nullable enable

namespace Microsoft.ExtractorSuite.Models.Exchange
{
    using System;
    using System.Text.Json.Serialization;

#pragma warning disable SA1600
#pragma warning disable SA1649
name
    public class ExchangeMailbox
#pragma warning restore SA1649
name
    {
        [JsonPropertyName("DisplayName")]
#pragma warning disable SA1600
        public string DisplayName { get; set; } = string.Empty;
#pragma warning restore SA1600

        [JsonPropertyName("Alias")]
#pragma warning disable SA1600
        public string Alias { get; set; } = string.Empty;
#pragma warning restore SA1600

        [JsonPropertyName("PrimarySmtpAddress")]
#pragma warning disable SA1600
        public string PrimarySmtpAddress { get; set; } = string.Empty;
#pragma warning restore SA1600

        [JsonPropertyName("UserPrincipalName")]
#pragma warning disable SA1600
        public string UserPrincipalName { get; set; } = string.Empty;
#pragma warning restore SA1600

        [JsonPropertyName("RecipientTypeDetails")]
#pragma warning disable SA1600
        public string RecipientTypeDetails { get; set; } = string.Empty;
#pragma warning restore SA1600

        [JsonPropertyName("WhenCreated")]
#pragma warning disable SA1600
        public DateTime? WhenCreated { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("WhenChanged")]
#pragma warning disable SA1600
        public DateTime? WhenChanged { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("IsMailboxEnabled")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool IsMailboxEnabled { get; set; }

        [JsonPropertyName("ArchiveStatus")]
#pragma warning disable SA1600
        public string ArchiveStatus { get; set; } = string.Empty;
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
#pragma warning disable SA1402
type
    public class UnifiedAuditLogResult
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("odata.metadata")]
#pragma warning disable SA1600
        public string Metadata { get; set; } = string.Empty;
#pragma warning restore SA1600

        [JsonPropertyName("odata.nextLink")]
#pragma warning disable SA1600
        public string NextLink { get; set; } = string.Empty;
#pragma warning restore SA1600

        [JsonPropertyName("value")]
#pragma warning disable SA1600
        public UnifiedAuditLogRecord[] Value { get; set; } = Array.Empty<UnifiedAuditLogRecord>();
#pragma warning restore SA1600

        [JsonPropertyName("ResultCount")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public int ResultCount { get; set; }

        [JsonPropertyName("HasMoreData")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool HasMoreData { get; set; }

        [JsonPropertyName("SessionId")]
#pragma warning disable SA1600
        public string SessionId { get; set; } = string.Empty;
#pragma warning restore SA1600

        [JsonPropertyName("ResultSetId")]
#pragma warning disable SA1600
        public string ResultSetId { get; set; } = string.Empty;
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
#pragma warning disable SA1402
type
    public class UnifiedAuditLogRecord
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("Id")]
#pragma warning disable SA1600
        public string Id { get; set; } = string.Empty;
#pragma warning restore SA1600

        [JsonPropertyName("RecordType")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public int RecordType { get; set; }

        [JsonPropertyName("CreationTime")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public DateTime CreationTime { get; set; }

        [JsonPropertyName("Operation")]
#pragma warning disable SA1600
        public string Operation { get; set; } = string.Empty;
#pragma warning restore SA1600

        [JsonPropertyName("OrganizationId")]
#pragma warning disable SA1600
        public string? OrganizationId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("UserType")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public int UserType { get; set; }

        [JsonPropertyName("UserKey")]
#pragma warning disable SA1600
        public string? UserKey { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Workload")]
#pragma warning disable SA1600
        public string? Workload { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ResultStatus")]
#pragma warning disable SA1600
        public string? ResultStatus { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ObjectId")]
#pragma warning disable SA1600
        public string? ObjectId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("UserId")]
#pragma warning disable SA1600
        public string? UserId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ClientIP")]
#pragma warning disable SA1600
        public string? ClientIP { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("AuditData")]
#pragma warning disable SA1600
        public string? AuditData { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
#pragma warning disable SA1402
type
    public class MessageTraceResult
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("odata.metadata")]
#pragma warning disable SA1600
        public string? Metadata { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("odata.nextLink")]
#pragma warning disable SA1600
        public string? NextLink { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("value")]
#pragma warning disable SA1600
        public MessageTrace[]? Value { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
#pragma warning disable SA1402
type
    public class MessageTrace
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("MessageId")]
#pragma warning disable SA1600
        public string? MessageId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("MessageTraceId")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public Guid MessageTraceId { get; set; }

        [JsonPropertyName("Received")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public DateTime Received { get; set; }

        [JsonPropertyName("SenderAddress")]
#pragma warning disable SA1600
        public string? SenderAddress { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("RecipientAddress")]
#pragma warning disable SA1600
        public string? RecipientAddress { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Subject")]
#pragma warning disable SA1600
        public string? Subject { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Status")]
#pragma warning disable SA1600
        public string? Status { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Size")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public long Size { get; set; }

        [JsonPropertyName("FromIP")]
#pragma warning disable SA1600
        public string? FromIP { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ToIP")]
#pragma warning disable SA1600
        public string? ToIP { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
#pragma warning disable SA1402
type
    public class MailboxInfo
#pragma warning restore SA1402
type
    {
#pragma warning disable SA1600
        public string? UserPrincipalName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? DisplayName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Email { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? MailboxGuid { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? RecipientTypeDetails { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime? WhenCreated { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool LitigationHoldEnabled { get; set; }
        public long? TotalItemSize { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public long? ItemCount { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
#pragma warning disable SA1402
type
    public class MailboxAuditLogResult
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("Records")]
#pragma warning disable SA1600
        public MailboxAuditLogRecord[]? Records { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("HasMoreData")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool HasMoreData { get; set; }

        [JsonPropertyName("ResultSetId")]
#pragma warning disable SA1600
        public string? ResultSetId { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
#pragma warning disable SA1402
type
    public class MailboxAuditLogRecord
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("Operation")]
#pragma warning disable SA1600
        public string? Operation { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("OperationResult")]
#pragma warning disable SA1600
        public string? OperationResult { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("LogonType")]
#pragma warning disable SA1600
        public string? LogonType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("LogonUserSid")]
#pragma warning disable SA1600
        public string? LogonUserSid { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("LogonUserDisplayName")]
#pragma warning disable SA1600
        public string? LogonUserDisplayName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ClientInfoString")]
#pragma warning disable SA1600
        public string? ClientInfoString { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ClientIPAddress")]
#pragma warning disable SA1600
        public string? ClientIPAddress { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ClientProcessName")]
#pragma warning disable SA1600
        public string? ClientProcessName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("LastAccessed")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public DateTime LastAccessed { get; set; }

        [JsonPropertyName("MailboxGuid")]
#pragma warning disable SA1600
        public string? MailboxGuid { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("MailboxOwnerUPN")]
#pragma warning disable SA1600
        public string? MailboxOwnerUPN { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("FolderId")]
#pragma warning disable SA1600
        public string? FolderId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("FolderPathName")]
#pragma warning disable SA1600
        public string? FolderPathName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ItemSubject")]
#pragma warning disable SA1600
        public string? ItemSubject { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
#pragma warning disable SA1402
type
    public class TransportRuleResult
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("value")]
#pragma warning disable SA1600
        public TransportRule[]? Value { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
#pragma warning disable SA1402
type
    public class TransportRule
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("Identity")]
#pragma warning disable SA1600
        public string? Identity { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Name")]
#pragma warning disable SA1600
        public string? Name { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("State")]
#pragma warning disable SA1600
        public string? State { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Mode")]
#pragma warning disable SA1600
        public string? Mode { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Priority")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public int Priority { get; set; }

        [JsonPropertyName("Description")]
#pragma warning disable SA1600
        public string? Description { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Conditions")]
#pragma warning disable SA1600
        public object? Conditions { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Actions")]
#pragma warning disable SA1600
        public object? Actions { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Exceptions")]
#pragma warning disable SA1600
        public object? Exceptions { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("WhenChanged")]
#pragma warning disable SA1600
        public DateTime? WhenChanged { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
#pragma warning disable SA1402
type
    public class InboxRuleResult
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("value")]
#pragma warning disable SA1600
        public InboxRule[]? Value { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("@odata.nextLink")]
#pragma warning disable SA1600
        public string? NextLink { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
#pragma warning disable SA1402
type
    public class InboxRule
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("Identity")]
#pragma warning disable SA1600
        public string? Identity { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("RuleIdentity")]
#pragma warning disable SA1600
        public string? RuleIdentity { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Name")]
#pragma warning disable SA1600
        public string? Name { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Enabled")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool Enabled { get; set; }

        [JsonPropertyName("Priority")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public int Priority { get; set; }

        [JsonPropertyName("StopProcessingRules")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool StopProcessingRules { get; set; }

        [JsonPropertyName("InError")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool InError { get; set; }

        [JsonPropertyName("ErrorType")]
#pragma warning disable SA1600
        public string? ErrorType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Description")]
#pragma warning disable SA1600
        public string? Description { get; set; }
#pragma warning restore SA1600

        // Actions
        [JsonPropertyName("CopyToFolder")]
#pragma warning disable SA1600
        public string? CopyToFolder { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("MoveToFolder")]
#pragma warning disable SA1600
        public string? MoveToFolder { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("RedirectTo")]
#pragma warning disable SA1600
        public string[]? RedirectTo { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ForwardTo")]
#pragma warning disable SA1600
        public string[]? ForwardTo { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ForwardAsAttachmentTo")]
#pragma warning disable SA1600
        public string[]? ForwardAsAttachmentTo { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("DeleteMessage")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool DeleteMessage { get; set; }

        [JsonPropertyName("SoftDeleteMessage")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool SoftDeleteMessage { get; set; }

        [JsonPropertyName("MarkAsRead")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool MarkAsRead { get; set; }

        [JsonPropertyName("MarkImportance")]
#pragma warning disable SA1600
        public string? MarkImportance { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ApplyCategory")]
#pragma warning disable SA1600
        public string[]? ApplyCategory { get; set; }
#pragma warning restore SA1600

        // Conditions
        [JsonPropertyName("From")]
#pragma warning disable SA1600
        public string[]? From { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("SentTo")]
#pragma warning disable SA1600
        public string[]? SentTo { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("SubjectContainsWords")]
#pragma warning disable SA1600
        public string[]? SubjectContainsWords { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("SubjectOrBodyContainsWords")]
#pragma warning disable SA1600
        public string[]? SubjectOrBodyContainsWords { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("BodyContainsWords")]
#pragma warning disable SA1600
        public string[]? BodyContainsWords { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("HasAttachment")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool HasAttachment { get; set; }

        [JsonPropertyName("WithImportance")]
#pragma warning disable SA1600
        public string? WithImportance { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ReceivedAfterDate")]
#pragma warning disable SA1600
        public DateTime? ReceivedAfterDate { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ReceivedBeforeDate")]
#pragma warning disable SA1600
        public DateTime? ReceivedBeforeDate { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("MyNameInToOrCcBox")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool MyNameInToOrCcBox { get; set; }

        [JsonPropertyName("SentOnlyToMe")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool SentOnlyToMe { get; set; }

        [JsonPropertyName("MailboxOwnerId")]
#pragma warning disable SA1600
        public string? MailboxOwnerId { get; set; }
#pragma warning restore SA1600
    }

    #region InvokeCommand Models

    /// <summary>
    /// Result from invoking Exchange Online PowerShell cmdlets via the beta admin API
    /// </summary>
#pragma warning disable SA1402
type
    public class InvokeCommandResult
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("Results")]
#pragma warning disable SA1600
        public InvokeCommandResultItem[]? Results { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Errors")]
#pragma warning disable SA1600
        public InvokeCommandError[]? Errors { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Warnings")]
#pragma warning disable SA1600
        public string[]? Warnings { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("HasErrors")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool HasErrors { get; set; }

        [JsonPropertyName("HasWarnings")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool HasWarnings { get; set; }
    }

    /// <summary>
    /// Individual result item from a cmdlet execution
    /// </summary>
#pragma warning disable SA1402
type
    public class InvokeCommandResultItem
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("ObjectId")]
#pragma warning disable SA1600
        public string? ObjectId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Output")]
#pragma warning disable SA1600
        public object? Output { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ErrorDetails")]
#pragma warning disable SA1600
        public string? ErrorDetails { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("HasErrors")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool HasErrors { get; set; }

        [JsonPropertyName("HasWarnings")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool HasWarnings { get; set; }

        [JsonPropertyName("Warnings")]
#pragma warning disable SA1600
        public string[]? Warnings { get; set; }
#pragma warning restore SA1600
    }

    /// <summary>
    /// Error information from cmdlet execution
    /// </summary>
#pragma warning disable SA1402
type
    public class InvokeCommandError
#pragma warning restore SA1402
type
    {
        [JsonPropertyName("ErrorCode")]
#pragma warning disable SA1600
        public string? ErrorCode { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ErrorDescription")]
#pragma warning disable SA1600
        public string? ErrorDescription { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ErrorType")]
#pragma warning disable SA1600
        public string? ErrorType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("RecommendedAction")]
#pragma warning disable SA1600
        public string? RecommendedAction { get; set; }
#pragma warning restore SA1600
    }

    #endregion
}
