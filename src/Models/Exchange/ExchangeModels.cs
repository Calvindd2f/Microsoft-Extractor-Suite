// <copyright file="ExchangeModels.cs" company="PlaceholderCompany">
// Copyright (c) PlaceholderCompany. All rights reserved.
// </copyright>

#nullable enable

namespace Microsoft.ExtractorSuite.Models.Exchange
{
    using System;
    using System.Text.Json.Serialization;



name
    public class ExchangeMailbox

name
    {
        [JsonPropertyName("DisplayName")]

        public string DisplayName { get; set; } = string.Empty;


        [JsonPropertyName("Alias")]

        public string Alias { get; set; } = string.Empty;


        [JsonPropertyName("PrimarySmtpAddress")]

        public string PrimarySmtpAddress { get; set; } = string.Empty;


        [JsonPropertyName("UserPrincipalName")]

        public string UserPrincipalName { get; set; } = string.Empty;


        [JsonPropertyName("RecipientTypeDetails")]

        public string RecipientTypeDetails { get; set; } = string.Empty;


        [JsonPropertyName("WhenCreated")]

        public DateTime? WhenCreated { get; set; }


        [JsonPropertyName("WhenChanged")]

        public DateTime? WhenChanged { get; set; }


        [JsonPropertyName("IsMailboxEnabled")]


        public bool IsMailboxEnabled { get; set; }

        [JsonPropertyName("ArchiveStatus")]

        public string ArchiveStatus { get; set; } = string.Empty;

    }



type
    public class UnifiedAuditLogResult

type
    {
        [JsonPropertyName("odata.metadata")]

        public string Metadata { get; set; } = string.Empty;


        [JsonPropertyName("odata.nextLink")]

        public string NextLink { get; set; } = string.Empty;


        [JsonPropertyName("value")]

        public UnifiedAuditLogRecord[] Value { get; set; } = Array.Empty<UnifiedAuditLogRecord>();


        [JsonPropertyName("ResultCount")]


        public int ResultCount { get; set; }

        [JsonPropertyName("HasMoreData")]


        public bool HasMoreData { get; set; }

        [JsonPropertyName("SessionId")]

        public string SessionId { get; set; } = string.Empty;


        [JsonPropertyName("ResultSetId")]

        public string ResultSetId { get; set; } = string.Empty;

    }



type
    public class UnifiedAuditLogRecord

type
    {
        [JsonPropertyName("Id")]

        public string Id { get; set; } = string.Empty;


        [JsonPropertyName("RecordType")]


        public int RecordType { get; set; }

        [JsonPropertyName("CreationTime")]


        public DateTime CreationTime { get; set; }

        [JsonPropertyName("Operation")]

        public string Operation { get; set; } = string.Empty;


        [JsonPropertyName("OrganizationId")]

        public string? OrganizationId { get; set; }


        [JsonPropertyName("UserType")]


        public int UserType { get; set; }

        [JsonPropertyName("UserKey")]

        public string? UserKey { get; set; }


        [JsonPropertyName("Workload")]

        public string? Workload { get; set; }


        [JsonPropertyName("ResultStatus")]

        public string? ResultStatus { get; set; }


        [JsonPropertyName("ObjectId")]

        public string? ObjectId { get; set; }


        [JsonPropertyName("UserId")]

        public string? UserId { get; set; }


        [JsonPropertyName("ClientIP")]

        public string? ClientIP { get; set; }


        [JsonPropertyName("AuditData")]

        public string? AuditData { get; set; }

    }



type
    public class MessageTraceResult

type
    {
        [JsonPropertyName("odata.metadata")]

        public string? Metadata { get; set; }


        [JsonPropertyName("odata.nextLink")]

        public string? NextLink { get; set; }


        [JsonPropertyName("value")]

        public MessageTrace[]? Value { get; set; }

    }



type
    public class MessageTrace

type
    {
        [JsonPropertyName("MessageId")]

        public string? MessageId { get; set; }


        [JsonPropertyName("MessageTraceId")]


        public Guid MessageTraceId { get; set; }

        [JsonPropertyName("Received")]


        public DateTime Received { get; set; }

        [JsonPropertyName("SenderAddress")]

        public string? SenderAddress { get; set; }


        [JsonPropertyName("RecipientAddress")]

        public string? RecipientAddress { get; set; }


        [JsonPropertyName("Subject")]

        public string? Subject { get; set; }


        [JsonPropertyName("Status")]

        public string? Status { get; set; }


        [JsonPropertyName("Size")]


        public long Size { get; set; }

        [JsonPropertyName("FromIP")]

        public string? FromIP { get; set; }


        [JsonPropertyName("ToIP")]

        public string? ToIP { get; set; }

    }



type
    public class MailboxInfo

type
    {

        public string? UserPrincipalName { get; set; }


        public string? DisplayName { get; set; }


        public string? Email { get; set; }


        public string? MailboxGuid { get; set; }


        public string? RecipientTypeDetails { get; set; }


        public DateTime? WhenCreated { get; set; }




        public bool LitigationHoldEnabled { get; set; }
        public long? TotalItemSize { get; set; }


        public long? ItemCount { get; set; }

    }



type
    public class MailboxAuditLogResult

type
    {
        [JsonPropertyName("Records")]

        public MailboxAuditLogRecord[]? Records { get; set; }


        [JsonPropertyName("HasMoreData")]


        public bool HasMoreData { get; set; }

        [JsonPropertyName("ResultSetId")]

        public string? ResultSetId { get; set; }

    }



type
    public class MailboxAuditLogRecord

type
    {
        [JsonPropertyName("Operation")]

        public string? Operation { get; set; }


        [JsonPropertyName("OperationResult")]

        public string? OperationResult { get; set; }


        [JsonPropertyName("LogonType")]

        public string? LogonType { get; set; }


        [JsonPropertyName("LogonUserSid")]

        public string? LogonUserSid { get; set; }


        [JsonPropertyName("LogonUserDisplayName")]

        public string? LogonUserDisplayName { get; set; }


        [JsonPropertyName("ClientInfoString")]

        public string? ClientInfoString { get; set; }


        [JsonPropertyName("ClientIPAddress")]

        public string? ClientIPAddress { get; set; }


        [JsonPropertyName("ClientProcessName")]

        public string? ClientProcessName { get; set; }


        [JsonPropertyName("LastAccessed")]


        public DateTime LastAccessed { get; set; }

        [JsonPropertyName("MailboxGuid")]

        public string? MailboxGuid { get; set; }


        [JsonPropertyName("MailboxOwnerUPN")]

        public string? MailboxOwnerUPN { get; set; }


        [JsonPropertyName("FolderId")]

        public string? FolderId { get; set; }


        [JsonPropertyName("FolderPathName")]

        public string? FolderPathName { get; set; }


        [JsonPropertyName("ItemSubject")]

        public string? ItemSubject { get; set; }

    }



type
    public class TransportRuleResult

type
    {
        [JsonPropertyName("value")]

        public TransportRule[]? Value { get; set; }

    }



type
    public class TransportRule

type
    {
        [JsonPropertyName("Identity")]

        public string? Identity { get; set; }


        [JsonPropertyName("Name")]

        public string? Name { get; set; }


        [JsonPropertyName("State")]

        public string? State { get; set; }


        [JsonPropertyName("Mode")]

        public string? Mode { get; set; }


        [JsonPropertyName("Priority")]


        public int Priority { get; set; }

        [JsonPropertyName("Description")]

        public string? Description { get; set; }


        [JsonPropertyName("Conditions")]

        public object? Conditions { get; set; }


        [JsonPropertyName("Actions")]

        public object? Actions { get; set; }


        [JsonPropertyName("Exceptions")]

        public object? Exceptions { get; set; }


        [JsonPropertyName("WhenChanged")]

        public DateTime? WhenChanged { get; set; }

    }



type
    public class InboxRuleResult

type
    {
        [JsonPropertyName("value")]

        public InboxRule[]? Value { get; set; }


        [JsonPropertyName("@odata.nextLink")]

        public string? NextLink { get; set; }

    }



type
    public class InboxRule

type
    {
        [JsonPropertyName("Identity")]

        public string? Identity { get; set; }


        [JsonPropertyName("RuleIdentity")]

        public string? RuleIdentity { get; set; }


        [JsonPropertyName("Name")]

        public string? Name { get; set; }


        [JsonPropertyName("Enabled")]


        public bool Enabled { get; set; }

        [JsonPropertyName("Priority")]


        public int Priority { get; set; }

        [JsonPropertyName("StopProcessingRules")]


        public bool StopProcessingRules { get; set; }

        [JsonPropertyName("InError")]


        public bool InError { get; set; }

        [JsonPropertyName("ErrorType")]

        public string? ErrorType { get; set; }


        [JsonPropertyName("Description")]

        public string? Description { get; set; }


        // Actions
        [JsonPropertyName("CopyToFolder")]

        public string? CopyToFolder { get; set; }


        [JsonPropertyName("MoveToFolder")]

        public string? MoveToFolder { get; set; }


        [JsonPropertyName("RedirectTo")]

        public string[]? RedirectTo { get; set; }


        [JsonPropertyName("ForwardTo")]

        public string[]? ForwardTo { get; set; }


        [JsonPropertyName("ForwardAsAttachmentTo")]

        public string[]? ForwardAsAttachmentTo { get; set; }


        [JsonPropertyName("DeleteMessage")]


        public bool DeleteMessage { get; set; }

        [JsonPropertyName("SoftDeleteMessage")]


        public bool SoftDeleteMessage { get; set; }

        [JsonPropertyName("MarkAsRead")]


        public bool MarkAsRead { get; set; }

        [JsonPropertyName("MarkImportance")]

        public string? MarkImportance { get; set; }


        [JsonPropertyName("ApplyCategory")]

        public string[]? ApplyCategory { get; set; }


        // Conditions
        [JsonPropertyName("From")]

        public string[]? From { get; set; }


        [JsonPropertyName("SentTo")]

        public string[]? SentTo { get; set; }


        [JsonPropertyName("SubjectContainsWords")]

        public string[]? SubjectContainsWords { get; set; }


        [JsonPropertyName("SubjectOrBodyContainsWords")]

        public string[]? SubjectOrBodyContainsWords { get; set; }


        [JsonPropertyName("BodyContainsWords")]

        public string[]? BodyContainsWords { get; set; }


        [JsonPropertyName("HasAttachment")]


        public bool HasAttachment { get; set; }

        [JsonPropertyName("WithImportance")]

        public string? WithImportance { get; set; }


        [JsonPropertyName("ReceivedAfterDate")]

        public DateTime? ReceivedAfterDate { get; set; }


        [JsonPropertyName("ReceivedBeforeDate")]

        public DateTime? ReceivedBeforeDate { get; set; }


        [JsonPropertyName("MyNameInToOrCcBox")]


        public bool MyNameInToOrCcBox { get; set; }

        [JsonPropertyName("SentOnlyToMe")]


        public bool SentOnlyToMe { get; set; }

        [JsonPropertyName("MailboxOwnerId")]

        public string? MailboxOwnerId { get; set; }

    }

    #region InvokeCommand Models

    /// <summary>
    /// Result from invoking Exchange Online PowerShell cmdlets via the beta admin API
    /// </summary>

type
    public class InvokeCommandResult

type
    {
        [JsonPropertyName("Results")]

        public InvokeCommandResultItem[]? Results { get; set; }


        [JsonPropertyName("Errors")]

        public InvokeCommandError[]? Errors { get; set; }


        [JsonPropertyName("Warnings")]

        public string[]? Warnings { get; set; }


        [JsonPropertyName("HasErrors")]


        public bool HasErrors { get; set; }

        [JsonPropertyName("HasWarnings")]


        public bool HasWarnings { get; set; }
    }

    /// <summary>
    /// Individual result item from a cmdlet execution
    /// </summary>

type
    public class InvokeCommandResultItem

type
    {
        [JsonPropertyName("ObjectId")]

        public string? ObjectId { get; set; }


        [JsonPropertyName("Output")]

        public object? Output { get; set; }


        [JsonPropertyName("ErrorDetails")]

        public string? ErrorDetails { get; set; }


        [JsonPropertyName("HasErrors")]


        public bool HasErrors { get; set; }

        [JsonPropertyName("HasWarnings")]


        public bool HasWarnings { get; set; }

        [JsonPropertyName("Warnings")]

        public string[]? Warnings { get; set; }

    }

    /// <summary>
    /// Error information from cmdlet execution
    /// </summary>

type
    public class InvokeCommandError

type
    {
        [JsonPropertyName("ErrorCode")]

        public string? ErrorCode { get; set; }


        [JsonPropertyName("ErrorDescription")]

        public string? ErrorDescription { get; set; }


        [JsonPropertyName("ErrorType")]

        public string? ErrorType { get; set; }


        [JsonPropertyName("RecommendedAction")]

        public string? RecommendedAction { get; set; }

    }

    #endregion
}
