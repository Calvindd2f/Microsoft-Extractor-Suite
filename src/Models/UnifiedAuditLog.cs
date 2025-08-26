namespace Microsoft.ExtractorSuite.Models
{
    using System;
    using System.Text.Json.Serialization;

#pragma warning disable SA1600
    public class UnifiedAuditLog
#pragma warning restore SA1600
    {
        [JsonPropertyName("Id")]
#pragma warning disable SA1600
        public string? Id { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("RecordType")]
#pragma warning disable SA1600
        public string? RecordType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("CreationTime")]
#pragma warning disable SA1600
        public DateTime? CreationTime { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("Operation")]
#pragma warning disable SA1600
        public string? Operation { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("OrganizationId")]
#pragma warning disable SA1600
        public string? OrganizationId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("UserType")]
#pragma warning disable SA1600
        public int? UserType { get; set; }
#pragma warning restore SA1600

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

        [JsonPropertyName("Scope")]
#pragma warning disable SA1600
        public string? Scope { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("AuditData")]
#pragma warning disable SA1600
        public string? AuditData { get; set; }
#pragma warning restore SA1600

        // Parsed audit data (lazy loaded)
#pragma warning disable SA1309
#pragma warning disable SA1201
        private object? _parsedAuditData;
#pragma warning restore SA1201
#pragma warning disable SA1600

#pragma warning restore SA1600
        [JsonIgnore]
        public object? ParsedAuditData
        {
            get
            {
#pragma warning disable SA1101
                if (_parsedAuditData == null && !string.IsNullOrEmpty(AuditData))
                {
                    try
                    {
#pragma warning disable SA1101
                        _parsedAuditData = System.Text.Json.JsonSerializer.Deserialize<object>(AuditData!);
#pragma warning restore SA1101
                    }
                    catch
                    {
#pragma warning disable SA1101
                        _parsedAuditData = AuditData;
#pragma warning restore SA1101
                    }
                }
#pragma warning restore SA1101
#pragma warning disable SA1101
                return _parsedAuditData;
#pragma warning restore SA1101
            }
        }
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

    public class AuditLogResponse
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
        [JsonPropertyName("Results")]
        public UnifiedAuditLog[] Results { get; set; } = Array.Empty<UnifiedAuditLog>();
#pragma warning disable SA1600

#pragma warning restore SA1600
        [JsonPropertyName("ResultCount")]
#pragma warning disable SA1600
        #pragma warning restore SA1600
        public int ResultCount { get; set; }
        [JsonPropertyName("HasMoreData")]
#pragma warning disable SA1600
        #pragma warning restore SA1600
        public bool HasMoreData { get; set; }
        [JsonPropertyName("ResultSetId")]
        public string? ResultSetId { get; set; }
#pragma warning disable SA1600

#pragma warning restore SA1600
        [JsonPropertyName("ErrorMessage")]
        public string? ErrorMessage { get; set; }
    }
}
