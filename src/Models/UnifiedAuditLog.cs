namespace Microsoft.ExtractorSuite.Models
{
    using System;
    using System.Text.Json.Serialization;


    public class UnifiedAuditLog

    {
        [JsonPropertyName("Id")]

        public string? Id { get; set; }


        [JsonPropertyName("RecordType")]

        public string? RecordType { get; set; }


        [JsonPropertyName("CreationTime")]

        public DateTime? CreationTime { get; set; }


        [JsonPropertyName("Operation")]

        public string? Operation { get; set; }


        [JsonPropertyName("OrganizationId")]

        public string? OrganizationId { get; set; }


        [JsonPropertyName("UserType")]

        public int? UserType { get; set; }


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


        [JsonPropertyName("Scope")]

        public string? Scope { get; set; }


        [JsonPropertyName("AuditData")]

        public string? AuditData { get; set; }


        // Parsed audit data (lazy loaded)


        private object? _parsedAuditData;




        [JsonIgnore]
        public object? ParsedAuditData
        {
            get
            {

                if (_parsedAuditData == null && !string.IsNullOrEmpty(AuditData))
                {
                    try
                    {

                        _parsedAuditData = System.Text.Json.JsonSerializer.Deserialize<object>(AuditData!);

                    }
                    catch
                    {

                        _parsedAuditData = AuditData;

                    }
                }


                return _parsedAuditData;

            }
        }

    }


    public class AuditLogResponse

    {

        [JsonPropertyName("Results")]
        public UnifiedAuditLog[] Results { get; set; } = Array.Empty<UnifiedAuditLog>();



        [JsonPropertyName("ResultCount")]


        public int ResultCount { get; set; }
        [JsonPropertyName("HasMoreData")]


        public bool HasMoreData { get; set; }
        [JsonPropertyName("ResultSetId")]
        public string? ResultSetId { get; set; }



        [JsonPropertyName("ErrorMessage")]
        public string? ErrorMessage { get; set; }
    }
}
