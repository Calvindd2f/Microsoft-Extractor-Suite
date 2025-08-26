using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Cmdlets.MLPipeline;

namespace Microsoft.ExtractorSuite.Core.MLPipeline
{
#pragma warning disable SA1600
    public class OpenPipeDataExporter
#pragma warning restore SA1600
    {
#pragma warning disable SA1309
        private readonly JsonSerializerOptions _serializerOptions;
#pragma warning disable SA1600
#pragma warning restore SA1309

        public OpenPipeDataExporter()
        {
#pragma warning disable SA1101
            _serializerOptions = new JsonSerializerOptions
            {
                WriteIndented = false,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public async Task<string> ExportToOpenPipeFormatAsync(
            List<MLTrainingRecord> data,
            string outputPath,
            ExportOptions options,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var openPipePath = GetOpenPipePath(outputPath);
#pragma warning restore SA1101

            using var writer = new StreamWriter(openPipePath);
            var recordCount = 0;

            foreach (var record in data)
            {
#pragma warning disable SA1101
                var openPipeRecord = ConvertToOpenPipeFormat(record, options);
#pragma warning restore SA1101
#pragma warning disable SA1101
                var json = JsonSerializer.Serialize(openPipeRecord, _serializerOptions);
#pragma warning restore SA1101
                await writer.WriteLineAsync(json);

                recordCount++;
                if (recordCount % 1000 == 0)
                {
                    // Log progress every 1000 records
                    Console.WriteLine($"Exported {recordCount} records...");
                }

                cancellationToken.ThrowIfCancellationRequested();
            }

            return openPipePath;
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public async Task<string> ExportToStandardJSONLAsync(
            List<MLTrainingRecord> data,
            string outputPath,
            ExportOptions options,
            CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var jsonlPath = GetJSONLPath(outputPath);
#pragma warning restore SA1101

            using var writer = new StreamWriter(jsonlPath);
            var recordCount = 0;

            foreach (var record in data)
            {
#pragma warning disable SA1101
                var json = JsonSerializer.Serialize(record, _serializerOptions);
#pragma warning restore SA1101
                await writer.WriteLineAsync(json);

                recordCount++;
                if (recordCount % 1000 == 0)
                {
                    Console.WriteLine($"Exported {recordCount} records...");
                }

                cancellationToken.ThrowIfCancellationRequested();
            }

            return jsonlPath;
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public async Task<ExportMetadata> ExportWithMetadataAsync(
            List<MLTrainingRecord> data,
            string outputPath,
            ExportOptions options,
            CancellationToken cancellationToken)
        {
            var metadata = new ExportMetadata
            {
                ExportTime = DateTime.UtcNow,
                TotalRecords = data.Count,
                DataSources = data.Select(r => r.Source).Distinct().ToArray(),
                DateRange = new DateRange
                {
                    Start = data.Min(r => r.Timestamp),
                    End = data.Max(r => r.Timestamp)
                },
                Options = options
            };

            // Export data
#pragma warning disable SA1101
            var openPipePath = await ExportToOpenPipeFormatAsync(data, outputPath, options, cancellationToken);
#pragma warning restore SA1101
#pragma warning disable SA1101
            var jsonlPath = await ExportToStandardJSONLAsync(data, outputPath, options, cancellationToken);
#pragma warning restore SA1101

            // Export metadata
            var metadataPath = Path.Combine(Path.GetDirectoryName(outputPath)!, "export_metadata.json");
            var metadataJson = JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(metadataPath, metadataJson, cancellationToken);

            metadata.OutputFiles = new[] { openPipePath, jsonlPath, metadataPath };
            return metadata;
        }

        private OpenPipeRecord ConvertToOpenPipeFormat(MLTrainingRecord record, ExportOptions options)
        {
            var messages = new List<OpenPipeMessage>();

            // Add system message if requested
            if (options.IncludeSystemMessage)
            {
                messages.Add(new OpenPipeMessage
                {
                    Role = "system",
                    Content = GetSystemMessage(record.Source)
                });
            }

            // Add user message
#pragma warning disable SA1101
            messages.Add(new OpenPipeMessage
            {
                Role = "user",
                Content = FormatUserPrompt(record, options)
            });
#pragma warning restore SA1101

            // Add assistant message
#pragma warning disable SA1101
            messages.Add(new OpenPipeMessage
            {
                Role = "assistant",
                Content = FormatAssistantResponse(record, options)
            });
#pragma warning restore SA1101

            return new OpenPipeRecord
            {
                Messages = messages.ToArray()
            };
        }

        private string GetSystemMessage(string source)
        {
            return source.ToLower() switch
            {
                "signinlogs" => "You are a cybersecurity analyst. Analyze sign-in logs for security risks and anomalies.",
                "auditlogs" => "You are a cybersecurity analyst. Analyze audit logs for suspicious activities and security concerns.",
                "mailboxaudit" => "You are a cybersecurity analyst. Analyze mailbox audit logs for email security threats.",
                "ual" => "You are a cybersecurity analyst. Analyze Unified Audit Logs for security incidents.",
                "securityalerts" => "You are a cybersecurity analyst. Analyze security alerts for threat assessment.",
                "riskdetections" => "You are a cybersecurity analyst. Analyze risk detections for threat evaluation.",
                _ => "You are a cybersecurity analyst. Analyze the provided data for security risks and threats."
            };
        }

        private string FormatUserPrompt(MLTrainingRecord record, ExportOptions options)
        {
            var prompt = $"Analyze the following {record.Source} record and determine the security risk level:\n\n";

            // Add structured data
            foreach (var kvp in record.Data)
            {
                if (options.IncludeAllFields || IsImportantField(kvp.Key))
                {
                    prompt += $"{kvp.Key}: {kvp.Value}\n";
                }
            }

            // Add labels if available
            if (options.IncludeLabels && record.Labels.Any())
            {
                prompt += "\nKnown Labels:\n";
                foreach (var label in record.Labels)
                {
                    prompt += $"- {label.Key}: {label.Value}\n";
                }
            }

            prompt += "\nWhat is the security risk level and why? Provide a detailed analysis.";
            return prompt;
        }

        private string FormatAssistantResponse(MLTrainingRecord record, ExportOptions options)
        {
            var riskLevel = record.Labels.GetValueOrDefault("risk_level", "unknown");
            var explanation = GenerateRiskExplanation(record, riskLevel);

            var response = $"Risk Level: {riskLevel}\n\n";
            response += $"Explanation: {explanation}\n\n";

            if (options.IncludeRecommendations)
            {
                response += $"Recommendations: {GenerateRecommendations(record, riskLevel)}";
            }

            return response;
        }

        private bool IsImportantField(string fieldName)
        {
            var importantFields = new[]
            {
                "ipAddress", "location", "country", "riskDetail", "status", "result",
                "category", "activity", "userId", "userPrincipalName", "appDisplayName"
            };

            return importantFields.Contains(fieldName, StringComparer.OrdinalIgnoreCase);
        }

        private string GenerateRiskExplanation(MLTrainingRecord record, string riskLevel)
        {
            var source = record.Source.ToLower();
            var data = record.Data;

            return source switch
            {
                "signinlogs" => GenerateSignInRiskExplanation(data, riskLevel),
                "auditlogs" => GenerateAuditRiskExplanation(data, riskLevel),
                "mailboxaudit" => GenerateMailboxRiskExplanation(data, riskLevel),
                "ual" => GenerateUALRiskExplanation(data, riskLevel),
                "securityalerts" => GenerateSecurityAlertExplanation(data, riskLevel),
                "riskdetections" => GenerateRiskDetectionExplanation(data, riskLevel),
                _ => $"Data from {source} analyzed for security patterns and risk indicators."
            };
        }

        private string GenerateSignInRiskExplanation(Dictionary<string, object> data, string riskLevel)
        {
            var explanations = new List<string>();

            if (data.ContainsKey("riskDetail") && data["riskDetail"]?.ToString() != "")
            {
                explanations.Add($"Sign-in shows {data["riskDetail"]} risk level based on Microsoft's risk assessment.");
            }

            if (data.ContainsKey("ipAddress") && !string.IsNullOrEmpty(data["ipAddress"]?.ToString()))
            {
                var ip = data["ipAddress"].ToString();
#pragma warning disable SA1101
                if (IsSuspiciousIP(ip))
                {
                    explanations.Add($"IP address {ip} is associated with suspicious activity or known threats.");
                }
#pragma warning restore SA1101
            }

            if (data.ContainsKey("location") && !string.IsNullOrEmpty(data["location"]?.ToString()))
            {
                var location = data["location"].ToString();
#pragma warning disable SA1101
                if (IsUnusualLocation(location))
                {
                    explanations.Add($"Sign-in from unusual location: {location}");
                }
#pragma warning restore SA1101
            }

            if (data.ContainsKey("status") && data["status"]?.ToString() != "")
            {
                explanations.Add($"Sign-in status indicates: {data["status"]}");
            }

            return explanations.Any()
                ? string.Join(" ", explanations)
                : "Standard sign-in with no elevated risk indicators.";
        }

        private string GenerateAuditRiskExplanation(Dictionary<string, object> data, string riskLevel)
        {
            var explanations = new List<string>();

            var category = data.GetValueOrDefault("category", "").ToString();
            var result = data.GetValueOrDefault("result", "").ToString();
            var activity = data.GetValueOrDefault("activity", "").ToString();

            if (result != "success")
            {
                explanations.Add($"Audit log shows {result} result for {category} activity, indicating potential security concern.");
            }

            if (IsHighRiskCategory(category))
            {
                explanations.Add($"Activity {activity} in category {category} is considered high-risk administrative action.");
            }

            if (data.ContainsKey("ipAddress") && !string.IsNullOrEmpty(data["ipAddress"]?.ToString()))
            {
                var ip = data["ipAddress"].ToString();
#pragma warning disable SA1101
                if (IsSuspiciousIP(ip))
                {
                    explanations.Add($"IP address {ip} is associated with suspicious activity.");
                }
#pragma warning restore SA1101
            }

            return explanations.Any()
                ? string.Join(" ", explanations)
                : $"Standard {category} activity completed successfully.";
        }

        private string GenerateMailboxRiskExplanation(Dictionary<string, object> data, string riskLevel)
        {
            // Placeholder for mailbox audit log explanation
            return "Mailbox audit log analyzed for email security threats and access patterns.";
        }

        private string GenerateUALRiskExplanation(Dictionary<string, object> data, string riskLevel)
        {
            // Placeholder for UAL explanation
            return "Unified Audit Log analyzed for comprehensive security monitoring and threat detection.";
        }

        private string GenerateSecurityAlertExplanation(Dictionary<string, object> data, string riskLevel)
        {
            // Placeholder for security alert explanation
            return "Security alert analyzed for threat assessment and response prioritization.";
        }

        private string GenerateRiskDetectionExplanation(Dictionary<string, object> data, string riskLevel)
        {
            // Placeholder for risk detection explanation
            return "Risk detection analyzed for threat evaluation and user risk assessment.";
        }

        private string GenerateRecommendations(MLTrainingRecord record, string riskLevel)
        {
            var recommendations = new List<string>();

            switch (riskLevel.ToLower())
            {
                case "high":
                    recommendations.AddRange(new[]
                    {
                        "Immediate investigation required",
                        "Consider blocking user account temporarily",
                        "Review recent user activities",
                        "Check for related security incidents"
                    });
                    break;

                case "medium":
                    recommendations.AddRange(new[]
                    {
                        "Monitor user activity closely",
                        "Review authentication patterns",
                        "Consider additional verification steps",
                        "Document incident for future reference"
                    });
                    break;

                case "low":
                    recommendations.AddRange(new[]
                    {
                        "Continue normal monitoring",
                        "Document for trend analysis",
                        "No immediate action required"
                    });
                    break;

                default:
                    recommendations.Add("Review data quality and labeling");
                    break;
            }

            return string.Join("; ", recommendations);
        }

        private bool IsSuspiciousIP(string? ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;

            // Simple heuristic for suspicious IPs
            // In production, this would integrate with threat intelligence feeds
            var suspiciousPatterns = new[]
            {
                "10.0.0.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
            };

            return suspiciousPatterns.Any(pattern => ip.StartsWith(pattern));
        }

        private bool IsUnusualLocation(string? location)
        {
            if (string.IsNullOrEmpty(location)) return false;

            // Simple heuristic for unusual locations
            // In production, this would use geographic analysis
            var unusualLocations = new[]
            {
                "unknown", "anonymous", "tor", "vpn", "proxy"
            };

            return unusualLocations.Any(loc => location.Contains(loc, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsHighRiskCategory(string? category)
        {
            if (string.IsNullOrEmpty(category)) return false;

            var highRiskCategories = new[]
            {
                "UserManagement", "GroupManagement", "ApplicationManagement", "DirectoryManagement",
                "Authentication", "Authorization", "SecuritySettings", "ComplianceSettings"
            };

            return highRiskCategories.Contains(category, StringComparer.OrdinalIgnoreCase);
        }

        private string GetOpenPipePath(string basePath)
        {
            return basePath.Replace(".jsonl", "_openpipe.jsonl");
        }

        private string GetJSONLPath(string basePath)
        {
            var jsonlPath = basePath.Replace("_openpipe.jsonl", ".jsonl");
            if (jsonlPath == basePath) jsonlPath = basePath.Replace(".jsonl", "_standard.jsonl");
            return jsonlPath;
        }
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class ExportOptions
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
        public bool IncludeSystemMessage { get; set; } = true;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public bool IncludeAllFields { get; set; } = false;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public bool IncludeLabels { get; set; } = true;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public bool IncludeRecommendations { get; set; } = true;
#pragma warning restore SA1600
        public bool AnonymizeData { get; set; } = true;
        public bool IncludeMetadata { get; set; } = true;
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class ExportMetadata
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime ExportTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalRecords { get; set; }
        public string[] DataSources { get; set; } = Array.Empty<string>();
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateRange DateRange { get; set; } = new();
#pragma warning restore SA1600
        public ExportOptions Options { get; set; } = new();
        public string[] OutputFiles { get; set; } = Array.Empty<string>();
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class DateRange
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTime Start { get; set; }public DateTime End { get; set; }
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class OpenPipeRecord
#pragma warning restore SA1600
    {
        public OpenPipeMessage[] Messages { get; set; } = Array.Empty<OpenPipeMessage>();
#pragma warning disable SA1600
    }
#pragma warning restore SA1600

#pragma warning disable SA1600
    public class OpenPipeMessage
#pragma warning restore SA1600
#pragma warning disable SA1600
    {
#pragma warning restore SA1600
        public string Role { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
    }
}
