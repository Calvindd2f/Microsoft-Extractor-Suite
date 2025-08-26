using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Cmdlets.MLPipeline;

namespace Microsoft.ExtractorSuite.Core.MLPipeline
{

    public class DataQualityAnalyzer

    {

        public async Task<DataQualityMetrics> AnalyzeDataQualityAsync(

            List<MLTrainingRecord> data,
            CancellationToken cancellationToken)
        {
            if (data == null || !data.Any())
                return new DataQualityMetrics();

            var metrics = new DataQualityMetrics
            {
                TotalRecords = data.Count,
                MissingValuesByFeature = new Dictionary<string, int>(),
                UniqueValuesByFeature = new Dictionary<string, object>(),
                DataTypesByFeature = new Dictionary<string, object>(),
                QualityIssues = new List<string>()
            };

            try
            {
                // Analyze completeness

                await AnalyzeCompletenessAsync(data, metrics, cancellationToken);


                // Analyze data types

                await AnalyzeDataTypesAsync(data, metrics, cancellationToken);


                // Analyze value distributions

                await AnalyzeValueDistributionsAsync(data, metrics, cancellationToken);


                // Detect anomalies

                await DetectAnomaliesAsync(data, metrics, cancellationToken);


                // Calculate overall quality score

                metrics.CompletenessScore = CalculateCompletenessScore(metrics);

                metrics.CompleteRecords = data.Count - metrics.IncompleteRecords;

                // Generate quality recommendations

                await GenerateQualityRecommendationsAsync(metrics, cancellationToken);

            }
            catch (Exception ex)
            {
                metrics.QualityIssues.Add($"Error during quality analysis: {ex.Message}");
            }

            return metrics;
        }

        private async Task AnalyzeCompletenessAsync(
            List<MLTrainingRecord> data,
            DataQualityMetrics metrics,
            CancellationToken cancellationToken)
        {
            var allFeatures = data.SelectMany(r => r.Features.Keys).Distinct().ToList();
            var allLabels = data.SelectMany(r => r.Labels.Keys).Distinct().ToList();

            // Analyze feature completeness
            foreach (var feature in allFeatures)
            {
                var missingCount = data.Count(r => !r.Features.ContainsKey(feature) ||
                                                  r.Features[feature] == null ||
                                                  string.IsNullOrEmpty(r.Features[feature]?.ToString()));

                metrics.MissingValuesByFeature[feature] = missingCount;

                if (missingCount > 0)
                {
                    var missingPercentage = (double)missingCount / data.Count * 100;
                    if (missingPercentage > 50)
                    {
                        metrics.QualityIssues.Add($"Feature '{feature}' has {missingPercentage:F1}% missing values");
                    }
                }
            }

            // Analyze label completeness
            foreach (var label in allLabels)
            {
                var missingCount = data.Count(r => !r.Labels.ContainsKey(label) ||
                                                  r.Labels[label] == null);

                if (missingCount > 0)
                {
                    var missingPercentage = (double)missingCount / data.Count * 100;
                    if (missingPercentage > 10)
                    {
                        metrics.QualityIssues.Add($"Label '{label}' has {missingPercentage:F1}% missing values");
                    }
                }
            }

            // Count incomplete records
            metrics.IncompleteRecords = data.Count(r =>
                r.Features.Any(f => f.Value == null || string.IsNullOrEmpty(f.Value?.ToString())) ||
                r.Labels.Any(l => l.Value == null));

            await Task.CompletedTask;
        }

        private async Task AnalyzeDataTypesAsync(
            List<MLTrainingRecord> data,
            DataQualityMetrics metrics,
            CancellationToken cancellationToken)
        {
            var allFeatures = data.SelectMany(r => r.Features.Keys).Distinct().ToList();

            foreach (var feature in allFeatures)
            {
                var values = data.Where(r => r.Features.ContainsKey(feature) && r.Features[feature] != null)
                                .Select(r => r.Features[feature])
                                .ToList();

                if (values.Any())
                {

                    var dataType = DetermineDataType(values);

                    metrics.DataTypesByFeature[feature] = dataType;

                    // Check for type consistency

                    var inconsistentTypes = values.Where(v => !IsConsistentType(v, dataType)).ToList();

                    if (inconsistentTypes.Any())
                    {
                        var percentage = (double)inconsistentTypes.Count / values.Count * 100;
                        if (percentage > 5)
                        {
                            metrics.QualityIssues.Add($"Feature '{feature}' has {percentage:F1}% inconsistent data types");
                        }
                    }
                }
            }

            await Task.CompletedTask;
        }

        private async Task AnalyzeValueDistributionsAsync(
            List<MLTrainingRecord> data,
            DataQualityMetrics metrics,
            CancellationToken cancellationToken)
        {
            var allFeatures = data.SelectMany(r => r.Features.Keys).Distinct().ToList();

            foreach (var feature in allFeatures)
            {
                var values = data.Where(r => r.Features.ContainsKey(feature) && r.Features[feature] != null)
                                .Select(r => r.Features[feature])
                                .ToList();

                if (values.Any())
                {
                    var uniqueCount = values.Distinct().Count();
                    metrics.UniqueValuesByFeature[feature] = uniqueCount;

                    // Check for low cardinality (potential issues)
                    var cardinalityRatio = (double)uniqueCount / values.Count;
                    if (cardinalityRatio < 0.01 && values.Count > 100)
                    {
                        metrics.QualityIssues.Add($"Feature '{feature}' has very low cardinality ({cardinalityRatio:P1})");
                    }

                    // Check for high cardinality (potential issues)
                    if (cardinalityRatio > 0.95 && values.Count > 100)
                    {
                        metrics.QualityIssues.Add($"Feature '{feature}' has very high cardinality ({cardinalityRatio:P1})");
                    }
                }
            }

            await Task.CompletedTask;
        }

        private async Task DetectAnomaliesAsync(
            List<MLTrainingRecord> data,
            DataQualityMetrics metrics,
            CancellationToken cancellationToken)
        {
            // Detect duplicate records
            var duplicates = data.GroupBy(r => new
            {
                r.Timestamp,
                r.Features.ContainsKey("userId") ? r.Features["userId"] : "",
                r.Features.ContainsKey("ipAddress") ? r.Features["ipAddress"] : ""
            })
            .Where(g => g.Count() > 1)
            .ToList();

            if (duplicates.Any())
            {
                var duplicateCount = duplicates.Sum(g => g.Count() - 1);
                var duplicatePercentage = (double)duplicateCount / data.Count * 100;
                if (duplicatePercentage > 5)
                {
                    metrics.QualityIssues.Add($"Dataset contains {duplicatePercentage:F1}% duplicate records");
                }
            }

            // Detect timestamp anomalies
            var timestampAnomalies = data.Where(r =>
                r.Timestamp < DateTime.UtcNow.AddYears(-10) ||
                r.Timestamp > DateTime.UtcNow.AddDays(1)).ToList();

            if (timestampAnomalies.Any())
            {
                metrics.QualityIssues.Add($"Dataset contains {timestampAnomalies.Count} records with suspicious timestamps");
            }

            // Detect feature value anomalies

            await DetectFeatureAnomaliesAsync(data, metrics, cancellationToken);


            await Task.CompletedTask;
        }

        private async Task DetectFeatureAnomaliesAsync(
            List<MLTrainingRecord> data,
            DataQualityMetrics metrics,
            CancellationToken cancellationToken)
        {
            // Check for suspicious IP addresses

            var suspiciousIPs = data.Where(r =>
                r.Features.ContainsKey("ipAddress") &&
                r.Features["ipAddress"] != null &&
                IsSuspiciousIP(r.Features["ipAddress"].ToString())).ToList();


            if (suspiciousIPs.Any())
            {
                var percentage = (double)suspiciousIPs.Count / data.Count * 100;
                if (percentage > 20)
                {
                    metrics.QualityIssues.Add($"Dataset contains {percentage:F1}% records with suspicious IP addresses");
                }
            }

            // Check for empty or null values in critical fields
            var criticalFields = new[] { "userId", "timestamp", "dataSource" };
            foreach (var field in criticalFields)
            {
                var emptyValues = data.Where(r =>
                    !r.Features.ContainsKey(field) ||
                    r.Features[field] == null ||
                    string.IsNullOrEmpty(r.Features[field]?.ToString())).ToList();

                if (emptyValues.Any())
                {
                    var percentage = (double)emptyValues.Count / data.Count * 100;
                    metrics.QualityIssues.Add($"Critical field '{field}' has {percentage:F1}% empty values");
                }
            }

            await Task.CompletedTask;
        }

        private async Task GenerateQualityRecommendationsAsync(
            DataQualityMetrics metrics,
            CancellationToken cancellationToken)
        {
            var recommendations = new List<string>();

            // Completeness recommendations
            if (metrics.CompletenessScore < 0.8)
            {
                recommendations.Add("Consider data imputation techniques for missing values");
                recommendations.Add("Review data collection processes to reduce missing data");
            }

            // Feature recommendations
            var highMissingFeatures = metrics.MissingValuesByFeature
                .Where(kvp => (double)kvp.Value / metrics.TotalRecords > 0.5)
                .Select(kvp => kvp.Key);

            foreach (var feature in highMissingFeatures)
            {
                recommendations.Add($"Consider removing feature '{feature}' due to high missing value rate");
            }

            // Data type recommendations
            var inconsistentFeatures = metrics.DataTypesByFeature
                .Where(kvp => kvp.Value.ToString().Contains("inconsistent"))
                .Select(kvp => kvp.Key);

            foreach (var feature in inconsistentFeatures)
            {
                recommendations.Add($"Standardize data types for feature '{feature}'");
            }

            // Add recommendations to quality issues
            if (recommendations.Any())
            {
                metrics.QualityIssues.Add("--- RECOMMENDATIONS ---");
                metrics.QualityIssues.AddRange(recommendations);
            }

            await Task.CompletedTask;
        }

        private double CalculateCompletenessScore(DataQualityMetrics metrics)
        {
            if (metrics.TotalRecords == 0) return 0.0;

            var completeRecords = metrics.TotalRecords - metrics.IncompleteRecords;
            return (double)completeRecords / metrics.TotalRecords;
        }

        private string DetermineDataType(List<object> values)
        {
            if (!values.Any()) return "unknown";

            var types = values.Select(v => v?.GetType()).Where(t => t != null).Distinct().ToList();

            if (types.Count == 1)
            {
                var type = types.First();
                if (type == typeof(string)) return "string";
                if (type == typeof(int) || type == typeof(long)) return "integer";
                if (type == typeof(double) || type == typeof(decimal)) return "decimal";
                if (type == typeof(bool)) return "boolean";
                if (type == typeof(DateTime)) return "datetime";
                return type.Name.ToLower();
            }

            return "mixed";
        }

        private bool IsConsistentType(object value, string expectedType)
        {
            if (value == null) return false;

            return expectedType.ToLower() switch
            {
                "string" => value is string,
                "integer" => value is int or long,
                "decimal" => value is double or decimal or float,
                "boolean" => value is bool,
                "datetime" => value is DateTime,
                _ => true // Unknown types are considered consistent
            };
        }

        private bool IsSuspiciousIP(string? ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress)) return false;

            // Check for private IP ranges
            var privateRanges = new[]
            {
                "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
            };

            return privateRanges.Any(range => ipAddress.StartsWith(range, StringComparison.OrdinalIgnoreCase));
        }


        public Dictionary<string, object> GenerateQualityReport(DataQualityMetrics metrics)

        {

            var report = new Dictionary<string, object>
            {
                ["Summary"] = new
                {
                    TotalRecords = metrics.TotalRecords,
                    CompleteRecords = metrics.CompleteRecords,
                    IncompleteRecords = metrics.IncompleteRecords,
                    CompletenessScore = $"{metrics.CompletenessScore:P1}",
                    QualityGrade = GetQualityGrade(metrics.CompletenessScore)
                },
                ["MissingValues"] = metrics.MissingValuesByFeature,
                ["UniqueValues"] = metrics.UniqueValuesByFeature,
                ["DataTypes"] = metrics.DataTypesByFeature,
                ["Issues"] = metrics.QualityIssues,
                ["Recommendations"] = GenerateRecommendations(metrics)
            };


            return report;
        }

        private string GetQualityGrade(double completenessScore)
        {
            return completenessScore switch
            {
                >= 0.95 => "A+",
                >= 0.90 => "A",
                >= 0.85 => "A-",
                >= 0.80 => "B+",
                >= 0.75 => "B",
                >= 0.70 => "B-",
                >= 0.65 => "C+",
                >= 0.60 => "C",
                >= 0.55 => "C-",
                >= 0.50 => "D",
                _ => "F"
            };
        }

        private List<string> GenerateRecommendations(DataQualityMetrics metrics)
        {
            var recommendations = new List<string>();

            if (metrics.CompletenessScore < 0.8)
            {
                recommendations.Add("Data completeness is below recommended threshold (80%)");
                recommendations.Add("Implement data validation at collection point");
                recommendations.Add("Consider data imputation for missing values");
            }

            var highMissingFeatures = metrics.MissingValuesByFeature
                .Where(kvp => (double)kvp.Value / metrics.TotalRecords > 0.3)
                .Select(kvp => kvp.Key);

            foreach (var feature in highMissingFeatures)
            {
                recommendations.Add($"Feature '{feature}' has >30% missing values - review collection process");
            }

            if (metrics.QualityIssues.Count > 10)
            {
                recommendations.Add("High number of quality issues detected - comprehensive data cleaning recommended");
            }

            return recommendations;
        }
    }
}
