using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.ExtractorSuite.Cmdlets.MLPipeline;

namespace Microsoft.ExtractorSuite.Core.MLPipeline
{
#pragma warning disable SA1600
    public class MLDataProcessor
#pragma warning restore SA1600
    {
#pragma warning disable SA1309
        private readonly Random _random;
#pragma warning disable SA1600
#pragma warning restore SA1309

        public MLDataProcessor(int? seed = null)
        {
#pragma warning disable SA1101
            _random = seed.HasValue ? new Random(seed.Value) : new Random();
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public DataSetSplit SplitDataSets(
            List<MLTrainingRecord> data,
            double trainingPercentage,
            double validationPercentage)
        {
            if (data == null || !data.Any())
                return new DataSetSplit();

            // Validate percentages
            if (trainingPercentage + validationPercentage > 1.0)
                throw new ArgumentException("Training and validation percentages cannot exceed 100%");

            // Shuffle data for random split
#pragma warning disable SA1101
            var shuffledData = data.OrderBy(x => _random.Next()).ToList();
#pragma warning restore SA1101

            var totalCount = shuffledData.Count;
            var trainingCount = (int)(totalCount * trainingPercentage);
            var validationCount = (int)(totalCount * validationPercentage);
            var testCount = totalCount - trainingCount - validationCount;

            return new DataSetSplit
            {
                Training = shuffledData.Take(trainingCount).ToList(),
                Validation = shuffledData.Skip(trainingCount).Take(validationCount).ToList(),
                Test = shuffledData.Skip(trainingCount + validationCount).Take(testCount).ToList()
            };
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public DataSetSplit SplitDataSetsByTime(
            List<MLTrainingRecord> data,
            double trainingPercentage,
            double validationPercentage)
        {
            if (data == null || !data.Any())
                return new DataSetSplit();

            // Sort by timestamp for time-based split
            var sortedData = data.OrderBy(x => x.Timestamp).ToList();

            var totalCount = sortedData.Count;
            var trainingCount = (int)(totalCount * trainingPercentage);
            var validationCount = (int)(totalCount * validationPercentage);

            return new DataSetSplit
            {
                Training = sortedData.Take(trainingCount).ToList(),
                Validation = sortedData.Skip(trainingCount).Take(validationCount).ToList(),
                Test = sortedData.Skip(trainingCount + validationCount).ToList()
            };
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public DataSetSplit SplitDataSetsStratified(
            List<MLTrainingRecord> data,
            double trainingPercentage,
            double validationPercentage,
            string labelKey = "riskLevel")
        {
            if (data == null || !data.Any())
                return new DataSetSplit();

            // Group by label for stratified sampling
#pragma warning disable SA1101
            var groupedData = data.GroupBy(x => GetLabelValue(x, labelKey)).ToList();
#pragma warning restore SA1101
            var result = new DataSetSplit();

            foreach (var group in groupedData)
            {
                var groupData = group.ToList();
                var groupTrainingCount = (int)(groupData.Count * trainingPercentage);
                var groupValidationCount = (int)(groupData.Count * validationPercentage);

                result.Training.AddRange(groupData.Take(groupTrainingCount));
                result.Validation.AddRange(groupData.Skip(groupTrainingCount).Take(groupValidationCount));
                result.Test.AddRange(groupData.Skip(groupTrainingCount + groupValidationCount));
            }

            // Shuffle each set to avoid bias
#pragma warning disable SA1101
            result.Training = result.Training.OrderBy(x => _random.Next()).ToList();
#pragma warning restore SA1101
#pragma warning disable SA1101
            result.Validation = result.Validation.OrderBy(x => _random.Next()).ToList();
#pragma warning restore SA1101
#pragma warning disable SA1101
            result.Test = result.Test.OrderBy(x => _random.Next()).ToList();
#pragma warning restore SA1101

            return result;
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public List<MLTrainingRecord> BalanceDataset(
            List<MLTrainingRecord> data,
            string labelKey = "isRisky",
            int? maxRecordsPerClass = null)
        {
            if (data == null || !data.Any())
                return new List<MLTrainingRecord>();

#pragma warning disable SA1101
            var groupedData = data.GroupBy(x => GetLabelValue(x, labelKey)).ToList();
#pragma warning restore SA1101

            if (groupedData.Count < 2)
                return data;

            // Find the minority class size
            var minClassSize = groupedData.Min(g => g.Count());
            var targetSize = maxRecordsPerClass ?? minClassSize;

            var balancedData = new List<MLTrainingRecord>();

            foreach (var group in groupedData)
            {
                var groupData = group.ToList();
                if (groupData.Count > targetSize)
                {
                    // Downsample majority class
#pragma warning disable SA1101
                    balancedData.AddRange(groupData.OrderBy(x => _random.Next()).Take(targetSize));
#pragma warning restore SA1101
                }
                else
                {
                    // Keep minority class as is
                    balancedData.AddRange(groupData);
                }
            }

#pragma warning disable SA1101
            return balancedData.OrderBy(x => _random.Next()).ToList();
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public List<MLTrainingRecord> AugmentDataset(
            List<MLTrainingRecord> data,
            double augmentationRatio = 0.5,
            string labelKey = "isRisky")
        {
            if (data == null || !data.Any())
                return new List<MLTrainingRecord>();

            var augmentedData = new List<MLTrainingRecord>(data);
#pragma warning disable SA1101
            var minorityClass = data.GroupBy(x => GetLabelValue(x, labelKey))
                                   .OrderBy(g => g.Count())
                                   .First();
#pragma warning restore SA1101

            var augmentationCount = (int)(minorityClass.Count() * augmentationRatio);
            var minorityData = minorityClass.ToList();

            for (int i = 0; i < augmentationCount; i++)
            {
#pragma warning disable SA1101
                var originalRecord = minorityData[_random.Next(minorityData.Count)];
#pragma warning restore SA1101
#pragma warning disable SA1101
                var augmentedRecord = CreateAugmentedRecord(originalRecord);
#pragma warning restore SA1101
                augmentedData.Add(augmentedRecord);
            }

#pragma warning disable SA1101
            return augmentedData.OrderBy(x => _random.Next()).ToList();
#pragma warning restore SA1101
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public Dictionary<string, object> ExtractFeatures(MLTrainingRecord record)
        {
            var features = new Dictionary<string, object>();

            // Extract basic features
            features["timestamp"] = record.Timestamp;
            features["dataSource"] = record.DataSource;
            features["recordType"] = record.RecordType;

            // Extract features from the Features dictionary
            foreach (var feature in record.Features)
            {
                features[feature.Key] = feature.Value;
            }

            // Extract derived features
            features["hourOfDay"] = record.Timestamp.Hour;
            features["dayOfWeek"] = (int)record.Timestamp.DayOfWeek;
            features["isWeekend"] = record.Timestamp.DayOfWeek == DayOfWeek.Saturday ||
                                   record.Timestamp.DayOfWeek == DayOfWeek.Sunday;
            features["isBusinessHours"] = record.Timestamp.Hour >= 8 && record.Timestamp.Hour <= 18;

            return features;
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public Dictionary<string, object> ExtractLabels(MLTrainingRecord record)
        {
            var labels = new Dictionary<string, object>();

            // Extract labels from the Labels dictionary
            foreach (var label in record.Labels)
            {
                labels[label.Key] = label.Value;
            }

            // Extract derived labels
            if (record.Labels.ContainsKey("riskLevel"))
            {
                var riskLevel = record.Labels["riskLevel"]?.ToString() ?? "none";
                labels["isHighRisk"] = riskLevel.Equals("high", StringComparison.OrdinalIgnoreCase);
                labels["isMediumRisk"] = riskLevel.Equals("medium", StringComparison.OrdinalIgnoreCase);
                labels["isLowRisk"] = riskLevel.Equals("low", StringComparison.OrdinalIgnoreCase);
            }

            return labels;
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public List<MLTrainingRecord> FilterRecords(
            List<MLTrainingRecord> data,
            Func<MLTrainingRecord, bool> predicate)
        {
            return data?.Where(predicate).ToList() ?? new List<MLTrainingRecord>();
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public List<MLTrainingRecord> SampleRecords(
            List<MLTrainingRecord> data,
            int sampleSize,
            bool withReplacement = false)
        {
            if (data == null || !data.Any() || sampleSize <= 0)
                return new List<MLTrainingRecord>();

            if (sampleSize >= data.Count)
                return withReplacement ? data : data.ToList();

            if (withReplacement)
            {
                var sampled = new List<MLTrainingRecord>();
                for (int i = 0; i < sampleSize; i++)
                {
#pragma warning disable SA1101
                    sampled.Add(data[_random.Next(data.Count)]);
#pragma warning restore SA1101
                }
                return sampled;
            }
            else
            {
#pragma warning disable SA1101
                return data.OrderBy(x => _random.Next()).Take(sampleSize).ToList();
#pragma warning restore SA1101
            }
#pragma warning disable SA1600
        }
#pragma warning restore SA1600

        public Dictionary<string, object> GenerateFeatureStatistics(List<MLTrainingRecord> data)
        {
            if (data == null || !data.Any())
                return new Dictionary<string, object>();

            var stats = new Dictionary<string, object>();
            var allFeatures = data.SelectMany(r => r.Features.Keys).Distinct().ToList();

            foreach (var feature in allFeatures)
            {
                var values = data.Select(r => r.Features.ContainsKey(feature) ? r.Features[feature] : null)
                                .Where(v => v != null)
                                .ToList();

                if (values.Any())
                {
                    stats[feature] = new
                    {
                        Count = values.Count,
                        UniqueCount = values.Distinct().Count(),
                        NullCount = data.Count(r => !r.Features.ContainsKey(feature) || r.Features[feature] == null),
                        SampleValues = values.Take(5).ToList()
                    };
                }
            }

            return stats;
        }

        private object GetLabelValue(MLTrainingRecord record, string labelKey)
        {
            return record.Labels.ContainsKey(labelKey) ? record.Labels[labelKey] : "unknown";
        }

        private MLTrainingRecord CreateAugmentedRecord(MLTrainingRecord original)
        {
#pragma warning disable SA1101
            var augmented = new MLTrainingRecord
            {
                Id = Guid.NewGuid().ToString(),
                Timestamp = original.Timestamp.AddMinutes(_random.Next(-30, 31)), // ±30 minutes
                DataSource = original.DataSource,
                RecordType = original.RecordType,
                Features = new Dictionary<string, object>(original.Features),
                Labels = new Dictionary<string, object>(original.Labels)
            };
#pragma warning restore SA1101

            // Add some noise to numeric features
            foreach (var feature in augmented.Features)
            {
                if (feature.Value is int intValue)
                {
#pragma warning disable SA1101
                    augmented.Features[feature.Key] = intValue + _random.Next(-2, 3); // ±2
#pragma warning restore SA1101
                }
                else if (feature.Value is double doubleValue)
                {
#pragma warning disable SA1101
                    augmented.Features[feature.Key] = doubleValue + (_random.NextDouble() - 0.5) * 0.1; // ±0.05
#pragma warning restore SA1101
                }
            }

            return augmented;
        }
    }
}
