using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Cmdlets.MLPipeline;

namespace Microsoft.ExtractorSuite.Core.MLPipeline
{
#pragma warning disable SA1600
    public class RiskSimulator
#pragma warning restore SA1600
    {
#pragma warning disable SA1309
        private readonly Random _random;
#pragma warning restore SA1309
#pragma warning disable SA1600
#pragma warning disable SA1309
#pragma warning restore SA1600
        private readonly Dictionary<string, string[]> _riskPatterns;
#pragma warning restore SA1309

        public RiskSimulator(int? seed = null)
        {
#pragma warning disable SA1600
#pragma warning disable SA1101
            _random = seed.HasValue ? new Random(seed.Value) : new Random();
#pragma warning restore SA1101
#pragma warning disable SA1101
            _riskPatterns = InitializeRiskPatterns();
#pragma warning restore SA1101
        }

        public async Task<List<MLTrainingRecord>> GenerateSyntheticRiskDataAsync(
            int seed,
            int recordCount,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken)
        {
            _random = new Random(seed);
            var records = new List<MLTrainingRecord>();

            // Generate different types of risk scenarios
            var riskTypes = new[] { "AnonymousIP", "UnfamiliarSignIn", "AtypicalTravel", "LeakedCredentials", "ImpossibleTravel" };
            var recordsPerType = recordCount / riskTypes.Length;

            foreach (var riskType in riskTypes)
            {
                if (cancellationToken.IsCancellationRequested) break;

#pragma warning disable SA1101
                var typeRecords = await GenerateRiskTypeRecordsAsync(
                    riskType, recordsPerType, startDate, endDate, cancellationToken);
#pragma warning restore SA1101
                records.AddRange(typeRecords);
            }

            // Fill remaining records with normal behavior
            var remainingRecords = recordCount - records.Count;
            if (remainingRecords > 0)
            {
#pragma warning disable SA1101
                var normalRecords = await GenerateNormalBehaviorRecordsAsync(
                    remainingRecords, startDate, endDate, cancellationToken);
#pragma warning restore SA1101
                records.AddRange(normalRecords);
            }

            return records.OrderBy(x => x.Timestamp).ToList();
        }

        private async Task<List<MLTrainingRecord>> GenerateRiskTypeRecordsAsync(
            string riskType,
            int count,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken)
        {
            var records = new List<MLTrainingRecord>();

            for (int i = 0; i < count; i++)
            {
                if (cancellationToken.IsCancellationRequested) break;

#pragma warning disable SA1101
                var record = await GenerateRiskRecordAsync(riskType, startDate, endDate);
#pragma warning restore SA1101
                records.Add(record);
            }

            return records;
        }

        private async Task<MLTrainingRecord> GenerateRiskRecordAsync(
            string riskType,
            DateTime startDate,
            DateTime endDate)
        {
#pragma warning disable SA1101
            var timestamp = GenerateRandomTimestamp(startDate, endDate);
#pragma warning restore SA1101
#pragma warning disable SA1101
            var userId = GenerateRandomUserId();
#pragma warning restore SA1101
#pragma warning disable SA1101
            var ipAddress = GenerateIPAddressForRiskType(riskType);
#pragma warning restore SA1101
#pragma warning disable SA1101
            var location = GenerateLocationForRiskType(riskType);
#pragma warning restore SA1101

#pragma warning disable SA1101
            var features = new Dictionary<string, object>
            {
                ["userId"] = userId,
                ["userPrincipalName"] = $"{userId}@contoso.com",
                ["ipAddress"] = ipAddress,
                ["location"] = location.city,
                ["country"] = location.country,
                ["appId"] = GenerateRandomAppId(),
                ["appDisplayName"] = GenerateRandomAppName(),
                ["clientAppUsed"] = GenerateRandomClientApp(),
                ["deviceId"] = GenerateRandomDeviceId(),
                ["operatingSystem"] = GenerateRandomOS(),
                ["browser"] = GenerateRandomBrowser(),
                ["isCompliant"] = "false",
                ["isManaged"] = "false",
                ["trustType"] = "AzureAD"
            };
#pragma warning restore SA1101

#pragma warning disable SA1101
            var labels = GenerateLabelsForRiskType(riskType);
#pragma warning restore SA1101

            return new MLTrainingRecord
            {
                Id = Guid.NewGuid().ToString(),
                Timestamp = timestamp,
                DataSource = "RiskSimulation",
                RecordType = "SignIn",
                Features = features,
                Labels = labels
            };
        }

        private async Task<List<MLTrainingRecord>> GenerateNormalBehaviorRecordsAsync(
            int count,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken)
        {
            var records = new List<MLTrainingRecord>();

            for (int i = 0; i < count; i++)
            {
                if (cancellationToken.IsCancellationRequested) break;

#pragma warning disable SA1101
                var record = await GenerateNormalRecordAsync(startDate, endDate);
#pragma warning restore SA1101
                records.Add(record);
            }

            return records;
        }

        private async Task<MLTrainingRecord> GenerateNormalRecordAsync(DateTime startDate, DateTime endDate)
        {
#pragma warning disable SA1101
            var timestamp = GenerateRandomTimestamp(startDate, endDate);
#pragma warning restore SA1101
#pragma warning disable SA1101
            var userId = GenerateRandomUserId();
#pragma warning restore SA1101
#pragma warning disable SA1101
            var ipAddress = GenerateNormalIPAddress();
#pragma warning restore SA1101
#pragma warning disable SA1101
            var location = GenerateNormalLocation();
#pragma warning restore SA1101

#pragma warning disable SA1101
            var features = new Dictionary<string, object>
            {
                ["userId"] = userId,
                ["userPrincipalName"] = $"{userId}@contoso.com",
                ["ipAddress"] = ipAddress,
                ["location"] = location.city,
                ["country"] = location.country,
                ["appId"] = GenerateRandomAppId(),
                ["appDisplayName"] = GenerateRandomAppName(),
                ["clientAppUsed"] = GenerateRandomClientApp(),
                ["deviceId"] = GenerateRandomDeviceId(),
                ["operatingSystem"] = GenerateRandomOS(),
                ["browser"] = GenerateRandomBrowser(),
                ["isCompliant"] = "true",
                ["isManaged"] = "true",
                ["trustType"] = "AzureAD"
            };
#pragma warning restore SA1101

            var labels = new Dictionary<string, object>
            {
                ["riskLevel"] = "none",
                ["isRisky"] = false,
                ["conditionalAccessBlocked"] = false
            };

            return new MLTrainingRecord
            {
                Id = Guid.NewGuid().ToString(),
                Timestamp = timestamp,
                DataSource = "RiskSimulation",
                RecordType = "SignIn",
                Features = features,
                Labels = labels
            };
        }

        private Dictionary<string, object> GenerateLabelsForRiskType(string riskType)
        {
            var labels = new Dictionary<string, object>();

            switch (riskType.ToLower())
            {
                case "anonymousip":
                    labels["riskLevel"] = "medium";
                    labels["isRisky"] = true;
#pragma warning disable SA1101
                    labels["conditionalAccessBlocked"] = _random.Next(100) < 70; // 70% chance of blocking
#pragma warning restore SA1101
                    labels["riskType"] = "AnonymousIP";
                    break;

                case "unfamiliarsignin":
                    labels["riskLevel"] = "medium";
                    labels["isRisky"] = true;
#pragma warning disable SA1101
                    labels["conditionalAccessBlocked"] = _random.Next(100) < 60; // 60% chance of blocking
#pragma warning restore SA1101
                    labels["riskType"] = "UnfamiliarSignIn";
                    break;

                case "atypicaltravel":
                    labels["riskLevel"] = "high";
                    labels["isRisky"] = true;
#pragma warning disable SA1101
                    labels["conditionalAccessBlocked"] = _random.Next(100) < 80; // 80% chance of blocking
#pragma warning restore SA1101
                    labels["riskType"] = "AtypicalTravel";
                    break;

                case "leakedcredentials":
                    labels["riskLevel"] = "high";
                    labels["isRisky"] = true;
#pragma warning disable SA1101
                    labels["conditionalAccessBlocked"] = _random.Next(100) < 90; // 90% chance of blocking
#pragma warning restore SA1101
                    labels["riskType"] = "LeakedCredentials";
                    break;

                case "impossibletravel":
                    labels["riskLevel"] = "high";
                    labels["isRisky"] = true;
#pragma warning disable SA1101
                    labels["conditionalAccessBlocked"] = _random.Next(100) < 85; // 85% chance of blocking
#pragma warning restore SA1101
                    labels["riskType"] = "ImpossibleTravel";
                    break;

                default:
                    labels["riskLevel"] = "none";
                    labels["isRisky"] = false;
                    labels["conditionalAccessBlocked"] = false;
                    break;
            }

            return labels;
        }

        private string GenerateIPAddressForRiskType(string riskType)
        {
            switch (riskType.ToLower())
            {
                case "anonymousip":
                    // Tor exit nodes and VPN ranges
                    var torRanges = new[]
                    {
                        "185.220.101.", "185.220.102.", "185.220.103.", "185.220.104.",
                        "185.220.105.", "185.220.106.", "185.220.107.", "185.220.108.",
                        "51.15.13.", "51.15.14.", "51.15.15.", "51.15.16.",
                        "176.10.99.", "176.10.100.", "176.10.101.", "176.10.102."
                    };
#pragma warning disable SA1101
                    return torRanges[_random.Next(torRanges.Length)] + _random.Next(1, 255);
#pragma warning restore SA1101

                case "unfamiliarsignin":
                case "atypicaltravel":
                    // Random international IPs
                    var internationalRanges = new[]
                    {
                        "203.208.60.", "203.208.61.", "203.208.62.", "203.208.63.",
                        "8.8.8.", "8.8.9.", "8.8.10.", "8.8.11.",
                        "1.1.1.", "1.1.2.", "1.1.3.", "1.1.4."
                    };
#pragma warning disable SA1101
                    return internationalRanges[_random.Next(internationalRanges.Length)] + _random.Next(1, 255);
#pragma warning restore SA1101

                case "leakedcredentials":
                case "impossibletravel":
                    // Suspicious IP ranges
                    var suspiciousRanges = new[]
                    {
                        "192.168.1.", "192.168.2.", "192.168.3.", "192.168.4.",
                        "10.0.0.", "10.0.1.", "10.0.2.", "10.0.3.",
                        "172.16.0.", "172.16.1.", "172.16.2.", "172.16.3."
                    };
#pragma warning disable SA1101
                    return suspiciousRanges[_random.Next(suspiciousRanges.Length)] + _random.Next(1, 255);
#pragma warning restore SA1101

                default:
#pragma warning disable SA1101
                    return GenerateNormalIPAddress();
#pragma warning restore SA1101
            }
        }

        private (string city, string country) GenerateLocationForRiskType(string riskType)
        {
            switch (riskType.ToLower())
            {
                case "anonymousip":
                    // Tor exit node locations
                    var torLocations = new[]
                    {
                        ("Amsterdam", "Netherlands"),
                        ("Frankfurt", "Germany"),
                        ("London", "United Kingdom"),
                        ("Paris", "France"),
                        ("Stockholm", "Sweden"),
                        ("Zurich", "Switzerland")
                    };
#pragma warning disable SA1101
                    return torLocations[_random.Next(torLocations.Length)];
#pragma warning restore SA1101

                case "unfamiliarsignin":
                case "atypicaltravel":
                    // International locations
                    var internationalLocations = new[]
                    {
                        ("Tokyo", "Japan"),
                        ("Sydney", "Australia"),
                        ("São Paulo", "Brazil"),
                        ("Mumbai", "India"),
                        ("Cairo", "Egypt"),
                        ("Johannesburg", "South Africa")
                    };
#pragma warning disable SA1101
                    return internationalLocations[_random.Next(internationalLocations.Length)];
#pragma warning restore SA1101

                case "leakedcredentials":
                case "impossibletravel":
                    // Suspicious locations
                    var suspiciousLocations = new[]
                    {
                        ("Moscow", "Russia"),
                        ("Pyongyang", "North Korea"),
                        ("Tehran", "Iran"),
                        ("Damascus", "Syria"),
                        ("Caracas", "Venezuela"),
                        ("Havana", "Cuba")
                    };
#pragma warning disable SA1101
                    return suspiciousLocations[_random.Next(suspiciousLocations.Length)];
#pragma warning restore SA1101

                default:
#pragma warning disable SA1101
                    return GenerateNormalLocation();
#pragma warning restore SA1101
            }
        }

        private string GenerateNormalIPAddress()
        {
            // Generate realistic US-based IP addresses
            var usRanges = new[]
            {
                "192.168.1.", "192.168.2.", "192.168.3.", "192.168.4.",
                "10.0.0.", "10.0.1.", "10.0.2.", "10.0.3.",
                "172.16.0.", "172.16.1.", "172.16.2.", "172.16.3."
            };
#pragma warning disable SA1101
            return usRanges[_random.Next(usRanges.Length)] + _random.Next(1, 255);
#pragma warning restore SA1101
        }

        private (string city, string country) GenerateNormalLocation()
        {
            var normalLocations = new[]
            {
                ("New York", "United States"),
                ("Los Angeles", "United States"),
                ("Chicago", "United States"),
                ("Houston", "United States"),
                ("Phoenix", "United States"),
                ("Philadelphia", "United States"),
                ("San Antonio", "United States"),
                ("San Diego", "United States"),
                ("Dallas", "United States"),
                ("San Jose", "United States")
            };
#pragma warning disable SA1101
            return normalLocations[_random.Next(normalLocations.Length)];
#pragma warning restore SA1101
        }

        private DateTime GenerateRandomTimestamp(DateTime startDate, DateTime endDate)
        {
            var timeSpan = endDate - startDate;
#pragma warning disable SA1101
            var randomDays = _random.Next(timeSpan.Days);
#pragma warning restore SA1101
#pragma warning disable SA1101
            var randomHours = _random.Next(24);
#pragma warning restore SA1101
#pragma warning disable SA1101
            var randomMinutes = _random.Next(60);
#pragma warning restore SA1101
#pragma warning disable SA1101
            var randomSeconds = _random.Next(60);
#pragma warning restore SA1101

            return startDate.AddDays(randomDays)
                           .AddHours(randomHours)
                           .AddMinutes(randomMinutes)
                           .AddSeconds(randomSeconds);
        }

        private string GenerateRandomUserId()
        {
            var prefixes = new[] { "john", "jane", "mike", "sarah", "david", "lisa", "robert", "emily" };
            var suffixes = new[] { "smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis" };

#pragma warning disable SA1101
            var prefix = prefixes[_random.Next(prefixes.Length)];
#pragma warning restore SA1101
#pragma warning disable SA1101
            var suffix = suffixes[_random.Next(suffixes.Length)];
#pragma warning restore SA1101
#pragma warning disable SA1101
            var number = _random.Next(1000, 9999);
#pragma warning restore SA1101

            return $"{prefix}.{suffix}{number}";
        }

        private string GenerateRandomAppId()
        {
            return Guid.NewGuid().ToString();
        }

        private string GenerateRandomAppName()
        {
            var appNames = new[]
            {
                "Microsoft Office", "Outlook", "Teams", "SharePoint", "OneDrive",
                "Power BI", "Azure Portal", "Visual Studio", "GitHub", "Slack"
            };
#pragma warning disable SA1101
            return appNames[_random.Next(appNames.Length)];
#pragma warning restore SA1101
        }

        private string GenerateRandomClientApp()
        {
            var clientApps = new[]
            {
                "Browser", "Mobile Apps and desktop clients", "Exchange ActiveSync",
                "IMAP", "POP3", "SMTP", "Authenticated SMTP", "Reporting Web Services"
            };
#pragma warning disable SA1101
            return clientApps[_random.Next(clientApps.Length)];
#pragma warning restore SA1101
        }

        private string GenerateRandomDeviceId()
        {
            return Guid.NewGuid().ToString();
        }

        private string GenerateRandomOS()
        {
            var operatingSystems = new[]
            {
                "Windows 10", "Windows 11", "macOS", "iOS", "Android", "Linux"
            };
#pragma warning disable SA1101
            return operatingSystems[_random.Next(operatingSystems.Length)];
#pragma warning restore SA1101
        }

        private string GenerateRandomBrowser()
        {
            var browsers = new[]
            {
                "Chrome", "Edge", "Firefox", "Safari", "Internet Explorer"
            };
#pragma warning disable SA1101
            return browsers[_random.Next(browsers.Length)];
#pragma warning restore SA1101
        }

        private Dictionary<string, string[]> InitializeRiskPatterns()
        {
            return new Dictionary<string, string[]>
            {
                ["AnonymousIP"] = new[]
                {
                    "Tor exit nodes", "VPN services", "Proxy servers", "Anonymous networks"
                },
                ["UnfamiliarSignIn"] = new[]
                {
                    "New locations", "New devices", "Unusual time patterns", "New applications"
                },
                ["AtypicalTravel"] = new[]
                {
                    "Impossible travel times", "Unusual travel patterns", "Geographic anomalies"
                },
                ["LeakedCredentials"] = new[]
                {
                    "Dark web exposure", "GitHub leaks", "Pastebin dumps", "Breach databases"
                },
                ["ImpossibleTravel"] = new[]
                {
                    "Multiple countries in short time", "Unrealistic travel speeds", "Geographic contradictions"
#pragma warning disable SA1600
                }
#pragma warning restore SA1600
            };
        }

        public List<string> GetAvailableRiskTypes()
#pragma warning disable SA1600
        {
#pragma warning restore SA1600
#pragma warning disable SA1101
            return _riskPatterns.Keys.ToList();
#pragma warning restore SA1101
        }

        public string[] GetRiskPatterns(string riskType)
#pragma warning disable SA1600
        {
#pragma warning restore SA1600
#pragma warning disable SA1101
            return _riskPatterns.ContainsKey(riskType) ? _riskPatterns[riskType] : Array.Empty<string>();
#pragma warning restore SA1101
        }

        public Dictionary<string, object> GetRiskTypeStatistics()
        {
            var stats = new Dictionary<string, object>();

#pragma warning disable SA1101
            foreach (var riskType in _riskPatterns.Keys)
            {
#pragma warning disable SA1101
                stats[riskType] = new
                {
                    Patterns = _riskPatterns[riskType],
                    PatternCount = _riskPatterns[riskType].Length,
                    Description = GetRiskTypeDescription(riskType)
                };
#pragma warning restore SA1101
            }
#pragma warning restore SA1101

            return stats;
        }

        private string GetRiskTypeDescription(string riskType)
        {
            return riskType.ToLower() switch
            {
                "anonymousip" => "Sign-ins from IP addresses associated with anonymous networks like Tor or VPNs",
                "unfamiliarsignin" => "Sign-ins from new locations, devices, or applications not previously used",
                "atypicaltravel" => "Sign-ins that indicate unusual travel patterns or impossible travel times",
                "leakedcredentials" => "Credentials that have been exposed in data breaches or public repositories",
                "impossibletravel" => "Sign-ins from geographically distant locations in impossibly short timeframes",
                _ => "Unknown risk type"
            };
        }
    }
}
