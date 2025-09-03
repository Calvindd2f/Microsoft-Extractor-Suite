using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Cmdlets.MLPipeline;

namespace Microsoft.ExtractorSuite.Core.MLPipeline
{
    public class RiskSimulator
    {
        private Random _random;
        private readonly Dictionary<string, string[]> _riskPatterns;
        
        // Static readonly IP ranges for performance
        private static readonly string[] TorRanges = {
            "185.220.101.", "185.220.102.", "185.220.103.", "185.220.104.",
            "185.220.105.", "185.220.106.", "185.220.107.", "185.220.108.",
            "51.15.13.", "51.15.14.", "51.15.15.", "51.15.16.",
            "176.10.99.", "176.10.100.", "176.10.101.", "176.10.102."
        };
        
        private static readonly string[] InternationalRanges = {
            "203.208.60.", "203.208.61.", "203.208.62.", "203.208.63.",
            "8.8.8.", "8.8.9.", "8.8.10.", "8.8.11.",
            "1.1.1.", "1.1.2.", "1.1.3.", "1.1.4."
        };
        
        private static readonly string[] SuspiciousRanges = {
            "45.142.212.", "45.142.213.", "45.142.214.", "45.142.215.",
            "91.219.236.", "91.219.237.", "91.219.238.", "91.219.239.",
            "194.147.78.", "194.147.79.", "194.147.80.", "194.147.81."
        };
        
        private static readonly string[] NormalRanges = {
            "73.158.64.", "73.158.65.", "73.158.66.", "73.158.67.",
            "98.207.254.", "98.207.255.", "98.208.0.", "98.208.1.",
            "24.21.45.", "24.21.46.", "24.21.47.", "24.21.48."
        };


        public RiskSimulator(int? seed = null)
        {
            _random = seed.HasValue ? new Random(seed.Value) : new Random();
            _riskPatterns = InitializeRiskPatterns();
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

            var riskTypes = new[] { "AnonymousIP", "UnfamiliarSignIn", "AtypicalTravel", "LeakedCredentials", "ImpossibleTravel" };
            var recordsPerType = recordCount / riskTypes.Length;

            foreach (var riskType in riskTypes)
            {
                if (cancellationToken.IsCancellationRequested) break;

                var typeRecords = GenerateRiskTypeRecords(
                    riskType, recordsPerType, startDate, endDate, cancellationToken);
                records.AddRange(typeRecords);
            }

            var remainingRecords = recordCount - records.Count;
            if (remainingRecords > 0)
            {
                var normalRecords = GenerateNormalBehaviorRecords(
                    remainingRecords, startDate, endDate, cancellationToken);
                records.AddRange(normalRecords);
            }

            return records.OrderBy(x => x.Timestamp).ToList();
        }

        private List<MLTrainingRecord> GenerateRiskTypeRecords(
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
                var record = GenerateRiskRecord(riskType, startDate, endDate);
                records.Add(record);
            }

            return records;
        }

        private MLTrainingRecord GenerateRiskRecord(
            string riskType,
            DateTime startDate,
            DateTime endDate)
        {
            var timestamp = GenerateRandomTimestamp(startDate, endDate);
            var userId = GenerateRandomUserId();
            var ipAddress = GenerateIPAddressForRiskType(riskType);
            var location = GenerateLocationForRiskType(riskType);

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

            var labels = GenerateLabelsForRiskType(riskType);

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

        private List<MLTrainingRecord> GenerateNormalBehaviorRecords(
            int count,
            DateTime startDate,
            DateTime endDate,
            CancellationToken cancellationToken)
        {
            var records = new List<MLTrainingRecord>();

            for (int i = 0; i < count; i++)
            {
                if (cancellationToken.IsCancellationRequested) break;
                var record = GenerateNormalRecord(startDate, endDate);
                records.Add(record);
            }

            return records;
        }

        private MLTrainingRecord GenerateNormalRecord(DateTime startDate, DateTime endDate)
        {
            var timestamp = GenerateRandomTimestamp(startDate, endDate);
            var userId = GenerateRandomUserId();
            var ipAddress = GenerateNormalIPAddress();
            var location = GenerateNormalLocation();

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
            var riskTypeLower = riskType.ToLower();

            switch (riskTypeLower)
            {
                case "anonymousip":
                    labels["riskLevel"] = "medium";
                    labels["isRisky"] = true;
                    labels["conditionalAccessBlocked"] = _random.Next(100) < 70;
                    labels["riskType"] = "AnonymousIP";
                    break;

                case "unfamiliarsignin":
                    labels["riskLevel"] = "medium";
                    labels["isRisky"] = true;
                    labels["conditionalAccessBlocked"] = _random.Next(100) < 60;
                    labels["riskType"] = "UnfamiliarSignIn";
                    break;

                case "atypicaltravel":
                    labels["riskLevel"] = "high";
                    labels["isRisky"] = true;
                    labels["conditionalAccessBlocked"] = _random.Next(100) < 80;
                    labels["riskType"] = "AtypicalTravel";
                    break;

                case "leakedcredentials":
                    labels["riskLevel"] = "high";
                    labels["isRisky"] = true;
                    labels["conditionalAccessBlocked"] = _random.Next(100) < 90;
                    labels["riskType"] = "LeakedCredentials";
                    break;

                case "impossibletravel":
                    labels["riskLevel"] = "high";
                    labels["isRisky"] = true;
                    labels["conditionalAccessBlocked"] = _random.Next(100) < 85;
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
                    return TorRanges[_random.Next(TorRanges.Length)] + _random.Next(1, 255);

                case "unfamiliarsignin":
                case "atypicaltravel":
                    return InternationalRanges[_random.Next(InternationalRanges.Length)] + _random.Next(1, 255);

                case "leakedcredentials":
                case "impossibletravel":
                    return SuspiciousRanges[_random.Next(SuspiciousRanges.Length)] + _random.Next(1, 255);

                default:
                    return GenerateNormalIPAddress();
            }
        }


        private static readonly (string city, string country)[] TorLocations = {
            ("Amsterdam", "Netherlands"), ("Frankfurt", "Germany"), ("London", "United Kingdom"),
            ("Paris", "France"), ("Stockholm", "Sweden"), ("Zurich", "Switzerland")
        };
        
        private static readonly (string city, string country)[] InternationalLocations = {
            ("Tokyo", "Japan"), ("Sydney", "Australia"), ("São Paulo", "Brazil"),
            ("Mumbai", "India"), ("Cairo", "Egypt"), ("Johannesburg", "South Africa")
        };
        
        private static readonly (string city, string country)[] SuspiciousLocations = {
            ("Moscow", "Russia"), ("Pyongyang", "North Korea"), ("Tehran", "Iran"),
            ("Damascus", "Syria"), ("Caracas", "Venezuela"), ("Havana", "Cuba")
        };

        private (string city, string country) GenerateLocationForRiskType(string riskType)
        {
            switch (riskType.ToLower())
            {
                case "anonymousip":
                    return TorLocations[_random.Next(TorLocations.Length)];
                case "unfamiliarsignin":
                case "atypicaltravel":
                    return InternationalLocations[_random.Next(InternationalLocations.Length)];
                case "leakedcredentials":
                case "impossibletravel":
                    return SuspiciousLocations[_random.Next(SuspiciousLocations.Length)];
                default:
                    return GenerateNormalLocation();
            }
        }

        private string GenerateNormalIPAddress()
        {
            return NormalRanges[_random.Next(NormalRanges.Length)] + _random.Next(1, 255);
        }

        private static readonly (string city, string country)[] NormalLocations = {
            ("New York", "United States"), ("Los Angeles", "United States"), ("Chicago", "United States"),
            ("Houston", "United States"), ("Phoenix", "United States"), ("Philadelphia", "United States"),
            ("San Antonio", "United States"), ("San Diego", "United States"), ("Dallas", "United States"),
            ("San Jose", "United States")
        };

        private (string city, string country) GenerateNormalLocation()
        {
            return NormalLocations[_random.Next(NormalLocations.Length)];
        }

        private DateTime GenerateRandomTimestamp(DateTime startDate, DateTime endDate)
        {
            var timeSpan = endDate - startDate;
            var randomDays = _random.Next(timeSpan.Days);
            var randomHours = _random.Next(24);
            var randomMinutes = _random.Next(60);
            var randomSeconds = _random.Next(60);

            return startDate.AddDays(randomDays)
                           .AddHours(randomHours)
                           .AddMinutes(randomMinutes)
                           .AddSeconds(randomSeconds);
        }

        private static readonly string[] Prefixes = { "john", "jane", "mike", "sarah", "david", "lisa", "robert", "emily" };
        private static readonly string[] Suffixes = { "smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis" };

        private string GenerateRandomUserId()
        {
            var prefix = Prefixes[_random.Next(Prefixes.Length)];
            var suffix = Suffixes[_random.Next(Suffixes.Length)];
            var number = _random.Next(1000, 9999);
            return $"{prefix}.{suffix}{number}";
        }

        private string GenerateRandomAppId()
        {
            return Guid.NewGuid().ToString();
        }

        private static readonly string[] AppNames = {
            "Microsoft Office", "Outlook", "Teams", "SharePoint", "OneDrive",
            "Power BI", "Azure Portal", "Visual Studio", "GitHub", "Slack"
        };

        private string GenerateRandomAppName()
        {
            return AppNames[_random.Next(AppNames.Length)];
        }

        private static readonly string[] ClientApps = {
            "Browser", "Mobile Apps and desktop clients", "Exchange ActiveSync",
            "IMAP", "POP3", "SMTP", "Authenticated SMTP", "Reporting Web Services"
        };

        private string GenerateRandomClientApp()
        {
            return ClientApps[_random.Next(ClientApps.Length)];
        }

        private string GenerateRandomDeviceId()
        {
            return Guid.NewGuid().ToString();
        }

        private static readonly string[] OperatingSystems = {
            "Windows 10", "Windows 11", "macOS", "iOS", "Android", "Linux"
        };

        private string GenerateRandomOS()
        {
            return OperatingSystems[_random.Next(OperatingSystems.Length)];
        }

        private static readonly string[] Browsers = {
            "Chrome", "Edge", "Firefox", "Safari", "Internet Explorer"
        };

        private string GenerateRandomBrowser()
        {
            return Browsers[_random.Next(Browsers.Length)];
        }

        private Dictionary<string, string[]> InitializeRiskPatterns()
        {
            return new Dictionary<string, string[]>
            {
                ["AnonymousIP"] = new[] { "Tor exit nodes", "VPN services", "Proxy servers", "Anonymous networks" },
                ["UnfamiliarSignIn"] = new[] { "New locations", "New devices", "Unusual time patterns", "New applications" },
                ["AtypicalTravel"] = new[] { "Impossible travel times", "Unusual travel patterns", "Geographic anomalies" },
                ["LeakedCredentials"] = new[] { "Dark web exposure", "GitHub leaks", "Pastebin dumps", "Breach databases" },
                ["ImpossibleTravel"] = new[] { "Multiple countries in short time", "Unrealistic travel speeds", "Geographic contradictions" }
            };
        }

        public List<string> GetAvailableRiskTypes()
        {
            return _riskPatterns.Keys.ToList();
        }

        public string[] GetRiskPatterns(string riskType)
        {
            return _riskPatterns.TryGetValue(riskType, out var patterns) ? patterns : Array.Empty<string>();
        }

        public Dictionary<string, object> GetRiskTypeStatistics()
        {
            var stats = new Dictionary<string, object>();
            
            foreach (var riskType in _riskPatterns.Keys)
            {
                stats[riskType] = new
                {
                    Patterns = _riskPatterns[riskType],
                    PatternCount = _riskPatterns[riskType].Length,
                    Description = GetRiskTypeDescription(riskType)
                };
            }
            
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
