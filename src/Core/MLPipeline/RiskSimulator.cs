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

        private readonly Random _random;




        private readonly Dictionary<string, string[]> _riskPatterns;


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

            // Generate different types of risk scenarios
            var riskTypes = new[] { "AnonymousIP", "UnfamiliarSignIn", "AtypicalTravel", "LeakedCredentials", "ImpossibleTravel" };
            var recordsPerType = recordCount / riskTypes.Length;

            foreach (var riskType in riskTypes)
            {
                if (cancellationToken.IsCancellationRequested) break;


                var typeRecords = await GenerateRiskTypeRecordsAsync(
                    riskType, recordsPerType, startDate, endDate, cancellationToken);

                records.AddRange(typeRecords);
            }

            // Fill remaining records with normal behavior
            var remainingRecords = recordCount - records.Count;
            if (remainingRecords > 0)
            {

                var normalRecords = await GenerateNormalBehaviorRecordsAsync(
                    remainingRecords, startDate, endDate, cancellationToken);

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


                var record = await GenerateRiskRecordAsync(riskType, startDate, endDate);

                records.Add(record);
            }

            return records;
        }

        private async Task<MLTrainingRecord> GenerateRiskRecordAsync(
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


                var record = await GenerateNormalRecordAsync(startDate, endDate);

                records.Add(record);
            }

            return records;
        }

        private async Task<MLTrainingRecord> GenerateNormalRecordAsync(DateTime startDate, DateTime endDate)
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

            switch (riskType.ToLower())
            {
                case "anonymousip":
                    labels["riskLevel"] = "medium";
                    labels["isRisky"] = true;

                    labels["conditionalAccessBlocked"] = _random.Next(100) < 70; // 70% chance of blocking

                    labels["riskType"] = "AnonymousIP";
                    break;

                case "unfamiliarsignin":
                    labels["riskLevel"] = "medium";
                    labels["isRisky"] = true;

                    labels["conditionalAccessBlocked"] = _random.Next(100) < 60; // 60% chance of blocking

                    labels["riskType"] = "UnfamiliarSignIn";
                    break;

                case "atypicaltravel":
                    labels["riskLevel"] = "high";
                    labels["isRisky"] = true;

                    labels["conditionalAccessBlocked"] = _random.Next(100) < 80; // 80% chance of blocking

                    labels["riskType"] = "AtypicalTravel";
                    break;

                case "leakedcredentials":
                    labels["riskLevel"] = "high";
                    labels["isRisky"] = true;

                    labels["conditionalAccessBlocked"] = _random.Next(100) < 90; // 90% chance of blocking

                    labels["riskType"] = "LeakedCredentials";
                    break;

                case "impossibletravel":
                    labels["riskLevel"] = "high";
                    labels["isRisky"] = true;

                    labels["conditionalAccessBlocked"] = _random.Next(100) < 85; // 85% chance of blocking

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

                    return torRanges[_random.Next(torRanges.Length)] + _random.Next(1, 255);


                case "unfamiliarsignin":
                case "atypicaltravel":
                    // Random international IPs
                    var internationalRanges = new[]
                    {
                        "203.208.60.", "203.208.61.", "203.208.62.", "203.208.63.",
                        "8.8.8.", "8.8.9.", "8.8.10.", "8.8.11.",
                        "1.1.1.", "1.1.2.", "1.1.3.", "1.1.4."
                    };

                    return internationalRanges[_random.Next(internationalRanges.Length)] + _random.Next(1, 255);


                case "leakedcredentials":
                case "impossibletravel":
                    // Suspicious IP ranges
                    var suspiciousRanges = new[]
                    {
                        "192.168.1.", "192.168.2.", "192.168.3.", "192.168.4.",
                        "10.0.0.", "10.0.1.", "10.0.2.", "10.0.3.",
                        "172.16.0.", "172.16.1.", "172.16.2.", "172.16.3."
                    };

                    return suspiciousRanges[_random.Next(suspiciousRanges.Length)] + _random.Next(1, 255);


                default:

                    return GenerateNormalIPAddress();

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

                    return torLocations[_random.Next(torLocations.Length)];


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

                    return internationalLocations[_random.Next(internationalLocations.Length)];


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

                    return suspiciousLocations[_random.Next(suspiciousLocations.Length)];


                default:

                    return GenerateNormalLocation();

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

            return usRanges[_random.Next(usRanges.Length)] + _random.Next(1, 255);

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

            return normalLocations[_random.Next(normalLocations.Length)];

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

        private string GenerateRandomUserId()
        {
            var prefixes = new[] { "john", "jane", "mike", "sarah", "david", "lisa", "robert", "emily" };
            var suffixes = new[] { "smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis" };


            var prefix = prefixes[_random.Next(prefixes.Length)];


            var suffix = suffixes[_random.Next(suffixes.Length)];


            var number = _random.Next(1000, 9999);


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

            return appNames[_random.Next(appNames.Length)];

        }

        private string GenerateRandomClientApp()
        {
            var clientApps = new[]
            {
                "Browser", "Mobile Apps and desktop clients", "Exchange ActiveSync",
                "IMAP", "POP3", "SMTP", "Authenticated SMTP", "Reporting Web Services"
            };

            return clientApps[_random.Next(clientApps.Length)];

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

            return operatingSystems[_random.Next(operatingSystems.Length)];

        }

        private string GenerateRandomBrowser()
        {
            var browsers = new[]
            {
                "Chrome", "Edge", "Firefox", "Safari", "Internet Explorer"
            };

            return browsers[_random.Next(browsers.Length)];

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

                }

            };
        }

        public List<string> GetAvailableRiskTypes()

        {


            return _riskPatterns.Keys.ToList();

        }

        public string[] GetRiskPatterns(string riskType)

        {


            return _riskPatterns.ContainsKey(riskType) ? _riskPatterns[riskType] : Array.Empty<string>();

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
