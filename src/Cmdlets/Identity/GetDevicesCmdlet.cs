namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Management.Automation;
    using System.Threading;
    using System.Threading.Tasks;
    using CsvHelper;
    using Microsoft.ExtractorSuite.Core;
    using Microsoft.ExtractorSuite.Core.Json;
    using Microsoft.Graph;
    using Microsoft.Graph.Models;


    /// <summary>
    /// Retrieves information about all devices registered in Microsoft Entra ID.
    /// Provides detailed device information including status, operating system details, trust type, and management information.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "Devices")]
    [OutputType(typeof(DeviceInfo))]
    public class GetDevicesCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "Comma-separated list of user IDs to filter devices by registered users/owners")]
#pragma warning disable SA1600
        public string[]? UserIds { get; set; }
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Output format for the results. Default: CSV")]
        [ValidateSet("CSV", "JSON")]
#pragma warning disable SA1600
        public string OutputFormat { get; set; } = "CSV";
#pragma warning restore SA1600

        [Parameter(HelpMessage = "Text encoding for the output file. Default: UTF8")]
#pragma warning disable SA1600
        public string Encoding { get; set; } = "UTF8";
#pragma warning restore SA1600

#pragma warning disable SA1600
        protected override void ProcessRecord()
#pragma warning restore SA1600
        {
            var results = RunAsyncOperation(GetDevicesAsync, "Getting Devices");

#pragma warning disable SA1101
            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
#pragma warning restore SA1101
        }

        private async Task<List<DeviceInfo>> GetDevicesAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Device Collection");

#pragma warning disable SA1101
            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Not connected to Microsoft Graph. Please run Connect-M365 first.");
            }
#pragma warning restore SA1101

#pragma warning disable SA1101
            var graphClient = AuthManager.GraphClient!;
#pragma warning restore SA1101

            var summary = new DeviceSummary
            {
                StartTime = DateTime.UtcNow
            };

            progress.Report(new Core.AsyncOperations.TaskProgress
            {
                CurrentOperation = "Retrieving devices",
                PercentComplete = 10
            });

            var results = new List<DeviceInfo>();

            try
            {
                WriteVerboseWithTimestamp("Collecting device information...");

                // Get all devices
                var devices = await graphClient.Devices
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Top = 999;
                        requestConfiguration.QueryParameters.Select = new[]
                        {
                            "id", "deviceId", "displayName", "operatingSystem", "operatingSystemVersion",
                            "deviceVersion", "deviceCategory", "deviceOwnership", "enrollmentType",
                            "isCompliant", "isManaged", "trustType", "accountEnabled", "approximateLastSignInDateTime",
                            "deviceMetadata", "registeredOwners", "registeredUsers", "manufacturer", "model",
                            "onPremisesSyncEnabled", "profileType", "systemLabels"
                        };
                    }, cancellationToken);

                if (devices?.Value == null)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp("No devices found or insufficient permissions");
#pragma warning restore SA1101
                    return results;
                }

                WriteVerboseWithTimestamp($"Found {devices.Value.Count} devices");
                summary.TotalDevices = devices.Value.Count;

                // Filter devices by user if specified
                List<Device> filteredDevices;
#pragma warning disable SA1101
                if (UserIds?.Length > 0)
                {
                    progress.Report(new Core.AsyncOperations.TaskProgress
                    {
                        CurrentOperation = "Filtering devices by user",
                        PercentComplete = 30
                    });

#pragma warning disable SA1101
                    filteredDevices = await FilterDevicesByUsersAsync(graphClient, devices.Value, cancellationToken);
#pragma warning restore SA1101
                    WriteVerboseWithTimestamp($"Found {filteredDevices.Count} devices for specified users");
                }
                else
                {
                    filteredDevices = devices.Value.ToList();
                }
#pragma warning restore SA1101

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Processing device information",
                    PercentComplete = 50
                });

                var processedCount = 0;
                foreach (var device in filteredDevices)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    processedCount++;
#pragma warning disable SA1101
                    var deviceInfo = await MapDeviceToInfoAsync(graphClient, device, cancellationToken);
#pragma warning restore SA1101
                    results.Add(deviceInfo);

                    // Update summary statistics
#pragma warning disable SA1101
                    UpdateDeviceSummary(summary, deviceInfo);
#pragma warning restore SA1101

                    if (processedCount % 50 == 0 || processedCount == filteredDevices.Count)
                    {
                        var progressPercent = 50 + (int)((processedCount / (double)filteredDevices.Count) * 30);
                        progress.Report(new Core.AsyncOperations.TaskProgress
                        {
                            CurrentOperation = $"Processed {processedCount}/{filteredDevices.Count} devices",
                            PercentComplete = progressPercent,
                            ItemsProcessed = processedCount
                        });
                    }
                }

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Exporting results",
                    PercentComplete = 85
                });

                // Export results if output directory is specified
#pragma warning disable SA1101
                if (!string.IsNullOrEmpty(OutputDirectory))
                {
#pragma warning disable SA1101
                    await ExportDevicesAsync(results, cancellationToken);
#pragma warning restore SA1101
                }
#pragma warning restore SA1101

                summary.ProcessingTime = DateTime.UtcNow - summary.StartTime;

                // Log summary
                WriteVerboseWithTimestamp($"Device Analysis Summary:");
                WriteVerboseWithTimestamp($"  Total Devices: {summary.TotalDevices}");
                WriteVerboseWithTimestamp($"  Azure AD Joined: {summary.AzureADJoined}");
                WriteVerboseWithTimestamp($"  Workplace Joined: {summary.WorkplaceJoined}");
                WriteVerboseWithTimestamp($"  Hybrid Joined: {summary.HybridJoined}");
                WriteVerboseWithTimestamp($"  Compliant Devices: {summary.CompliantDevices}");
                WriteVerboseWithTimestamp($"  Managed Devices: {summary.ManagedDevices}");
                WriteVerboseWithTimestamp($"  Active (Last 30 Days): {summary.ActiveDevices30Days}");
                WriteVerboseWithTimestamp($"  Windows: {summary.Windows}, macOS: {summary.MacOS}, iOS: {summary.iOS}, Android: {summary.Android}");
                WriteVerboseWithTimestamp($"  Processing Time: {summary.ProcessingTime:mm\\:ss}");

                progress.Report(new Core.AsyncOperations.TaskProgress
                {
                    CurrentOperation = "Collection completed",
                    PercentComplete = 100
                });
            }
            catch (ServiceException ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Microsoft Graph API error: {ex.ResponseStatusCode} - {ex.Message}", ex);
#pragma warning restore SA1101
                throw;
            }
            catch (Exception ex)
            {
#pragma warning disable SA1101
                WriteErrorWithTimestamp($"Error retrieving devices: {ex.Message}", ex);
#pragma warning restore SA1101
                throw;
            }

            return results;
        }

        private async Task<List<Device>> FilterDevicesByUsersAsync(
            GraphServiceClient graphClient,
            IList<Device> devices,
            CancellationToken cancellationToken)
        {
            var filteredDevices = new List<Device>();
#pragma warning disable SA1101
            var userIdList = new HashSet<string>(UserIds!, StringComparer.OrdinalIgnoreCase);
#pragma warning restore SA1101

            foreach (var device in devices)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                try
                {
                    // Check registered owners
                    var owners = await graphClient.Devices[device.Id].RegisteredOwners
                        .GetAsync(requestConfiguration =>
                        {
                            requestConfiguration.QueryParameters.Select = new[] { "userPrincipalName" };
                        }, cancellationToken);

                    // Check registered users
                    var users = await graphClient.Devices[device.Id].RegisteredUsers
                        .GetAsync(requestConfiguration =>
                        {
                            requestConfiguration.QueryParameters.Select = new[] { "userPrincipalName" };
                        }, cancellationToken);

                    // Check if any owner or user matches our filter
                    var matchFound = false;

                    if (owners?.Value != null)
                    {
                        foreach (var owner in owners.Value)
                        {
                            if (owner is User ownerUser && ownerUser.UserPrincipalName != null)
                            {
                                if (userIdList.Contains(ownerUser.UserPrincipalName))
                                {
                                    matchFound = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (!matchFound && users?.Value != null)
                    {
                        foreach (var user in users.Value)
                        {
                            if (user is User registeredUser && registeredUser.UserPrincipalName != null)
                            {
                                if (userIdList.Contains(registeredUser.UserPrincipalName))
                                {
                                    matchFound = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (matchFound)
                    {
                        filteredDevices.Add(device);
                    }
                }
                catch (ServiceException ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Failed to retrieve owners/users for device {device.DisplayName}: {ex.Message}");
#pragma warning restore SA1101
                }
                catch (Exception ex)
                {
#pragma warning disable SA1101
                    WriteWarningWithTimestamp($"Error processing device {device.DisplayName}: {ex.Message}");
#pragma warning restore SA1101
                }
            }

            return filteredDevices;
        }

        private async Task<DeviceInfo> MapDeviceToInfoAsync(
            GraphServiceClient graphClient,
            Device device,
            CancellationToken cancellationToken)
        {
            var deviceInfo = new DeviceInfo
            {
                DeviceId = device.DeviceId ?? "",
                ObjectId = device.Id ?? "",
                DisplayName = device.DisplayName ?? "",
                OperatingSystem = device.OperatingSystem ?? "",
                OperatingSystemVersion = device.OperatingSystemVersion ?? "",
                DeviceVersion = device.DeviceVersion?.ToString() ?? "",
                DeviceCategory = device.DeviceCategory ?? "",
                DeviceOwnership = device.DeviceOwnership ?? "",
                EnrollmentType = device.EnrollmentType ?? "",
                IsCompliant = device.IsCompliant ?? false,
                IsManaged = device.IsManaged ?? false,
                TrustType = device.TrustType ?? "",
                AccountEnabled = device.AccountEnabled ?? false,
                ApproximateLastSignInDateTime = device.ApproximateLastSignInDateTime?.DateTime,
                Manufacturer = device.Manufacturer ?? "",
                Model = device.Model ?? "",
                OnPremisesSyncEnabled = device.OnPremisesSyncEnabled ?? false,
                ProfileType = device.ProfileType ?? "",
                SystemLabels = device.SystemLabels != null ? string.Join("; ", device.SystemLabels) : ""
            };

            // Get registered owners and users
            try
            {
                var owners = await graphClient.Devices[device.Id].RegisteredOwners
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Select = new[] { "displayName", "userPrincipalName" };
                    }, cancellationToken);

                var users = await graphClient.Devices[device.Id].RegisteredUsers
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Select = new[] { "displayName", "userPrincipalName" };
                    }, cancellationToken);

                if (owners?.Value != null)
                {
                    var ownerNames = owners.Value
                        .OfType<User>()
                        .Where(u => !string.IsNullOrEmpty(u.UserPrincipalName))
                        .Select(u => u.UserPrincipalName!)
                        .ToList();
                    deviceInfo.RegisteredOwners = string.Join("; ", ownerNames);
                }

                if (users?.Value != null)
                {
                    var userNames = users.Value
                        .OfType<User>()
                        .Where(u => !string.IsNullOrEmpty(u.UserPrincipalName))
                        .Select(u => u.UserPrincipalName!)
                        .ToList();
                    deviceInfo.RegisteredUsers = string.Join("; ", userNames);
                }
            }
            catch (ServiceException ex)
            {
                WriteVerboseWithTimestamp($"Could not retrieve owners/users for device {device.DisplayName}: {ex.Message}");
            }
            catch (Exception ex)
            {
                WriteVerboseWithTimestamp($"Error retrieving device relationships for {device.DisplayName}: {ex.Message}");
            }

            return deviceInfo;
        }

        private void UpdateDeviceSummary(DeviceSummary summary, DeviceInfo deviceInfo)
        {
            // Trust type statistics
            switch (deviceInfo.TrustType?.ToLowerInvariant())
            {
                case "azuread":
                    summary.AzureADJoined++;
                    break;
                case "workplace":
                    summary.WorkplaceJoined++;
                    break;
                case "serverad":
                    summary.HybridJoined++;
                    break;
            }

            // Compliance and management
            if (deviceInfo.IsCompliant) summary.CompliantDevices++;
            if (deviceInfo.IsManaged) summary.ManagedDevices++;

            // Activity statistics
            if (deviceInfo.ApproximateLastSignInDateTime.HasValue)
            {
                var daysSinceSignIn = (DateTime.UtcNow - deviceInfo.ApproximateLastSignInDateTime.Value).Days;
                if (daysSinceSignIn <= 30)
                {
                    summary.ActiveDevices30Days++;
                }
                if (daysSinceSignIn > 90)
                {
                    summary.InactiveDevices90Days++;
                }
            }

            // Operating system statistics
            var os = deviceInfo.OperatingSystem?.ToLowerInvariant() ?? "";
            if (os.Contains("windows"))
            {
                summary.Windows++;
            }
            else if (os.Contains("mac") || os.Contains("ios"))
            {
                if (os.Contains("mac"))
                    summary.MacOS++;
                else
                    summary.iOS++;
            }
            else if (os.Contains("android"))
            {
                summary.Android++;
            }
            else
            {
                summary.Other++;
            }
        }

        private async Task ExportDevicesAsync(List<DeviceInfo> devices, CancellationToken cancellationToken)
        {
#pragma warning disable SA1101
            var fileName = Path.Combine(
                OutputDirectory!,
                $"Devices_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{OutputFormat.ToLower()}");
#pragma warning restore SA1101

            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

#pragma warning disable SA1101
            if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.Create(fileName);
                using var processor = new HighPerformanceJsonProcessor();
                await processor.SerializeAsync(stream, devices, true, cancellationToken);
            }
            else // CSV
            {
#pragma warning disable SA1101
                using var writer = new StreamWriter(fileName, false, System.Text.Encoding.GetEncoding(Encoding));
#pragma warning restore SA1101
                using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(devices, cancellationToken);
            }
#pragma warning restore SA1101

            WriteVerboseWithTimestamp($"Exported {devices.Count} devices to {fileName}");
        }
    }

#pragma warning disable SA1600
    public class DeviceInfo
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string DeviceId { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string ObjectId { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string DisplayName { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string OperatingSystem { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string OperatingSystemVersion { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string DeviceVersion { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string DeviceCategory { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string DeviceOwnership { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string EnrollmentType { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsCompliant { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool IsManaged { get; set; }
        public string TrustType { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool AccountEnabled { get; set; }
        public DateTime? ApproximateLastSignInDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Manufacturer { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string Model { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public bool OnPremisesSyncEnabled { get; set; }
        public string ProfileType { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string SystemLabels { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string RegisteredOwners { get; set; } = string.Empty;
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string RegisteredUsers { get; set; } = string.Empty;
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class DeviceSummary
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public DateTime StartTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public TimeSpan ProcessingTime { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int TotalDevices { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int AzureADJoined { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int WorkplaceJoined { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int HybridJoined { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int ActiveDevices30Days { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int InactiveDevices90Days { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int CompliantDevices { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int ManagedDevices { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int Windows { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int MacOS { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int iOS { get; set; }
#pragma warning restore SA1600
        #pragma warning disable SA1600
        public int Android { get; set; }
#pragma warning restore SA1600
        public int Other { get; set; }
    }
}
