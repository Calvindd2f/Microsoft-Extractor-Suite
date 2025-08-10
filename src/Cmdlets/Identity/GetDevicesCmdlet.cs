using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ExtractorSuite.Core;
using Microsoft.ExtractorSuite.Core.Json;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using CsvHelper;
using System.Globalization;

namespace Microsoft.ExtractorSuite.Cmdlets.Identity
{
    /// <summary>
    /// Retrieves information about all devices registered in Microsoft Entra ID.
    /// Provides detailed device information including status, operating system details, trust type, and management information.
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "Devices")]
    [OutputType(typeof(DeviceInfo))]
    public class GetDevicesCmdlet : AsyncBaseCmdlet
    {
        [Parameter(HelpMessage = "Comma-separated list of user IDs to filter devices by registered users/owners")]
        public string[]? UserIds { get; set; }

        [Parameter(HelpMessage = "Output format for the results. Default: CSV")]
        [ValidateSet("CSV", "JSON")]
        public string OutputFormat { get; set; } = "CSV";

        [Parameter(HelpMessage = "Text encoding for the output file. Default: UTF8")]
        public string Encoding { get; set; } = "UTF8";

        protected override void ProcessRecord()
        {
            var results = RunAsyncOperation(GetDevicesAsync, "Getting Devices");

            if (!Async.IsPresent && results != null)
            {
                foreach (var result in results)
                {
                    WriteObject(result);
                }
            }
        }

        private async Task<List<DeviceInfo>> GetDevicesAsync(
            IProgress<Core.AsyncOperations.TaskProgress> progress,
            CancellationToken cancellationToken)
        {
            WriteVerboseWithTimestamp("Starting Device Collection");

            if (!RequireGraphConnection())
            {
                throw new InvalidOperationException("Not connected to Microsoft Graph. Please run Connect-M365 first.");
            }

            var graphClient = AuthManager.GraphClient!;

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
                    WriteWarningWithTimestamp("No devices found or insufficient permissions");
                    return results;
                }

                WriteVerboseWithTimestamp($"Found {devices.Value.Count} devices");
                summary.TotalDevices = devices.Value.Count;

                // Filter devices by user if specified
                List<Device> filteredDevices;
                if (UserIds?.Length > 0)
                {
                    progress.Report(new Core.AsyncOperations.TaskProgress
                    {
                        CurrentOperation = "Filtering devices by user",
                        PercentComplete = 30
                    });

                    filteredDevices = await FilterDevicesByUsersAsync(graphClient, devices.Value, cancellationToken);
                    WriteVerboseWithTimestamp($"Found {filteredDevices.Count} devices for specified users");
                }
                else
                {
                    filteredDevices = devices.Value.ToList();
                }

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
                    var deviceInfo = await MapDeviceToInfoAsync(graphClient, device, cancellationToken);
                    results.Add(deviceInfo);

                    // Update summary statistics
                    UpdateDeviceSummary(summary, deviceInfo);

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
                if (!string.IsNullOrEmpty(OutputDirectory))
                {
                    await ExportDevicesAsync(results, cancellationToken);
                }

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
                WriteErrorWithTimestamp($"Microsoft Graph API error: {ex.ResponseStatusCode} - {ex.Message}", ex);
                throw;
            }
            catch (Exception ex)
            {
                WriteErrorWithTimestamp($"Error retrieving devices: {ex.Message}", ex);
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
            var userIdList = new HashSet<string>(UserIds!, StringComparer.OrdinalIgnoreCase);

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
                    WriteWarningWithTimestamp($"Failed to retrieve owners/users for device {device.DisplayName}: {ex.Message}");
                }
                catch (Exception ex)
                {
                    WriteWarningWithTimestamp($"Error processing device {device.DisplayName}: {ex.Message}");
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
            var fileName = Path.Combine(
                OutputDirectory!,
                $"Devices_{DateTime.UtcNow:yyyyMMdd_HHmmss}.{OutputFormat.ToLower()}");

            Directory.CreateDirectory(Path.GetDirectoryName(fileName)!);

            if (OutputFormat.Equals("JSON", StringComparison.OrdinalIgnoreCase))
            {
                using var stream = File.Create(fileName);
                using var processor = new HighPerformanceJsonProcessor();
                await processor.SerializeAsync(stream, devices, true, cancellationToken);
            }
            else // CSV
            {
                using var writer = new StreamWriter(fileName, false, System.Text.Encoding.GetEncoding(Encoding));
                using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
                await csv.WriteRecordsAsync(devices, cancellationToken);
            }

            WriteVerboseWithTimestamp($"Exported {devices.Count} devices to {fileName}");
        }
    }

    public class DeviceInfo
    {
        public string DeviceId { get; set; } = string.Empty;
        public string ObjectId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string OperatingSystem { get; set; } = string.Empty;
        public string OperatingSystemVersion { get; set; } = string.Empty;
        public string DeviceVersion { get; set; } = string.Empty;
        public string DeviceCategory { get; set; } = string.Empty;
        public string DeviceOwnership { get; set; } = string.Empty;
        public string EnrollmentType { get; set; } = string.Empty;
        public bool IsCompliant { get; set; }
        public bool IsManaged { get; set; }
        public string TrustType { get; set; } = string.Empty;
        public bool AccountEnabled { get; set; }
        public DateTime? ApproximateLastSignInDateTime { get; set; }
        public string Manufacturer { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public bool OnPremisesSyncEnabled { get; set; }
        public string ProfileType { get; set; } = string.Empty;
        public string SystemLabels { get; set; } = string.Empty;
        public string RegisteredOwners { get; set; } = string.Empty;
        public string RegisteredUsers { get; set; } = string.Empty;
    }

    public class DeviceSummary
    {
        public DateTime StartTime { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public int TotalDevices { get; set; }
        public int AzureADJoined { get; set; }
        public int WorkplaceJoined { get; set; }
        public int HybridJoined { get; set; }
        public int ActiveDevices30Days { get; set; }
        public int InactiveDevices90Days { get; set; }
        public int CompliantDevices { get; set; }
        public int ManagedDevices { get; set; }
        public int Windows { get; set; }
        public int MacOS { get; set; }
        public int iOS { get; set; }
        public int Android { get; set; }
        public int Other { get; set; }
    }
}