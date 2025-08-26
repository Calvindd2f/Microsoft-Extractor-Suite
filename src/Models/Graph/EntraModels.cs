using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Microsoft.ExtractorSuite.Models.Graph
{
}

namespace Microsoft.Graph
{
    /// <summary>
    /// Temporary compatibility class for SignIn
    /// </summary>
#pragma warning disable SA1649
name
    public class SignIn
#pragma warning restore SA1649
name
    {
#pragma warning disable SA1600
        public string? Id { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DateTimeOffset? CreatedDateTime { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? UserDisplayName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? UserPrincipalName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? UserId { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? AppId { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? AppDisplayName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? IpAddress { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? ClientAppUsed { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? CorrelationId { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? ConditionalAccessStatus { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? IsInteractive { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? RiskDetail { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? RiskLevelAggregated { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? RiskLevelDuringSignIn { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? RiskState { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public DeviceDetail? DeviceDetail { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public SignInStatus? Status { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public Location? Location { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class DeviceDetail
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string? DeviceId { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? DisplayName { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? OperatingSystem { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? Browser { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public bool? IsCompliant { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public bool? IsManaged { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? TrustType { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class SignInStatus
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public int? ErrorCode { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? FailureReason { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? AdditionalDetails { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class Location
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public string? City { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? State { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public string? CountryOrRegion { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public GeoCoordinates? GeoCoordinates { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class GeoCoordinates
#pragma warning restore SA1600
    {
#pragma warning disable SA1600
        public double? Altitude { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public double? Latitude { get; set; }
#pragma warning restore SA1600
#pragma warning disable SA1600
        public double? Longitude { get; set; }
#pragma warning restore SA1600
    }
}

namespace Microsoft.ExtractorSuite.Models.Graph
{
    /// <summary>
    /// Represents an Entra ID (Azure AD) sign-in log entry
    /// </summary>
    public class SignInLog
    {
        [JsonPropertyName("id")]
#pragma warning disable SA1600
        public string? Id { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("createdDateTime")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public DateTimeOffset CreatedDateTime { get; set; }

        [JsonPropertyName("userDisplayName")]
#pragma warning disable SA1600
        public string? UserDisplayName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("userPrincipalName")]
#pragma warning disable SA1600
        public string? UserPrincipalName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("userId")]
#pragma warning disable SA1600
        public string? UserId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("appId")]
#pragma warning disable SA1600
        public string? AppId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("appDisplayName")]
#pragma warning disable SA1600
        public string? AppDisplayName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ipAddress")]
#pragma warning disable SA1600
        public string? IpAddress { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ipAddressFromResourceProvider")]
#pragma warning disable SA1600
        public string? IpAddressFromResourceProvider { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("clientAppUsed")]
#pragma warning disable SA1600
        public string? ClientAppUsed { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("correlationId")]
#pragma warning disable SA1600
        public string? CorrelationId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("conditionalAccessStatus")]
#pragma warning disable SA1600
        public string? ConditionalAccessStatus { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("originalRequestId")]
#pragma warning disable SA1600
        public string? OriginalRequestId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("isInteractive")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool IsInteractive { get; set; }

        [JsonPropertyName("tokenIssuerName")]
#pragma warning disable SA1600
        public string? TokenIssuerName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("tokenIssuerType")]
#pragma warning disable SA1600
        public string? TokenIssuerType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("processingTimeInMilliseconds")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public int ProcessingTimeInMilliseconds { get; set; }

        [JsonPropertyName("riskDetail")]
#pragma warning disable SA1600
        public string? RiskDetail { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("riskLevelAggregated")]
#pragma warning disable SA1600
        public string? RiskLevelAggregated { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("riskLevelDuringSignIn")]
#pragma warning disable SA1600
        public string? RiskLevelDuringSignIn { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("riskState")]
#pragma warning disable SA1600
        public string? RiskState { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("riskEventTypes")]
#pragma warning disable SA1600
        public List<string>? RiskEventTypes { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("riskEventTypes_v2")]
#pragma warning disable SA1600
        public List<string>? RiskEventTypesV2 { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("resourceDisplayName")]
#pragma warning disable SA1600
        public string? ResourceDisplayName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("resourceId")]
#pragma warning disable SA1600
        public string? ResourceId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("resourceTenantId")]
#pragma warning disable SA1600
        public string? ResourceTenantId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("homeTenantId")]
#pragma warning disable SA1600
        public string? HomeTenantId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("homeTenantName")]
#pragma warning disable SA1600
        public string? HomeTenantName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("status")]
#pragma warning disable SA1600
        public SignInStatus? Status { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("deviceDetail")]
#pragma warning disable SA1600
        public DeviceDetail? DeviceDetail { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("location")]
#pragma warning disable SA1600
        public SignInLocation? Location { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("appliedConditionalAccessPolicies")]
#pragma warning disable SA1600
        public List<AppliedConditionalAccessPolicy>? AppliedConditionalAccessPolicies { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("authenticationContextClassReferences")]
#pragma warning disable SA1600
        public List<AuthenticationContext>? AuthenticationContextClassReferences { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("authenticationMethodsUsed")]
#pragma warning disable SA1600
        public List<string>? AuthenticationMethodsUsed { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("authenticationRequirement")]
#pragma warning disable SA1600
        public string? AuthenticationRequirement { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("signInIdentifier")]
#pragma warning disable SA1600
        public string? SignInIdentifier { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("signInIdentifierType")]
#pragma warning disable SA1600
        public string? SignInIdentifierType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("servicePrincipalName")]
#pragma warning disable SA1600
        public string? ServicePrincipalName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("userType")]
#pragma warning disable SA1600
        public string? UserType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("flaggedForReview")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool FlaggedForReview { get; set; }

        [JsonPropertyName("isTenantRestricted")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public bool IsTenantRestricted { get; set; }

        [JsonPropertyName("autonomousSystemNumber")]
#pragma warning disable SA1600
        public int? AutonomousSystemNumber { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("crossTenantAccessType")]
#pragma warning disable SA1600
        public string? CrossTenantAccessType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("privateLinkDetails")]
#pragma warning disable SA1600
        public PrivateLinkDetails? PrivateLinkDetails { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("uniqueTokenIdentifier")]
#pragma warning disable SA1600
        public string? UniqueTokenIdentifier { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("incomingTokenType")]
#pragma warning disable SA1600
        public string? IncomingTokenType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("authenticationProtocol")]
#pragma warning disable SA1600
        public string? AuthenticationProtocol { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("resourceServicePrincipalId")]
#pragma warning disable SA1600
        public string? ResourceServicePrincipalId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("mfaDetail")]
#pragma warning disable SA1600
        public MfaDetail? MfaDetail { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class SignInStatus
#pragma warning restore SA1600
    {
        [JsonPropertyName("errorCode")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public int ErrorCode { get; set; }

        [JsonPropertyName("failureReason")]
#pragma warning disable SA1600
        public string? FailureReason { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("additionalDetails")]
#pragma warning disable SA1600
        public string? AdditionalDetails { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class DeviceDetail
#pragma warning restore SA1600
    {
        [JsonPropertyName("deviceId")]
#pragma warning disable SA1600
        public string? DeviceId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("displayName")]
#pragma warning disable SA1600
        public string? DisplayName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("operatingSystem")]
#pragma warning disable SA1600
        public string? OperatingSystem { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("browser")]
#pragma warning disable SA1600
        public string? Browser { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("isCompliant")]
#pragma warning disable SA1600
        public bool? IsCompliant { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("isManaged")]
#pragma warning disable SA1600
        public bool? IsManaged { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("trustType")]
#pragma warning disable SA1600
        public string? TrustType { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class SignInLocation
#pragma warning restore SA1600
    {
        [JsonPropertyName("city")]
#pragma warning disable SA1600
        public string? City { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("state")]
#pragma warning disable SA1600
        public string? State { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("countryOrRegion")]
#pragma warning disable SA1600
        public string? CountryOrRegion { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("geoCoordinates")]
#pragma warning disable SA1600
        public GeoCoordinates? GeoCoordinates { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class GeoCoordinates
#pragma warning restore SA1600
    {
        [JsonPropertyName("altitude")]
#pragma warning disable SA1600
        public double? Altitude { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("latitude")]
#pragma warning disable SA1600
        public double? Latitude { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("longitude")]
#pragma warning disable SA1600
        public double? Longitude { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class AppliedConditionalAccessPolicy
#pragma warning restore SA1600
    {
        [JsonPropertyName("id")]
#pragma warning disable SA1600
        public string? Id { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("displayName")]
#pragma warning disable SA1600
        public string? DisplayName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("enforcedGrantControls")]
#pragma warning disable SA1600
        public List<string>? EnforcedGrantControls { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("enforcedSessionControls")]
#pragma warning disable SA1600
        public List<string>? EnforcedSessionControls { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("result")]
#pragma warning disable SA1600
        public string? Result { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("conditionsSatisfied")]
#pragma warning disable SA1600
        public string? ConditionsSatisfied { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("conditionsNotSatisfied")]
#pragma warning disable SA1600
        public string? ConditionsNotSatisfied { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class AuthenticationContext
#pragma warning restore SA1600
    {
        [JsonPropertyName("id")]
#pragma warning disable SA1600
        public string? Id { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("detail")]
#pragma warning disable SA1600
        public string? Detail { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class MfaDetail
#pragma warning restore SA1600
    {
        [JsonPropertyName("authMethod")]
#pragma warning disable SA1600
        public string? AuthMethod { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("authDetail")]
#pragma warning disable SA1600
        public string? AuthDetail { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class PrivateLinkDetails
#pragma warning restore SA1600
    {
        [JsonPropertyName("policyId")]
#pragma warning disable SA1600
        public string? PolicyId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("policyName")]
#pragma warning disable SA1600
        public string? PolicyName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("resourceId")]
#pragma warning disable SA1600
        public string? ResourceId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("policyTenantId")]
#pragma warning disable SA1600
        public string? PolicyTenantId { get; set; }
#pragma warning restore SA1600
    }

    /// <summary>
    /// Represents an Entra ID (Azure AD) audit log entry
    /// </summary>
    public class AuditLog
    {
        [JsonPropertyName("id")]
#pragma warning disable SA1600
        public string? Id { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("category")]
#pragma warning disable SA1600
        public string? Category { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("correlationId")]
#pragma warning disable SA1600
        public string? CorrelationId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("result")]
#pragma warning disable SA1600
        public string? Result { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("resultReason")]
#pragma warning disable SA1600
        public string? ResultReason { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("activityDisplayName")]
#pragma warning disable SA1600
        public string? ActivityDisplayName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("activityDateTime")]
#pragma warning disable SA1600
#pragma warning restore SA1600
        public DateTimeOffset ActivityDateTime { get; set; }

        [JsonPropertyName("loggedByService")]
#pragma warning disable SA1600
        public string? LoggedByService { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("operationType")]
#pragma warning disable SA1600
        public string? OperationType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("initiatedBy")]
#pragma warning disable SA1600
        public AuditActor? InitiatedBy { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("targetResources")]
#pragma warning disable SA1600
        public List<TargetResource>? TargetResources { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("additionalDetails")]
#pragma warning disable SA1600
        public List<KeyValue>? AdditionalDetails { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("userAgent")]
#pragma warning disable SA1600
        public string? UserAgent { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class AuditActor
#pragma warning restore SA1600
    {
        [JsonPropertyName("user")]
#pragma warning disable SA1600
        public UserIdentity? User { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("app")]
#pragma warning disable SA1600
        public AppIdentity? App { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class UserIdentity
#pragma warning restore SA1600
    {
        [JsonPropertyName("id")]
#pragma warning disable SA1600
        public string? Id { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("displayName")]
#pragma warning disable SA1600
        public string? DisplayName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("userPrincipalName")]
#pragma warning disable SA1600
        public string? UserPrincipalName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("ipAddress")]
#pragma warning disable SA1600
        public string? IpAddress { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("userType")]
#pragma warning disable SA1600
        public string? UserType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("homeTenantId")]
#pragma warning disable SA1600
        public string? HomeTenantId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("homeTenantName")]
#pragma warning disable SA1600
        public string? HomeTenantName { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class AppIdentity
#pragma warning restore SA1600
    {
        [JsonPropertyName("appId")]
#pragma warning disable SA1600
        public string? AppId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("displayName")]
#pragma warning disable SA1600
        public string? DisplayName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("servicePrincipalId")]
#pragma warning disable SA1600
        public string? ServicePrincipalId { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("servicePrincipalName")]
#pragma warning disable SA1600
        public string? ServicePrincipalName { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class TargetResource
#pragma warning restore SA1600
    {
        [JsonPropertyName("id")]
#pragma warning disable SA1600
        public string? Id { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("displayName")]
#pragma warning disable SA1600
        public string? DisplayName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("type")]
#pragma warning disable SA1600
        public string? Type { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("userPrincipalName")]
#pragma warning disable SA1600
        public string? UserPrincipalName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("groupType")]
#pragma warning disable SA1600
        public string? GroupType { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("modifiedProperties")]
#pragma warning disable SA1600
        public List<ModifiedProperty>? ModifiedProperties { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class ModifiedProperty
#pragma warning restore SA1600
    {
        [JsonPropertyName("displayName")]
#pragma warning disable SA1600
        public string? DisplayName { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("oldValue")]
#pragma warning disable SA1600
        public string? OldValue { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("newValue")]
#pragma warning disable SA1600
        public string? NewValue { get; set; }
#pragma warning restore SA1600
    }

#pragma warning disable SA1600
    public class KeyValue
#pragma warning restore SA1600
    {
        [JsonPropertyName("key")]
#pragma warning disable SA1600
        public string? Key { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("value")]
#pragma warning disable SA1600
        public string? Value { get; set; }
#pragma warning restore SA1600
    }

    /// <summary>
    /// Represents a paged response from Graph API
    /// </summary>
    public class GraphPagedResponse<T>
    {
        [JsonPropertyName("@odata.context")]
#pragma warning disable SA1600
        public string? Context { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("@odata.nextLink")]
#pragma warning disable SA1600
        public string? NextLink { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("@odata.count")]
#pragma warning disable SA1600
        public int? Count { get; set; }
#pragma warning restore SA1600

        [JsonPropertyName("value")]
#pragma warning disable SA1600
        public List<T>? Value { get; set; }
#pragma warning restore SA1600
    }
}
