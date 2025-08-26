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

name
    public class SignIn

name
    {

        public string? Id { get; set; }


        public DateTimeOffset? CreatedDateTime { get; set; }


        public string? UserDisplayName { get; set; }


        public string? UserPrincipalName { get; set; }


        public string? UserId { get; set; }


        public string? AppId { get; set; }


        public string? AppDisplayName { get; set; }


        public string? IpAddress { get; set; }


        public string? ClientAppUsed { get; set; }


        public string? CorrelationId { get; set; }


        public string? ConditionalAccessStatus { get; set; }


        public string? IsInteractive { get; set; }


        public string? RiskDetail { get; set; }


        public string? RiskLevelAggregated { get; set; }


        public string? RiskLevelDuringSignIn { get; set; }


        public string? RiskState { get; set; }


        public DeviceDetail? DeviceDetail { get; set; }


        public SignInStatus? Status { get; set; }


        public Location? Location { get; set; }

    }


    public class DeviceDetail

    {

        public string? DeviceId { get; set; }


        public string? DisplayName { get; set; }


        public string? OperatingSystem { get; set; }


        public string? Browser { get; set; }


        public bool? IsCompliant { get; set; }


        public bool? IsManaged { get; set; }


        public string? TrustType { get; set; }

    }


    public class SignInStatus

    {

        public int? ErrorCode { get; set; }


        public string? FailureReason { get; set; }


        public string? AdditionalDetails { get; set; }

    }


    public class Location

    {

        public string? City { get; set; }


        public string? State { get; set; }


        public string? CountryOrRegion { get; set; }


        public GeoCoordinates? GeoCoordinates { get; set; }

    }


    public class GeoCoordinates

    {

        public double? Altitude { get; set; }


        public double? Latitude { get; set; }


        public double? Longitude { get; set; }

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

        public string? Id { get; set; }


        [JsonPropertyName("createdDateTime")]


        public DateTimeOffset CreatedDateTime { get; set; }

        [JsonPropertyName("userDisplayName")]

        public string? UserDisplayName { get; set; }


        [JsonPropertyName("userPrincipalName")]

        public string? UserPrincipalName { get; set; }


        [JsonPropertyName("userId")]

        public string? UserId { get; set; }


        [JsonPropertyName("appId")]

        public string? AppId { get; set; }


        [JsonPropertyName("appDisplayName")]

        public string? AppDisplayName { get; set; }


        [JsonPropertyName("ipAddress")]

        public string? IpAddress { get; set; }


        [JsonPropertyName("ipAddressFromResourceProvider")]

        public string? IpAddressFromResourceProvider { get; set; }


        [JsonPropertyName("clientAppUsed")]

        public string? ClientAppUsed { get; set; }


        [JsonPropertyName("correlationId")]

        public string? CorrelationId { get; set; }


        [JsonPropertyName("conditionalAccessStatus")]

        public string? ConditionalAccessStatus { get; set; }


        [JsonPropertyName("originalRequestId")]

        public string? OriginalRequestId { get; set; }


        [JsonPropertyName("isInteractive")]


        public bool IsInteractive { get; set; }

        [JsonPropertyName("tokenIssuerName")]

        public string? TokenIssuerName { get; set; }


        [JsonPropertyName("tokenIssuerType")]

        public string? TokenIssuerType { get; set; }


        [JsonPropertyName("processingTimeInMilliseconds")]


        public int ProcessingTimeInMilliseconds { get; set; }

        [JsonPropertyName("riskDetail")]

        public string? RiskDetail { get; set; }


        [JsonPropertyName("riskLevelAggregated")]

        public string? RiskLevelAggregated { get; set; }


        [JsonPropertyName("riskLevelDuringSignIn")]

        public string? RiskLevelDuringSignIn { get; set; }


        [JsonPropertyName("riskState")]

        public string? RiskState { get; set; }


        [JsonPropertyName("riskEventTypes")]

        public List<string>? RiskEventTypes { get; set; }


        [JsonPropertyName("riskEventTypes_v2")]

        public List<string>? RiskEventTypesV2 { get; set; }


        [JsonPropertyName("resourceDisplayName")]

        public string? ResourceDisplayName { get; set; }


        [JsonPropertyName("resourceId")]

        public string? ResourceId { get; set; }


        [JsonPropertyName("resourceTenantId")]

        public string? ResourceTenantId { get; set; }


        [JsonPropertyName("homeTenantId")]

        public string? HomeTenantId { get; set; }


        [JsonPropertyName("homeTenantName")]

        public string? HomeTenantName { get; set; }


        [JsonPropertyName("status")]

        public SignInStatus? Status { get; set; }


        [JsonPropertyName("deviceDetail")]

        public DeviceDetail? DeviceDetail { get; set; }


        [JsonPropertyName("location")]

        public SignInLocation? Location { get; set; }


        [JsonPropertyName("appliedConditionalAccessPolicies")]

        public List<AppliedConditionalAccessPolicy>? AppliedConditionalAccessPolicies { get; set; }


        [JsonPropertyName("authenticationContextClassReferences")]

        public List<AuthenticationContext>? AuthenticationContextClassReferences { get; set; }


        [JsonPropertyName("authenticationMethodsUsed")]

        public List<string>? AuthenticationMethodsUsed { get; set; }


        [JsonPropertyName("authenticationRequirement")]

        public string? AuthenticationRequirement { get; set; }


        [JsonPropertyName("signInIdentifier")]

        public string? SignInIdentifier { get; set; }


        [JsonPropertyName("signInIdentifierType")]

        public string? SignInIdentifierType { get; set; }


        [JsonPropertyName("servicePrincipalName")]

        public string? ServicePrincipalName { get; set; }


        [JsonPropertyName("userType")]

        public string? UserType { get; set; }


        [JsonPropertyName("flaggedForReview")]


        public bool FlaggedForReview { get; set; }

        [JsonPropertyName("isTenantRestricted")]


        public bool IsTenantRestricted { get; set; }

        [JsonPropertyName("autonomousSystemNumber")]

        public int? AutonomousSystemNumber { get; set; }


        [JsonPropertyName("crossTenantAccessType")]

        public string? CrossTenantAccessType { get; set; }


        [JsonPropertyName("privateLinkDetails")]

        public PrivateLinkDetails? PrivateLinkDetails { get; set; }


        [JsonPropertyName("uniqueTokenIdentifier")]

        public string? UniqueTokenIdentifier { get; set; }


        [JsonPropertyName("incomingTokenType")]

        public string? IncomingTokenType { get; set; }


        [JsonPropertyName("authenticationProtocol")]

        public string? AuthenticationProtocol { get; set; }


        [JsonPropertyName("resourceServicePrincipalId")]

        public string? ResourceServicePrincipalId { get; set; }


        [JsonPropertyName("mfaDetail")]

        public MfaDetail? MfaDetail { get; set; }

    }


    public class SignInStatus

    {
        [JsonPropertyName("errorCode")]


        public int ErrorCode { get; set; }

        [JsonPropertyName("failureReason")]

        public string? FailureReason { get; set; }


        [JsonPropertyName("additionalDetails")]

        public string? AdditionalDetails { get; set; }

    }


    public class DeviceDetail

    {
        [JsonPropertyName("deviceId")]

        public string? DeviceId { get; set; }


        [JsonPropertyName("displayName")]

        public string? DisplayName { get; set; }


        [JsonPropertyName("operatingSystem")]

        public string? OperatingSystem { get; set; }


        [JsonPropertyName("browser")]

        public string? Browser { get; set; }


        [JsonPropertyName("isCompliant")]

        public bool? IsCompliant { get; set; }


        [JsonPropertyName("isManaged")]

        public bool? IsManaged { get; set; }


        [JsonPropertyName("trustType")]

        public string? TrustType { get; set; }

    }


    public class SignInLocation

    {
        [JsonPropertyName("city")]

        public string? City { get; set; }


        [JsonPropertyName("state")]

        public string? State { get; set; }


        [JsonPropertyName("countryOrRegion")]

        public string? CountryOrRegion { get; set; }


        [JsonPropertyName("geoCoordinates")]

        public GeoCoordinates? GeoCoordinates { get; set; }

    }


    public class GeoCoordinates

    {
        [JsonPropertyName("altitude")]

        public double? Altitude { get; set; }


        [JsonPropertyName("latitude")]

        public double? Latitude { get; set; }


        [JsonPropertyName("longitude")]

        public double? Longitude { get; set; }

    }


    public class AppliedConditionalAccessPolicy

    {
        [JsonPropertyName("id")]

        public string? Id { get; set; }


        [JsonPropertyName("displayName")]

        public string? DisplayName { get; set; }


        [JsonPropertyName("enforcedGrantControls")]

        public List<string>? EnforcedGrantControls { get; set; }


        [JsonPropertyName("enforcedSessionControls")]

        public List<string>? EnforcedSessionControls { get; set; }


        [JsonPropertyName("result")]

        public string? Result { get; set; }


        [JsonPropertyName("conditionsSatisfied")]

        public string? ConditionsSatisfied { get; set; }


        [JsonPropertyName("conditionsNotSatisfied")]

        public string? ConditionsNotSatisfied { get; set; }

    }


    public class AuthenticationContext

    {
        [JsonPropertyName("id")]

        public string? Id { get; set; }


        [JsonPropertyName("detail")]

        public string? Detail { get; set; }

    }


    public class MfaDetail

    {
        [JsonPropertyName("authMethod")]

        public string? AuthMethod { get; set; }


        [JsonPropertyName("authDetail")]

        public string? AuthDetail { get; set; }

    }


    public class PrivateLinkDetails

    {
        [JsonPropertyName("policyId")]

        public string? PolicyId { get; set; }


        [JsonPropertyName("policyName")]

        public string? PolicyName { get; set; }


        [JsonPropertyName("resourceId")]

        public string? ResourceId { get; set; }


        [JsonPropertyName("policyTenantId")]

        public string? PolicyTenantId { get; set; }

    }

    /// <summary>
    /// Represents an Entra ID (Azure AD) audit log entry
    /// </summary>
    public class AuditLog
    {
        [JsonPropertyName("id")]

        public string? Id { get; set; }


        [JsonPropertyName("category")]

        public string? Category { get; set; }


        [JsonPropertyName("correlationId")]

        public string? CorrelationId { get; set; }


        [JsonPropertyName("result")]

        public string? Result { get; set; }


        [JsonPropertyName("resultReason")]

        public string? ResultReason { get; set; }


        [JsonPropertyName("activityDisplayName")]

        public string? ActivityDisplayName { get; set; }


        [JsonPropertyName("activityDateTime")]


        public DateTimeOffset ActivityDateTime { get; set; }

        [JsonPropertyName("loggedByService")]

        public string? LoggedByService { get; set; }


        [JsonPropertyName("operationType")]

        public string? OperationType { get; set; }


        [JsonPropertyName("initiatedBy")]

        public AuditActor? InitiatedBy { get; set; }


        [JsonPropertyName("targetResources")]

        public List<TargetResource>? TargetResources { get; set; }


        [JsonPropertyName("additionalDetails")]

        public List<KeyValue>? AdditionalDetails { get; set; }


        [JsonPropertyName("userAgent")]

        public string? UserAgent { get; set; }

    }


    public class AuditActor

    {
        [JsonPropertyName("user")]

        public UserIdentity? User { get; set; }


        [JsonPropertyName("app")]

        public AppIdentity? App { get; set; }

    }


    public class UserIdentity

    {
        [JsonPropertyName("id")]

        public string? Id { get; set; }


        [JsonPropertyName("displayName")]

        public string? DisplayName { get; set; }


        [JsonPropertyName("userPrincipalName")]

        public string? UserPrincipalName { get; set; }


        [JsonPropertyName("ipAddress")]

        public string? IpAddress { get; set; }


        [JsonPropertyName("userType")]

        public string? UserType { get; set; }


        [JsonPropertyName("homeTenantId")]

        public string? HomeTenantId { get; set; }


        [JsonPropertyName("homeTenantName")]

        public string? HomeTenantName { get; set; }

    }


    public class AppIdentity

    {
        [JsonPropertyName("appId")]

        public string? AppId { get; set; }


        [JsonPropertyName("displayName")]

        public string? DisplayName { get; set; }


        [JsonPropertyName("servicePrincipalId")]

        public string? ServicePrincipalId { get; set; }


        [JsonPropertyName("servicePrincipalName")]

        public string? ServicePrincipalName { get; set; }

    }


    public class TargetResource

    {
        [JsonPropertyName("id")]

        public string? Id { get; set; }


        [JsonPropertyName("displayName")]

        public string? DisplayName { get; set; }


        [JsonPropertyName("type")]

        public string? Type { get; set; }


        [JsonPropertyName("userPrincipalName")]

        public string? UserPrincipalName { get; set; }


        [JsonPropertyName("groupType")]

        public string? GroupType { get; set; }


        [JsonPropertyName("modifiedProperties")]

        public List<ModifiedProperty>? ModifiedProperties { get; set; }

    }


    public class ModifiedProperty

    {
        [JsonPropertyName("displayName")]

        public string? DisplayName { get; set; }


        [JsonPropertyName("oldValue")]

        public string? OldValue { get; set; }


        [JsonPropertyName("newValue")]

        public string? NewValue { get; set; }

    }


    public class KeyValue

    {
        [JsonPropertyName("key")]

        public string? Key { get; set; }


        [JsonPropertyName("value")]

        public string? Value { get; set; }

    }

    /// <summary>
    /// Represents a paged response from Graph API
    /// </summary>
    public class GraphPagedResponse<T>
    {
        [JsonPropertyName("@odata.context")]

        public string? Context { get; set; }


        [JsonPropertyName("@odata.nextLink")]

        public string? NextLink { get; set; }


        [JsonPropertyName("@odata.count")]

        public int? Count { get; set; }


        [JsonPropertyName("value")]

        public List<T>? Value { get; set; }

    }
}
