function Get-SyntheticUserPrompt {
    <#
    .SYNOPSIS
    Generates a synthetic user prompt emulating different SOC analyst communication styles for a specified risk event.

    .DESCRIPTION
    Returns a randomized, context-rich analyst prompt based on templates commonly used by Security Operations (SOC) professionals.
    The message structure is designed to mimic human analyst interaction, supporting scenarios such as alert triage, escalation, and forensic inquiries.
    Each user message follows one of several semantic templates and corresponds to a specific communication style.

    .PARAMETER RiskName
    Specifies the name of the risk event or detection (e.g., "Impossible travel", "Unfamiliar sign-in properties").

    .PARAMETER RiskEventType
    (Optional) Specifies the event type associated with the risk (for additional context).

    .PARAMETER Username
    (Optional) The user principal associated with the risk event. Defaults to "user@contoso.com".

    .PARAMETER Tenant
    (Optional) The tenant name where the risk event occurred. Defaults to "demo.onmicrosoft.com".

    .PATTERNSTRUCTURE
    The following analyst styles are used to generate prompts, randomized for each invocation:

        Category                Template Intent                              Example Output (for Impossible travel)
        --------                ---------------                              --------------------------------------
        Alert summary           Plain factual description                     Alert triggered: Impossible travel detected for user alex.jordan@contoso.com
        Analyst inquiry         Asking for clarification or triage advice     Can you review this impossible travel detection? MFA was successful but user claims no travel.
        Incident escalation     L1–L2 escalation phrasing                     Escalating potential impossible travel between IE and US — confirm if legitimate or threat actor.
        Executive brief request SOC lead requesting summary                   Summarize the impossible travel incident for exec reporting, focus on root cause and impact.
        Forensic check          Context-driven investigation query            Cross-check this impossible travel alert against sign-in logs — same device fingerprint?

    .NOTES
    - Prompts are placeholders for the actual prompt generation workflow.
    - Templates are designed for diversity and realism.

    #TODO: Create enum/validate set for RiskEventType parameter
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RiskName,
        [Parameter()]
        [string]$RiskEventType = "",
        [Parameter()]
        [string]$Username = "user@contoso.com",
        [Parameter()]
        [string]$Tenant = "demo.onmicrosoft.com"
    )

    $templates = @(
        "Alert triggered: $RiskName detected for $Username in tenant $Tenant.",
        "Investigate this $RiskName event — determine if it's a false positive or genuine compromise.",
        "Can you classify the $RiskName detection for $Username? MFA succeeded but user claims no unusual activity.",
        "We received an Entra alert: $RiskName. Please provide triage summary and probable cause.",
        "SOC escalation: $RiskName affecting $Username. Cross-verify with sign-in logs.",
        "Draft an incident summary for the $RiskName alert and include likely remediation actions.",
        "Summarize and rate risk for $RiskName involving $Username (riskEventType: $RiskEventType).",
        "The following alert appeared under Entra ID: '$RiskName'. Provide contextual analysis.",
        "Analyst note: unusual behavior flagged — $RiskName. Check related sessions for this user.",
        "Generate an executive summary for the $RiskName detection affecting $Username."
    )

    return ($templates | Get-Random)
}
