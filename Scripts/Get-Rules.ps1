# Load required modules
. "$PSScriptRoot\Microsoft-Extractor-Suite.psm1"

# This contains functions to display or collect the inbox and transport rules.

# Gets the current date and time in the format "yyyyMMddHHmm"
$date = Get-Date -Format "yyyyMMddHHmm"

# Displays the transport rules in the organization
function Show-TransportRules {
    <#
        .SYNOPSIS
            Displays the transport rules in the organization.

        .DESCRIPTION
            Displays the transport rules in the organization.

        .EXAMPLE
            Show-TransportRules
    #>

    # Gets the transport rules from Microsoft Graph API
    $transportRules = Get-MgTransportRules

    if ($null -ne $transportRules) {
        # Displays information message
        Write-LogFile -Message "[INFO] Checking all TransportRules"

        # Loops through each transport rule
        $transportRules.Value | ForEach-Object {
            # Displays a message indicating that a transport rule is found
            [void](Write-LogFile -Message "[INFO] Found a TransportRule" -Color "Green")

            # Displays the name, created by, when changed, state, and description of the transport rule
            [void](Write-LogFile -Message "Rule Name: $($_.DisplayName)" -Color "Yellow")
            [void](Write-LogFile -Message "Rule CreatedBy: $($_.CreatedBy.Application.DisplayName)" -Color "Yellow")
            [void](Write-LogFile -Message "When Changed: $($_.CreatedBy.DateTime)" -Color "Yellow")
            [void](Write-LogFile -Message "Rule State: $($_.IsEnabled)" -Color "Yellow")
            [void](Write-LogFile -Message "Description: $($_.Description)" -Color "Yellow")
        }
    }
}

# Collects the transport rules in the organization and saves them to a CSV file
function Get-TransportRules {
    <#
        .SYNOPSIS
            Collects all transport rules in the organization and saves them to a CSV file.

        .DESCRIPTION
            Collects all transport rules in the organization and saves them to a CSV file.

        .PARAMETER OutputDir
            OutputDir is the parameter specifying the output directory.
            Default: Output\Rules

        .PARAMETER Encoding
            Encoding is the parameter specifying the encoding of the CSV output file.
            Default: UTF8

        .EXAMPLE
            Get-TransportRules
    #>

    [CmdletBinding()]
    param (
        [string]$OutputDir = "Output\Rules",
        [string]$Encoding = "UTF8"
    )

    # Validates the output directory
    if (!(Test-Path -Path $OutputDir)) {
        # Creates the output directory if it doesn't exist
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        Write-LogFile -Message "[INFO] Creating the following directory: $OutputDir"
    }

    $filename = "$($date)-TransportRules.csv"
    $outputDirectory = Join-Path $OutputDir $filename

    # Gets the transport rules from Microsoft Graph API
    $transportRules = Get-MgTransportRules

    if ($null -ne $transportRules) {
        # Creates a StreamWriter to write to the CSV file
        $streamWriter = [IO.StreamWriter]::Create($outputDirectory, $false, [Text.Utf8Encoding]::new($Encoding, $false, $true))

        try {
            # Writes the header row to the CSV file
            $streamWriter.WriteLine("Name,Description,CreatedBy,WhenChanged,State")

            # Loops through each transport rule
            $transportRules.Value | ForEach-Object {
                # Writes the properties of the transport rule to the CSV file
                $streamWriter.WriteLine("$($_.DisplayName),$($_.Description),$($_.CreatedBy.Application.DisplayName),$($_.CreatedBy.DateTime),$($_.IsEnabled)")
            }
        }
        finally {
            # Closes the StreamWriter
            $streamWriter.Dispose()
        }

        # Displays a success message
        Write-LogFile -Message "[INFO] Transport rules are collected and writen to: $outputDirectory" -Color "Green"
    }
}

# Gets the mailbox rules for the current user and saves them to a CSV file
function Get-CurrentUserMailboxRules {
    <#
        .SYNOPSIS
            Collects all the mailbox rules for the current user and saves them to a CSV file.

        .DESCRIPTION
            Collects all the mailbox rules for the current user and saves them to a CSV file.

        .EXAMPLE
            Get-CurrentUserMailboxRules
    #>

    [CmdletBinding()]
    param ()

    # Gets the mailbox rules for the current user
    $mailboxRules = Get-MgCurrentUserMailboxRules

    if ($null -ne $mailboxRules) {
        # Creates a StreamWriter to write to the CSV file
        $streamWriter = [IO.StreamWriter]::Create("Output\Rules\$($date)-TransportRules.csv", $false, [Text.Utf8Encoding]::new("UTF8", $false, $true))

        try {
            # Writes the header row to the CSV file
            $streamWriter.WriteLine("Name,Description,CreatedBy,WhenChanged,State")

            # Loops through each mailbox rule
            $mailboxRules.Value | ForEach-Object {
                # Writes the properties of the mailbox rule to the CSV file
                $streamWriter.WriteLine("$($_.DisplayName),$($_.Description),$($_.CreatedBy.Application.DisplayName),$($_.CreatedBy.DateTime),$($_.IsEnabled)")
            }
        }
        finally {
            # Closes the StreamWriter
            $streamWriter.Dispose()
        }

        # Displays a success message
        Write-LogFile -Message "[INFO] Mailbox rules are collected and writen to: Output\Rules\$($date)-TransportRules.csv" -Color "Green"
    }
}

# Displays the mailbox rules for the current user
function Show-CurrentUserMailboxRules {
    <#
        .SYNOPSIS
            Displays the mailbox rules for the current user.

        .DESCRIPTION
            Displays the mailbox rules for the current user.

        .EXAMPLE
            Show-CurrentUserMailboxRules
    #>

    # Gets the mailbox rules for the current user
    $mailboxRules = Get-MgCurrentUserMailboxRules

    if ($null -ne $mailboxRules) {
        # Displays information message
        Write-LogFile -Message "[INFO] Checking all MailboxRules"

        # Loops through each mailbox rule
        $mailboxRules.Value | ForEach-Object {
            # Displays a message indicating that a mailbox rule is found
            [void](Write-LogFile -Message "[INFO] Found a MailboxRule" -Color "Green")

            # Displays the name, created by, when changed, state, and description of the mailbox rule
            [void](Write-LogFile -Message "Rule Name: $($_.DisplayName)" -Color "Yellow")
            [void](Write-LogFile -Message "Rule CreatedBy: $($_.CreatedBy.Application.DisplayName)" -Color "Yellow")
            [void](Write-LogFile -Message "When Changed: $($_.CreatedBy.DateTime)" -Color "Yellow")
            [void](Write-LogFile -Message "Rule State: $($_.IsEnabled)" -Color "Yellow")
            [void](Write-LogFile -Message "Description: $($_.Description)" -Color "Yellow")
        }
    }
}

# Gets the mailbox rules for the specified users and saves them to a CSV file
function Get-MailboxRules {
    <#
        .SYNOPSIS
            Collects all the mailbox rules for the specified users and saves them to a CSV file.

        .DESCRIPTION
            Collects all the mailbox rules for the specified users and saves them to a CSV file.

        .PARAMETER UserIds
            UserIds is the Identity parameter specifies the Inbox rule that you want to view.

        .PARAMETER OutputDir
            OutputDir is the parameter specifying the output directory.
            Default: Output\Rules

        .PARAMETER Encoding
            Encoding is the parameter specifying the encoding of the CSV output file.
            Default: UTF8

        .EXAMPLE
            Get-mailboxRules -UserIds Test@Invictus-ir.com
            Get-mailboxRules -UserIds "HR@invictus-ir.com,Test@Invictus-ir.com"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserIds,

        [string]$OutputDir = "Output\Rules",
        [string]$Encoding = "UTF8"
    )

    # Validates the output directory
    if (!(Test-Path -Path $OutputDir)) {
        # Creates the output directory if it doesn't exist
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        Write-LogFile -Message "[INFO] Creating the following directory: $OutputDir"
    }

    $RuleList = @()

    # Splits the UserIds parameter into an array of user IDs
    $userIdsArray = $UserIds -split ","

    # Loops through each user ID
    foreach ($userId in $userIdsArray) {
        # Trims whitespace from the user ID
        $userId = $userId.Trim()

        # Gets the user object from Microsoft Graph API
        $user = Get-MgUser -UserId $userId -ErrorAction Stop

        if ($null -ne $user) {
            # Gets the mailbox rules for the user
            $inboxrule = Get-MgUserMailboxRules -UserId $user.Id -ErrorAction Stop

            if ($inboxrule) {
                # Loops through each mailbox rule
                foreach ($rule in $inboxrule.Value) {
                    $RuleList += [PSCustomObject]@{
                        UserName       = $user.Mail
                        RuleName       = $rule.Name
                        RuleEnabled    = $rule.IsEnabled
                        CopytoFolder   = $rule.CopyToFolder
                        MovetoFolder   = $rule.MoveToFolder
                        RedirectTo    = $rule.RedirectTo
                        ForwardTo     = $rule.ForwardTo
                        TextDescription = $rule.Description
                    }
                }

                # Displays a message indicating that the mailbox rules for the user are collected
                Write-LogFile -Message "[INFO] Found $($inboxrule.Value.Count) MailboxRule(s) for: $($user.Mail)..." -Color "Yellow"
                Write-LogFile -Message "[INFO] Collecting $($inboxrule.Value.Count) MailboxRule(s) for: $($user.Mail)..." -Color "Yellow"
            }
            else {
                # Displays a message indicating that no mailbox rules are found for the user
                Write-LogFile -Message "[INFO] No MailboxRules found for: $($user.Mail)" -Color "Yellow"
            }
        }
        else {
            # Displays an error message if the user is not found
            Write-LogFile -Message "[ERROR] User not found: $userId" -Color "Red"
        }
    }

    $filename = "$($date)-MailboxRules.csv"
    $outputDirectory = Join-Path $OutputDir $filename

    # Exports the mailbox rules to a CSV file
    $RuleList | Export-Csv -Path $outputDirectory -Encoding $Encoding -NoTypeInformation

    # Displays a success message
    Write-LogFile -Message "[INFO] MailboxRules rules are collected and writen to: $outputDirectory" -Color "Green"
}

# Gets the current user's mailbox rules
function Get-MgCurrentUserMailboxRules {
    $uri = "https://graph.microsoft.com/v1.0/me/mailboxRules"
    Invoke-MgGraphRequest -Method GET -Uri $uri
}

# Gets the transport rules from Microsoft Graph
function Get-MgTransportRules {
    $uri = "https://graph.microsoft.com/v1.0/policies/transportRules"
    Invoke-MgGraphRequest -Method GET -Uri $uri
}

# Gets the user object from Microsoft Graph
function Get-MgUser([string]$UserId, [switch]$ThrowIfNotFound) {
    $uri = "https://graph.microsoft.com/v1.0/users/$UserId"
    Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue

    if ($ThrowIfNotFound) {
        if ($null -eq $_) {
            throw "User not found: $UserId"
        }
    }
}

# Gets the mailbox rules for the user
function Get-MgUserMailboxRules([string]$UserId, [switch]$ThrowIfNotFound) {
    $uri = "https://graph.microsoft.com/v1.0/users/$UserId/mailboxRules"
    Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue

    if ($ThrowIfNotFound) {
        if ($null -eq $_) {
            throw "Mailbox rules not found for user: $UserId"
        }
    }
}

# Invokes a Microsoft Graph API request
function Invoke-MgGraphRequest([string]$Method, [string]$Uri, [string]$Body, [hashtable]$Headers, [string]$OutputType) {
    $headers = @{
        "Content-Type" = "application/json"
    }

    if ($Headers) {
        $headers.AddRange($Headers)
    }

    $response = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $Body

    if ($OutputType) {
        if ($OutputType -eq "Microsoft.Graph.User") {
            return [Microsoft.Graph.User]::new()
        }
        elseif ($OutputType -eq "Microsoft.Graph.TransportRule") {
            return [Microsoft.Graph.TransportRule]::new()
        }
        elseif ($OutputType -eq "Microsoft.Open.MSG.Clients.MailboxRules.MicrosoftGraph.TrustPolicy") {
            return [Microsoft.Open.MSG.Clients.MailboxRules.MicrosoftGraph.TrustPolicy]::new()
        }
    }

    return $response
}

