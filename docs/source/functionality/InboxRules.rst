function Get-MailboxRules {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$false, Position=0)]
        [string]$User,

        [Parameter(Mandatory=$false)]
        [string]$OutputDir = "Output\Rules",

        [Parameter(Mandatory=$false)]
        [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8,

        [Parameter(Mandatory=$false)]
        [switch]$Show,

        [Parameter(Mandatory=$false)]
        [switch]$WhatIf,

        [Parameter(Mandatory=$false)]
        [switch]$Confirm
    )

    if ($User) {
        $UserIds = @($User)
    } else {
        $UserIds = @()
    }

    $mailboxRules = @()

    foreach ($userId in $UserIds) {
        try {
            $mailboxRule = Get-MailboxRule -Identity $userId -ErrorAction Stop
            $mailboxRules += $mailboxRule
        } catch {
            Write-Warning "Error getting mailbox rule for user $userId: $_"
        }
    }

    if ($Show) {
        $mailboxRules
    } elseif ($OutputDir) {
        if (-not (Test-Path $OutputDir)) {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        }

        if ($PSCmdlet.ShouldProcess("Exporting mailbox rules to CSV", "")) {
            $csvPath = Join-Path -Path $OutputDir -ChildPath "MailboxRules.csv"
            $mailboxRules | Export-Csv -Path $csvPath -Encoding $Encoding -NoTypeInformation
            if ($WhatIf) {
                Write-Host "WhatIf: Mailbox rules would have been exported to $csvPath"
            } elseif ($Confirm) {
                Write-Host "Confirm: Are you sure you want to export mailbox rules to $csvPath?"
            } else {
                Write-Host "Mailbox rules exported to $csvPath"
            }
        }
    }

    $mailboxRules
}

# Get all mailbox rules in your organization
Get-MailboxRules

# Get the mailbox rules for the user test@invictus-ir.com
Get-MailboxRules -User test@Invictus-ir.com

# Get the mailbox rules for the users test@invictus-ir.com and HR@invictus-ir.com
Get-MailboxRules -User "HR@invictus-ir.com","test@Invictus-ir.com"

# Display the mailbox rules for the user test@invictus-ir.com
Get-MailboxRules -User test@Invictus-ir.com -Show

# Export the mailbox rules to a CSV file
Get-MailboxRules -OutputDir "C:\Exports"
