function Show-MailboxRules {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, Position=0)]
        [string[]]$UserIds
    )

    if ($UserIds) {
        Get-MailboxRule -Identity $UserIds -ErrorAction SilentlyContinue
    } else {
        Get-MailboxRule -ErrorAction SilentlyContinue
    }
}


# Show all mailbox rules in your organization
Show-MailboxRules

# Show the mailbox rules for the users test@invictus-ir.com and HR@invictus-ir.com
Show-MailboxRules -UserIds "HR@invictus-ir.com","test@Invictus-ir.com"


function Get-MailboxRules {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, Position=0)]
        [string[]]$UserIds,

        [Parameter(Mandatory=$false)]
        [string]$OutputDir = "Output\Rules",

        [Parameter(Mandatory=$false)]
        [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
    )

    $mailboxRules = @()

    if ($UserIds) {
        foreach ($userId in $UserIds) {
            $mailboxRules += Get-MailboxRule -Identity $userId -ErrorAction SilentlyContinue
        }
    } else {
        $mailboxRules += Get-MailboxRule -ErrorAction SilentlyContinue
    }

    if ($PSCmdlet.ShouldProcess("Exporting mailbox rules to CSV", "")) {
        $csvPath = Join-Path -Path $OutputDir -ChildPath "MailboxRules.csv"
        $mailboxRules | Export-Csv -Path $csvPath -Encoding $Encoding -NoTypeInformation
        Write-Host "Mailbox rules exported to $csvPath"
    }

    $mailboxRules
}


# Get all mailbox rules in your organization
Get-MailboxRules

# Get the mailbox rules for the user test@invictus-ir.com
Get-MailboxRules -UserIds Test@Invictus-ir.com

# Get the mailbox rules for the users test@invictus-ir.com and HR@invictus-ir.com
Get-MailboxRules -UserIds "HR@invictus-ir.com","test@Invictus-ir.com"

# Export the mailbox rules to a CSV file
Get-MailboxRules -OutputDir "C:\Exports"
