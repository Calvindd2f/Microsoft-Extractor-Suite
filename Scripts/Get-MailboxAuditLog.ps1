using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

# This contains a function for getting Mailbox Audit logging

function Get-MailboxAuditLog {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium',
        DefaultParameterSetName = 'AllUsers'
    )]
    param(
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ParameterSetName = 'SingleUser',
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$UserIds,

        [Parameter(
            Mandatory = $false,
            Position = 0,
            ParameterSetName = 'AllUsers'
        )]
        [switch]$AllUsers,

        [Parameter(
            Mandatory = $false,
            Position = 1,
            ParameterSetName = 'DateRange',
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$StartDate,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = 'DateRange',
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$EndDate,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'OutputParams'
        )]
        [string]$OutputDir,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'OutputParams'
        )]
        [string]$Encoding,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'OutputParams'
        )]
        [switch]$Force,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'OutputParams'
        )]
        [switch]$WhatIf,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'OutputParams'
        )]
        [switch]$Confirm
    )]

    begin {
        if ($PSCmdlet.ParameterSetName -eq 'OutputParams') {
            if ($OutputDir) {
                if (!(Test-Path $OutputDir)) {
                    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
                }
            } else {
                $OutputDir = "Output\MailboxAuditLog"
                if (!(Test-Path $OutputDir)) {
                    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
                }
            }

            if ($Encoding) {
                $encoding = $Encoding
            } else {
                $encoding = "UTF8"
            }
        }

        $date = Get-Date -Format "yyyyMMddHHmm"
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'SingleUser') {
            $UserIds = $UserIds.Trim()
            if ($UserIds -match '\s') {
                throw 'UserIds cannot contain spaces.'
            }

            $userIdArray = $UserIds -split ','
            foreach ($userId in $userIdArray) {
                $outputFile = "$OutputDir\$($date)-mailboxAuditLog-$($userId).csv"

                if ($PSCmdlet.ShouldProcess($outputFile, 'Exporting Mailbox Audit Log')) {
                    try {
                        $result = Search-MailboxAuditlog -Identity $userId -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000 -ErrorAction Stop
                        $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $encoding -Force

                        Write-Host "##[info] Output is written to: $outputFile"
                    } catch {
                        Write-Host "##[error] Failed to export Mailbox Audit Log for user: $userId. Error: $_"
                    }
                }
            }
        } elseif ($PSCmdlet.ParameterSetName -eq 'AllUsers') {
            Get-Mailbox -ResultSize unlimited | ForEach-Object {
                $userId = $_.UserPrincipalName

                $outputFile = "$OutputDir\$($date)-mailboxAuditLog-$($userId).csv"

                if ($PSCmdlet.ShouldProcess($outputFile, 'Exporting Mailbox Audit Log')) {
                    try {
                        $result = Search-MailboxAuditlog -Identity $userId -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000 -ErrorAction Stop
                        $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $encoding -Force

                        Write-Host "##[info] Output is written to: $outputFile"
                    } catch {
                        Write-Host "##[error] Failed to export Mailbox Audit Log for user: $userId. Error: $_"
                    }
                }
            }
        } elseif ($PSCmdlet.ParameterSetName -eq 'DateRange') {
            Get-Mailbox -ResultSize unlimited | ForEach-Object {
                $userId = $_.UserPrincipalName

                $outputFile = "$OutputDir\$($date)-mailboxAuditLog-$($userId).csv"

                if ($PSCmdlet.ShouldProcess($outputFile, 'Exporting Mailbox Audit Log')) {
                    try {
                        $result = Search-MailboxAuditlog -Identity $userId -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000 -ErrorAction Stop
                        $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $encoding -Force

                        Write-Host "##[info] Output is written to: $outputFile"
                    } catch {
                        Write-Host "##[error] Failed to export Mailbox Audit Log for user: $userId. Error: $_"
                    }
                }
            }
        }
    }

    end {
        Write-Host "##[section]Finished exporting Mailbox Audit Logs."
    }
}
