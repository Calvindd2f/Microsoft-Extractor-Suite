using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Export-MailboxAuditLog {
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
        [ValidateScript({
            if ($_ -match '^\s*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*($|\s*,\s*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*)*$') {
                $true
            } else {
                throw 'UserIds must be a comma-separated list of valid email addresses.'
            }
        })]
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
        [ValidatePattern('^(\d{4})-(\d{2})-(\d{2})$')]
        [string]$StartDate,

        [Parameter(
            Mandatory = $false,
            Position = 2,
            ParameterSetName = 'DateRange',
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidatePattern('^(\d{4})-(\d{2})-(\d{2})$')]
        [string]$EndDate,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'OutputParams'
        )]
        [ValidateNotNullOrEmpty()]
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
        [switch]$Confirm,

        [Parameter()]
        [switch]$Verbose,

        [Parameter()]
        [switch]$Debug,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$LogFile,

        [Parameter()]
        [ValidateSet('Stop','Continue','Inquire')]
        [string]$ErrorAction,

        [Parameter()]
        [switch]$ErrorActionPreference,

        [Parameter()]
        [switch]$WarningActionPreference,

        [Parameter()]
        [switch]$WarningPreference,

        [Parameter()]
        [switch]$InformationActionPreference,

        [Parameter()]
        [switch]$InformationPreference,

        [Parameter()]
        [switch]$InformationVariable,

        [Parameter()]
        [switch]$VerbosePreference,

        [Parameter()]
        [switch]$VerboseVariable,

        [Parameter()]
        [switch]$DebugPreference,

        [Parameter()]
        [switch]$DebugVariable,

        [Parameter()]
        [switch]$ErrorVariable,

        [Parameter()]
        [switch]$OutVariable,

        [Parameter()]
        [switch]$OutBuffer,

        [Parameter()]
        [switch]$PipelineVariable
    )]

    begin {
        if ($PSCmdlet.ParameterSetName -eq 'OutputParams') {
            if (!(Test-Path $OutputDir)) {
                New-Item -ItemType Directory -Force -Path $OutputDir -Confirm:$Confirm | Out-Null
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
                Export-SingleUserAuditLog -Identity $userId -OutputDir $OutputDir -Encoding $encoding -StartDate $StartDate -EndDate $EndDate -WhatIf:$WhatIf
            }
        } elseif ($PSCmdlet.ParameterSetName -eq 'AllUsers') {
            Export-AllUsersAuditLog -OutputDir $OutputDir -Encoding $encoding
        } elseif ($PSCmdlet.ParameterSetName -eq 'DateRange') {
            Export-DateRangeAuditLog -OutputDir $OutputDir -Encoding $encoding -StartDate $StartDate -EndDate $EndDate
        }
    }

    end {
        Write-Host "##[section]Finished exporting Mailbox Audit Logs."
    }
}

function Export-SingleUserAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Identity,

        [Parameter(Mandatory=$true)]
        [string]$OutputDir,

        [Parameter(Mandatory=$true)]
        [string]$Encoding,

        [Parameter()]
        [string]$StartDate,

        [Parameter()]
        [string]$EndDate,

        [Parameter()]
        [switch]$WhatIf
    )

    $outputFile = "$OutputDir\$($date)-mailboxAuditLog-$($Identity).csv"

    if ($PSCmdlet.ShouldProcess($outputFile, 'Exporting Mailbox Audit Log')) {
        try {
            $result = Search-MailboxAuditlog -Identity $Identity -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000 -ErrorAction Stop
            $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $encoding -WhatIf:$WhatIf -Force

            Write-Host "##[info] Output is written to: $outputFile"
        } catch {
            Write-Host "##[error] Failed to export Mailbox Audit Log for user: $Identity. Error: $_"
        }
    }
}

function Export-AllUsersAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputDir,

        [Parameter(Mandatory=$true)]
        [string]$Encoding
    )

    Get-Mailbox -ResultSize unlimited | ForEach-Object {
        $userId = $_.UserPrincipalName

        $outputFile = "$OutputDir\$($date)-mailboxAuditLog-$($userId).csv"

        if ($PSCmdlet.ShouldProcess($outputFile, 'Exporting Mailbox Audit Log')) {
            try {
                $result = Search-MailboxAuditlog -Identity $userId -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000 -ErrorAction Stop
                $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $encoding

                Write-Host "##[info] Output is written to: $outputFile"
            } catch {
                Write-Host "##[error] Failed to export Mailbox Audit Log for user: $userId. Error: $_"
            }
        }
    }
}

function Export-DateRangeAuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputDir,

        [Parameter(Mandatory=$true)]
        [string]$Encoding,

        [Parameter(Mandatory=$true)]
        [string]$StartDate,

        [Parameter(Mandatory=$true)]
        [string]$EndDate
    )

    Get-Mailbox -ResultSize unlimited | ForEach-Object {
        $userId = $_.UserPrincipalName

        $outputFile = "$OutputDir\$($date)-mailboxAuditLog-$($userId).csv"

        if ($PSCmdlet.ShouldProcess($outputFile, 'Exporting Mailbox Audit Log')) {
            try {
                $result = Search-MailboxAuditlog -Identity $userId -LogonTypes Delegate,Admin,Owner -StartDate $StartDate -EndDate $EndDate -ShowDetails -ResultSize 250000 -ErrorAction Stop
                $result | Export-Csv -NoTypeInformation -Path $outputFile -Encoding $encoding

                Write-Host "##[info] Output is written to: $outputFile"
            } catch {
                Write-Host "##[error] Failed to export Mailbox Audit Log for user: $userId. Error: $_"
            }
        }
    }
}

function Search-MailboxAuditlog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [string]$LogonTypes,

        [Parameter(Mandatory=$false)]
        [string]$StartDate,

        [Parameter(Mandatory=$false)]
        [string]$EndDate,

        [Parameter(Mandatory=$false)]
        [switch]$ShowDetails,

        [Parameter()]
        [ValidateSet('Stop','Continue','Inquire')]
        [string]$ErrorAction,

        [Parameter()]
        [switch]$ErrorVariable
    )

    $params = @{
        Identity          = $Identity
        LogonTypes        = $LogonTypes
        StartDate         = $StartDate
        EndDate           = $EndDate
        ShowDetails       = $ShowDetails
        ResultSize        = 250000
        ErrorAction       = $ErrorAction
        ErrorVariable     = $ErrorVariable
    }

    Search-MailboxAuditLog @params
}

function Export-CsvWithEncoding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputFile,

        [Parameter(Mandatory=$true)]
        [string]$OutputFile,

        [Parameter(Mandatory=$true)]
        [string]$Encoding
    )

    Get-Content -Path $InputFile -Encoding $Encoding | Export-Csv -Path $OutputFile -NoTypeInformation
}
