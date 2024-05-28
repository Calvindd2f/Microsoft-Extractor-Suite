function Install-Module {
    [CmdletBinding()]
    param(
        [string]$ModuleName,
        [version]$ModuleVersion,
        [version]$MaximumVersion
    )

    $modulePath = Join-Path -Path $env:ProgramFiles -ChildPath "WindowsPowerShell\Modules\$ModuleName"

    if (!(Test-Path -Path $modulePath)) {
        New-Item -ItemType Directory -Path $modulePath -Force | Out-Null
    }

    $modulePath = Join-Path -Path $modulePath -ChildPath " $($ModuleVersion.Major).$($ModuleVersion.Minor)"

    if (!(Test-Path -Path $modulePath)) {
        Write-Verbose "Installing module $ModuleName version $ModuleVersion"
        try {
            Install-Module -Name $ModuleName -RequiredVersion $ModuleVersion -Force -AllowClobber -Scope CurrentUser
        } catch {
            Write-Error "Failed to install module $ModuleName version $ModuleVersion: $_"
            return $false
        }
    } else {
        $installedModuleVersion = Get-Module -Name $ModuleName -ListAvailable | Where-Object { $_.Version -eq $ModuleVersion }

        if ($installedModuleVersion) {
            Write-Verbose "Module $ModuleName version $ModuleVersion already installed"
        } else {
            Write-Verbose "Updating module $ModuleName to version $ModuleVersion"
            try {
                Update-Module -Name $ModuleName -RequiredVersion $ModuleVersion -Force -AllowClobber -Scope CurrentUser
            } catch {
                Write-Error "Failed to update module $ModuleName to version $ModuleVersion: $_"
                return $false
            }
        }
    }

    $maximumModuleVersionPath = Join-Path -Path $modulePath -ChildPath " $($MaximumVersion.Major).$($MaximumVersion.Minor)"

    if (!(Test-Path -Path $maximumModuleVersionPath)) {
        Write-Verbose "Creating directory for maximum version of module $ModuleName"
        New-Item -ItemType Directory -Path $maximumModuleVersionPath -Force | Out-Null
    }

    Write-Verbose "Module $ModuleName installed and configured successfully"
    return $true
}

$ModuleList = @(
    @{
        ModuleName = 'MicrosoftTeams'
        ModuleVersion = [version] '4.9.3'
        MaximumVersion = [version] '5.99.99999'
    },
    @{
        ModuleName = 'ExchangeOnlineManagement' # includes Defender
        ModuleVersion = [version] '3.2.0'
        MaximumVersion = [version] '3.99.99999'
    },
    @{
        ModuleName = 'Microsoft.Online.SharePoint.PowerShell' # includes OneDrive
        ModuleVersion = [version] '16.0.0'
        MaximumVersion = [version] '16.0.24322.12000'
    },
    @{
        ModuleName = 'PnP.PowerShell' # alternate for SharePoint PowerShell
        ModuleVersion = [version] '1.12.0'
        MaximumVersion = [version] '1.99.99999'
    },
    @{
        ModuleName = 'Microsoft.PowerApps.Administration.PowerShell'
        ModuleVersion = [version] '2.0.0'
        MaximumVersion = [version] '2.99.99999'
    },
    @{
        ModuleName = 'Microsoft.PowerApps.PowerShell'
        ModuleVersion = [version] '1.0.0'
        MaximumVersion = [version] '1.99.99999'
    },
    @{
        ModuleName = 'Microsoft.Graph.Authentication'
        ModuleVersion = [version] '2.0.0'
        MaximumVersion = [version] '2.15.99999'
    },
    @{
        ModuleName = 'Microsoft.Graph.Beta.Users'
        ModuleVersion = [version] '2.0.0'
        MaximumVersion = [version] '2.15.99999'
    },
    @{
        ModuleName = 'Microsoft.Graph.Beta.Groups'
        ModuleVersion = [version] '2.0.0'
        MaximumVersion = [version] '2.15.99999'
    },
    @{
        ModuleName = 'Microsoft.Graph.Beta.Identity.DirectoryManagement'
        ModuleVersion = [version] '2.0.0'
        MaximumVersion = [version] '2.15.99999'
    },
    @{
        ModuleName = 'Microsoft.Graph.Beta.Identity.Governance'
        ModuleVersion = [version] '2.0.0'
        MaximumVersion = [version] '2.15.99999'
    },
    @{
        ModuleName = 'Microsoft.Graph.Beta.Identity.SignIns'
        ModuleVersion = [version] '2.0.0'
        MaximumVersion = [version] '2.15.99999'
    },
    @{
        ModuleName = 'powershell-yaml'
        ModuleVersion = [version] '0.4.2'
        MaximumVersion = [version] '0.99.99999'
    }
)

foreach ($module in $ModuleList) {
    $moduleName = $module.ModuleName
    $moduleVersion = $module.ModuleVersion
    $maximumVersion = $module.MaximumVersion

    if (!(Get-Module -Name $moduleName -ListAvailable)) {
        Install-Module -ModuleName $moduleName -ModuleVersion $moduleVersion -MaximumVersion $maximumVersion
    } else {
        $installedModuleVersion = Get-Module -Name $moduleName -ListAvailable | Select-Object -ExpandProperty Version

        if ($installedModuleVersion -lt $moduleVersion) {
            Install-Module -ModuleName $moduleName -ModuleVersion $moduleVersion -MaximumVersion $maximumVersion
        } elseif ($installedModuleVersion -gt $maximumVersion) {
            Write-Warning "Module $moduleName is already installed at a higher version than the maximum allowed version"
        }
    }
}
