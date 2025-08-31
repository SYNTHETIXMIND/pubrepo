<#PSScriptInfo
.VERSION 0.2.2.1
.GUID b8f3c4a7-9d2e-4f1b-8c5a-7e6d9f0b3c2a
.AUTHOR Thomas Dobler - tom@synthetixmind.com - SYNTHETIXMIND LTD
.COMPANYNAME SYNTHETIXMIND LTD
.COPYRIGHT (C) 2025 by SYNTHETIXMIND LTD - All rights reserved
.TAGS Chocolatey, PackageManagement, SoftwareInstallation, Automation
.LICENSEURI https://synthetixmind.com
.PROJECTURI https://synthetixmind.com
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES

Change History of this Script by Schema Major.Minor.Build.Revision, only Major Versions should be used in production
Version     |Type      |Date (Y/M/D)   |User                |Note
0.0.0.1     |Build     |2025/08/30     |Thomas Dobler       |Initial script creation with comprehensive Chocolatey helper functions for package management operations
0.0.1.0     |Build     |2025/08/30     |Thomas Dobler       |Fixed Export-ModuleMember error by removing the command as it can only be used in .psm1 modules, not .ps1 scripts
0.0.2.0     |Build     |2025/08/30     |Thomas Dobler       |Added Show-ChocoHelp function and automatic help display when script is run directly without dot-sourcing
0.0.2.1     |Revision  |2025/08/30     |Thomas Dobler       |Fixed chocolatey list command from --local-only to lo parameter in Get-ChocoInstalledPackages function
0.0.3.0     |Build     |2025/08/30     |Thomas Dobler       |Enhanced Update-ChocoPackages function with -All switch parameter instead of using PackageName 'all', improved parameter validation
0.1.0.0     |Minor     |2025/08/30     |Thomas Dobler       |Added Install-ChocoHelper function for automatic script deployment to PowerShell module folders, updated author information to SYNTHETIXMIND LTD
0.2.0.0     |Minor     |2025/08/30     |Thomas Dobler       |Converted script from .ps1 to .psm1 module format for automatic loading, added Export-ModuleMember, updated filename references
0.2.0.1     |Revision  |2025/08/30     |Thomas Dobler       |Fixed Export-ModuleMember error by removing auto-help display logic that was interfering with module import process
0.2.1.0     |Build     |2025/08/30     |Thomas Dobler       |Fixed module naming convention - changed filename from ChocoHelper.psm1 to ChocoHelper.psm1 for proper PowerShell module discovery
0.2.1.1     |Revision  |2025/08/30     |Thomas Dobler       |Enhanced Install-ChocoHelper function to always force update and replace existing installations with newest version from GitHub
0.2.1.2     |Revision  |2025/08/30     |Thomas Dobler       |Updated GitHub download URL from P5-ChocoHelper.ps1 to ChocoHelper.psm1 to match current module filename structure
0.2.1.3     |Revision  |2025/08/30     |Thomas Dobler       |Fixed GitHub URL format to include refs/heads path component to resolve 404 download errors
#>

# .FILENAME ChocoHelper.psm1

# Requires -Module $null
<# 
.DESCRIPTION 
 This script provides comprehensive PowerShell functions to support all standard Chocolatey commands with proper PowerShell inputs and outputs. 
 Functions include: Install Chocolatey, install/update/uninstall software, list packages, check for updates, get package details and install paths.
#> 

# Variable declarations
$LogPath = "C:\Temp\" # Path to the Logfile
$LogFileName = "ChocoHelper_Log" # By default, use the Name of the Script and add _Log
$LogType = "CSV" # CSV, XML or TXT
$LogRolling = "Day" # Rolling Interval for the Logfile: None, Day, Month, Year
$LogMinimumLevel = "INFO" # Minimum Loglevel to record in the Logfile
$ChocoExecutable = "choco.exe" # Chocolatey executable name
$DefaultChocoSource = "chocolatey" # Default Chocolatey source


function Write-LogFileMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory=$true)]
        [ValidateSet("DEBUG", "INFO", "WARNING", "ERROR", "FATAL", "DEB", "INF", "WAR", "ERR", "FAT")]
        [string]$Level,

        [Parameter(Mandatory=$false)]
        [hashtable]$AdditionalProperties
    )

    begin {
        $logLevels = @{
            "DEBUG" = 0; "DEB" = 0
            "INFO" = 1; "INF" = 1
            "WARNING" = 2; "WAR" = 2
            "ERROR" = 3; "ERR" = 3
            "FATAL" = 4; "FAT" = 4
        }

        # Convert full name to abbreviation
        $Level = $Level.Substring(0, 3).ToUpper()
    }

    process {
        $minimumLevel = $logLevels[$LogMinimumLevel]
        $currentLevel = $logLevels[$Level]

        if ($currentLevel -lt $minimumLevel) {
            Write-Host "Log message below minimum level: [$Level] $Message"
            return
        }

        $timestamp = Get-Date -Format "yyyy.MM.dd HH:mm:ss"

        switch ($LogRolling) {
            "Day" { $dateSuffix = "_" + (Get-Date).ToString("yyyyMMdd") }
            "Month" { $dateSuffix = "_" + (Get-Date).ToString("yyyyMM") }
            "Year" { $dateSuffix = "_" + (Get-Date).ToString("yyyy") }
            Default { $dateSuffix = "" }
        }

        $fullPath = Join-Path -Path $LogPath -ChildPath "$LogFileName$dateSuffix.$LogType"

        try {
            if (-not (Test-Path $fullPath)) {
                $null = New-Item -Path $fullPath -ItemType File -Force
                
                # Write header based on log type
                switch ($LogType) {
                    "CSV" { 
                        $header = "Timestamp,Level,Message"
                        if ($AdditionalProperties) {
                            $header += "," + ($AdditionalProperties.Keys -join ",")
                        }
                        $header | Out-File -FilePath $fullPath -Encoding utf8 
                    }
                    "XML" { 
                        '<?xml version="1.0" encoding="UTF-8"?><Logs>' | Out-File -FilePath $fullPath -Encoding utf8 
                    }
                }
            }

            $streamWriter = [System.IO.StreamWriter]::new($fullPath, $true, [System.Text.Encoding]::UTF8)

            switch ($LogType) {
                "CSV" {
                    $logEntry = "$timestamp,$Level,$Message"
                    if ($AdditionalProperties) {
                        $logEntry += "," + ($AdditionalProperties.Values -join ",")
                    }
                    $streamWriter.WriteLine($logEntry)
                }
                "XML" {
                    $xmlEntry = "<Log><Timestamp>$timestamp</Timestamp><Level>$Level</Level><Message>$Message</Message>"
                    if ($AdditionalProperties) {
                        foreach ($key in $AdditionalProperties.Keys) {
                            $xmlEntry += "<$key>$($AdditionalProperties[$key])</$key>"
                        }
                    }
                    $xmlEntry += "</Log>"
                    $streamWriter.WriteLine($xmlEntry)
                }
                "TXT" {
                    $logEntry = "[$timestamp] [$Level] $Message"
                    if ($AdditionalProperties) {
                        $logEntry += " " + ($AdditionalProperties.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " "
                    }
                    $streamWriter.WriteLine($logEntry)
                }
            }
        }
        catch {
            Write-Error "Failed to write to log file: $_"
        }
        finally {
            if ($streamWriter) {
                $streamWriter.Dispose()
            }
        }
    }
}

# Usage example:
# Write-LogFileMessage -Message "This is a test log message" -Level "INFO"
# Write-LogFileMessage -Message "This is a debug message" -Level "DEBUG" -AdditionalProperties @{User="JohnDoe"; Process="Backup"}

# Install or update the required modules
function Install-RequiredModules {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ModuleNames,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    begin {
        # Check if the script is running with elevated privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $isAdmin) {
            Write-Warning "This script is not running with elevated rights. Some operations may fail."
            if (-not $Force) {
                Write-Error "Please run the script as Administrator. Use -Force to continue anyway."
                exit
            }
        }
    }

    process {
        foreach ($ModuleName in $ModuleNames) {
            try {
                $installedModule = Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue

                if (-not $installedModule) {
                    Write-Host "Installing $ModuleName module..."
                    if ($isAdmin) {
                        Install-Module -Name $ModuleName -Force -AllowClobber -Scope AllUsers
                    } else {
                        Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
                    }
                } else {
                    $latestVersion = (Find-Module -Name $ModuleName -ErrorAction Stop).Version
                    $installedVersion = $installedModule.Version | Sort-Object -Descending | Select-Object -First 1

                    if ($latestVersion -gt $installedVersion) {
                        Write-Host "Updating $ModuleName module from $installedVersion to $latestVersion..."
                        if ($isAdmin) {
                            Update-Module -Name $ModuleName -Force -AllowClobber
                        } else {
                            Update-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
                        }
                    } else {
                        Write-Host "$ModuleName module is up to date (Version: $installedVersion)."
                    }
                }
            }
            catch {
                Write-Error "Failed to install or update $ModuleName module: $_"
                if (-not $Force) {
                    exit
                }
            }
        }
    }

    end {
        Write-Host "Module installation and update process completed."
    }
}

# Usage example:
# Install-RequiredModules -ModuleNames "Az", "AzureAD", "ExchangeOnlineManagement" -Force

# Test if Chocolatey is available
function Test-ChocolateyAvailability {
    [CmdletBinding()]
    param()
    
    begin {
        Write-LogFileMessage -Message "Testing Chocolatey availability" -Level "INFO"
    }
    
    process {
        try {
            $chocoPath = Get-Command $ChocoExecutable -ErrorAction SilentlyContinue
            if ($chocoPath) {
                $version = & $ChocoExecutable --version 2>$null
                $result = [PSCustomObject]@{
                    IsAvailable = $true
                    Path = $chocoPath.Path
                    Version = $version.Trim()
                    Status = "Available"
                }
                Write-LogFileMessage -Message "Chocolatey is available at $($chocoPath.Path) with version $version" -Level "INFO"
            } else {
                $result = [PSCustomObject]@{
                    IsAvailable = $false
                    Path = $null
                    Version = $null
                    Status = "Not Available"
                }
                Write-LogFileMessage -Message "Chocolatey is not available on this system" -Level "WARNING"
            }
            return $result
        }
        catch {
            Write-LogFileMessage -Message "Error testing Chocolatey availability: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
}

# Install Chocolatey
function Install-Chocolatey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    begin {
        Write-LogFileMessage -Message "Starting Chocolatey installation" -Level "INFO"
    }
    
    process {
        try {
            # Check if already installed
            $chocoTest = Test-ChocolateyAvailability
            if ($chocoTest.IsAvailable -and -not $Force) {
                Write-LogFileMessage -Message "Chocolatey is already installed. Use -Force to reinstall." -Level "INFO"
                return $chocoTest
            }
            
            # Check if running as administrator
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                Write-LogFileMessage -Message "Administrator rights required for Chocolatey installation" -Level "ERROR"
                throw "Administrator rights required for Chocolatey installation"
            }
            
            # Set execution policy
            Set-ExecutionPolicy Bypass -Scope Process -Force
            
            # Download and install Chocolatey
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            
            # Refresh environment variables
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            
            # Test installation
            $chocoTest = Test-ChocolateyAvailability
            if ($chocoTest.IsAvailable) {
                Write-LogFileMessage -Message "Chocolatey installed successfully" -Level "INFO"
                return $chocoTest
            } else {
                throw "Chocolatey installation failed"
            }
        }
        catch {
            Write-LogFileMessage -Message "Error installing Chocolatey: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
}

# Install a package using Chocolatey
function Install-ChocoPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PackageName,
        
        [Parameter(Mandatory=$false)]
        [string]$Version,
        
        [Parameter(Mandatory=$false)]
        [string]$Source = $DefaultChocoSource,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force,
        
        [Parameter(Mandatory=$false)]
        [switch]$IgnoreChecksums,
        
        [Parameter(Mandatory=$false)]
        [string]$InstallArguments,
        
        [Parameter(Mandatory=$false)]
        [string]$PackageParameters
    )
    
    begin {
        Write-LogFileMessage -Message "Starting installation of package: $PackageName" -Level "INFO"
    }
    
    process {
        try {
            # Test Chocolatey availability
            $chocoTest = Test-ChocolateyAvailability
            if (-not $chocoTest.IsAvailable) {
                throw "Chocolatey is not available. Please install Chocolatey first."
            }
            
            # Build command arguments
            $arguments = @("install", $PackageName, "-y", "--source", $Source)
            
            if ($Version) {
                $arguments += "--version"
                $arguments += $Version
            }
            
            if ($Force) {
                $arguments += "--force"
            }
            
            if ($IgnoreChecksums) {
                $arguments += "--ignore-checksums"
            }
            
            if ($InstallArguments) {
                $arguments += "--install-arguments"
                $arguments += "`"$InstallArguments`""
            }
            
            if ($PackageParameters) {
                $arguments += "--package-parameters"
                $arguments += "`"$PackageParameters`""
            }
            
            # Execute command
            Write-LogFileMessage -Message "Executing: choco $($arguments -join ' ')" -Level "DEBUG"
            $output = & $ChocoExecutable $arguments 2>&1
            $exitCode = $LASTEXITCODE
            
            # Parse result
            $result = [PSCustomObject]@{
                PackageName = $PackageName
                Version = $Version
                Success = ($exitCode -eq 0)
                ExitCode = $exitCode
                Output = $output -join "`n"
                Command = "choco $($arguments -join ' ')"
            }
            
            if ($result.Success) {
                Write-LogFileMessage -Message "Package $PackageName installed successfully" -Level "INFO"
            } else {
                Write-LogFileMessage -Message "Package $PackageName installation failed with exit code $exitCode" -Level "ERROR"
            }
            
            return $result
        }
        catch {
            Write-LogFileMessage -Message "Error installing package $PackageName`: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
}

# Uninstall a package using Chocolatey
function Uninstall-ChocoPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PackageName,
        
        [Parameter(Mandatory=$false)]
        [string]$Version,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force,
        
        [Parameter(Mandatory=$false)]
        [switch]$RemoveDependencies
    )
    
    begin {
        Write-LogFileMessage -Message "Starting uninstallation of package: $PackageName" -Level "INFO"
    }
    
    process {
        try {
            # Test Chocolatey availability
            $chocoTest = Test-ChocolateyAvailability
            if (-not $chocoTest.IsAvailable) {
                throw "Chocolatey is not available. Please install Chocolatey first."
            }
            
            # Build command arguments
            $arguments = @("uninstall", $PackageName, "-y")
            
            if ($Version) {
                $arguments += "--version"
                $arguments += $Version
            }
            
            if ($Force) {
                $arguments += "--force"
            }
            
            if ($RemoveDependencies) {
                $arguments += "--remove-dependencies"
            }
            
            # Execute command
            Write-LogFileMessage -Message "Executing: choco $($arguments -join ' ')" -Level "DEBUG"
            $output = & $ChocoExecutable $arguments 2>&1
            $exitCode = $LASTEXITCODE
            
            # Parse result
            $result = [PSCustomObject]@{
                PackageName = $PackageName
                Version = $Version
                Success = ($exitCode -eq 0)
                ExitCode = $exitCode
                Output = $output -join "`n"
                Command = "choco $($arguments -join ' ')"
            }
            
            if ($result.Success) {
                Write-LogFileMessage -Message "Package $PackageName uninstalled successfully" -Level "INFO"
            } else {
                Write-LogFileMessage -Message "Package $PackageName uninstallation failed with exit code $exitCode" -Level "ERROR"
            }
            
            return $result
        }
        catch {
            Write-LogFileMessage -Message "Error uninstalling package $PackageName`: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
}

# Update packages using Chocolatey
function Update-ChocoPackages {
    [CmdletBinding(DefaultParameterSetName = 'SpecificPackage')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName = 'SpecificPackage')]
        [ValidateNotNullOrEmpty()]
        [string]$PackageName,
        
        [Parameter(Mandatory=$true, ParameterSetName = 'AllPackages')]
        [switch]$All,
        
        [Parameter(Mandatory=$false)]
        [string]$Source = $DefaultChocoSource,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    begin {
        if ($All) {
            $targetPackage = "all"
            Write-LogFileMessage -Message "Starting update of all packages" -Level "INFO"
        } else {
            $targetPackage = $PackageName
            Write-LogFileMessage -Message "Starting update of package: $PackageName" -Level "INFO"
        }
    }
    
    process {
        try {
            # Test Chocolatey availability
            $chocoTest = Test-ChocolateyAvailability
            if (-not $chocoTest.IsAvailable) {
                throw "Chocolatey is not available. Please install Chocolatey first."
            }
            
            # Build command arguments
            $arguments = @("upgrade", $targetPackage, "-y", "--source", $Source)
            
            if ($Force) {
                $arguments += "--force"
            }
            
            # Execute command
            Write-LogFileMessage -Message "Executing: choco $($arguments -join ' ')" -Level "DEBUG"
            $output = & $ChocoExecutable $arguments 2>&1
            $exitCode = $LASTEXITCODE
            
            # Parse result
            $result = [PSCustomObject]@{
                PackageName = $targetPackage
                Success = ($exitCode -eq 0)
                ExitCode = $exitCode
                Output = $output -join "`n"
                Command = "choco $($arguments -join ' ')"
                UpdatedPackages = @()
            }
            
            # Parse updated packages from output
            $outputLines = $output | Where-Object { $_ -match "upgraded|updated" -and $_ -match "v\d+\.\d+" }
            foreach ($line in $outputLines) {
                if ($line -match "(\S+)\s+v([\d\.]+)\s+to\s+v([\d\.]+)") {
                    $result.UpdatedPackages += [PSCustomObject]@{
                        Name = $matches[1]
                        OldVersion = $matches[2]
                        NewVersion = $matches[3]
                    }
                }
            }
            
            if ($result.Success) {
                if ($All) {
                    Write-LogFileMessage -Message "Package update completed successfully. Updated $($result.UpdatedPackages.Count) packages." -Level "INFO"
                } else {
                    Write-LogFileMessage -Message "Package $PackageName update completed successfully." -Level "INFO"
                }
            } else {
                Write-LogFileMessage -Message "Package update failed with exit code $exitCode" -Level "ERROR"
            }
            
            return $result
        }
        catch {
            Write-LogFileMessage -Message "Error updating packages: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
}

# Get list of installed Chocolatey packages
function Get-ChocoInstalledPackages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$PackageName,
        
        [Parameter(Mandatory=$false)]
        [switch]$LocalOnly
    )
    
    begin {
        Write-LogFileMessage -Message "Getting list of installed packages" -Level "INFO"
    }
    
    process {
        try {
            # Test Chocolatey availability
            $chocoTest = Test-ChocolateyAvailability
            if (-not $chocoTest.IsAvailable) {
                throw "Chocolatey is not available. Please install Chocolatey first."
            }
            
            # Build command arguments
            $arguments = @("list", "lo")
            
            if ($PackageName) {
                $arguments += $PackageName
            }
            
            # Execute command
            Write-LogFileMessage -Message "Executing: choco $($arguments -join ' ')" -Level "DEBUG"
            $output = & $ChocoExecutable $arguments 2>&1
            $exitCode = $LASTEXITCODE
            
            if ($exitCode -ne 0) {
                throw "Chocolatey list command failed with exit code $exitCode"
            }
            
            # Parse output
            $packages = @()
            $outputLines = $output | Where-Object { $_ -match "^\S+\s+\S+" -and $_ -notmatch "packages installed|Chocolatey" }
            
            foreach ($line in $outputLines) {
                if ($line -match "^(\S+)\s+(\S+)") {
                    $packages += [PSCustomObject]@{
                        Name = $matches[1]
                        Version = $matches[2]
                        InstallDate = $null
                        InstallPath = $null
                    }
                }
            }
            
            Write-LogFileMessage -Message "Found $($packages.Count) installed packages" -Level "INFO"
            return $packages
        }
        catch {
            Write-LogFileMessage -Message "Error getting installed packages: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
}

# Get available package updates
function Get-ChocoOutdatedPackages {
    [CmdletBinding()]
    param()
    
    begin {
        Write-LogFileMessage -Message "Checking for outdated packages" -Level "INFO"
    }
    
    process {
        try {
            # Test Chocolatey availability
            $chocoTest = Test-ChocolateyAvailability
            if (-not $chocoTest.IsAvailable) {
                throw "Chocolatey is not available. Please install Chocolatey first."
            }
            
            # Execute command
            $arguments = @("outdated")
            Write-LogFileMessage -Message "Executing: choco $($arguments -join ' ')" -Level "DEBUG"
            $output = & $ChocoExecutable $arguments 2>&1
            $exitCode = $LASTEXITCODE
            
            # Parse output (outdated command returns exit code 2 when packages are outdated)
            $outdatedPackages = @()
            $outputLines = $output | Where-Object { $_ -match "^\S+\|\S+\|\S+" }
            
            foreach ($line in $outputLines) {
                if ($line -match "^([^|]+)\|([^|]+)\|([^|]+)") {
                    $outdatedPackages += [PSCustomObject]@{
                        Name = $matches[1].Trim()
                        CurrentVersion = $matches[2].Trim()
                        AvailableVersion = $matches[3].Trim()
                        UpdateAvailable = $true
                    }
                }
            }
            
            Write-LogFileMessage -Message "Found $($outdatedPackages.Count) outdated packages" -Level "INFO"
            return $outdatedPackages
        }
        catch {
            Write-LogFileMessage -Message "Error checking outdated packages: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
}

# Get detailed information about a package
function Get-ChocoPackageInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PackageName,
        
        [Parameter(Mandatory=$false)]
        [string]$Source = $DefaultChocoSource,
        
        [Parameter(Mandatory=$false)]
        [switch]$LocalOnly
    )
    
    begin {
        Write-LogFileMessage -Message "Getting information for package: $PackageName" -Level "INFO"
    }
    
    process {
        try {
            # Test Chocolatey availability
            $chocoTest = Test-ChocolateyAvailability
            if (-not $chocoTest.IsAvailable) {
                throw "Chocolatey is not available. Please install Chocolatey first."
            }
            
            # Build command arguments
            $arguments = @("info", $PackageName)
            
            if ($LocalOnly) {
                $arguments += "--local-only"
            } else {
                $arguments += "--source"
                $arguments += $Source
            }
            
            # Execute command
            Write-LogFileMessage -Message "Executing: choco $($arguments -join ' ')" -Level "DEBUG"
            $output = & $ChocoExecutable $arguments 2>&1
            $exitCode = $LASTEXITCODE
            
            if ($exitCode -ne 0) {
                throw "Package information command failed with exit code $exitCode"
            }
            
            # Parse output
            $packageInfo = [PSCustomObject]@{
                Name = $PackageName
                Version = $null
                Title = $null
                Summary = $null
                Description = $null
                Tags = @()
                InstallPath = $null
                PackageSize = $null
                DownloadCount = $null
                Source = $Source
                IsInstalled = $false
                RawOutput = $output -join "`n"
            }
            
            # Parse specific information from output
            foreach ($line in $output) {
                if ($line -match "Version:\s*(.+)") {
                    $packageInfo.Version = $matches[1].Trim()
                }
                elseif ($line -match "Title:\s*(.+)") {
                    $packageInfo.Title = $matches[1].Trim()
                }
                elseif ($line -match "Summary:\s*(.+)") {
                    $packageInfo.Summary = $matches[1].Trim()
                }
                elseif ($line -match "Description:\s*(.+)") {
                    $packageInfo.Description = $matches[1].Trim()
                }
                elseif ($line -match "Tags:\s*(.+)") {
                    $packageInfo.Tags = $matches[1].Trim() -split '\s+'
                }
                elseif ($line -match "Package Size:\s*(.+)") {
                    $packageInfo.PackageSize = $matches[1].Trim()
                }
                elseif ($line -match "Download Count:\s*(.+)") {
                    $packageInfo.DownloadCount = $matches[1].Trim()
                }
            }
            
            # Check if package is installed and get install path
            $installedPackages = Get-ChocoInstalledPackages -PackageName $PackageName
            if ($installedPackages) {
                $packageInfo.IsInstalled = $true
                # Try to get install path from Chocolatey directory
                $chocoInstallPath = "$env:ChocolateyInstall\lib\$PackageName"
                if (Test-Path $chocoInstallPath) {
                    $packageInfo.InstallPath = $chocoInstallPath
                }
            }
            
            Write-LogFileMessage -Message "Retrieved information for package $PackageName" -Level "INFO"
            return $packageInfo
        }
        catch {
            Write-LogFileMessage -Message "Error getting package information for $PackageName`: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
}

# Search for packages in Chocolatey repository
function Search-ChocoPackages {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SearchTerm,
        
        [Parameter(Mandatory=$false)]
        [string]$Source = $DefaultChocoSource,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxResults = 50
    )
    
    begin {
        Write-LogFileMessage -Message "Searching packages for term: $SearchTerm" -Level "INFO"
    }
    
    process {
        try {
            # Test Chocolatey availability
            $chocoTest = Test-ChocolateyAvailability
            if (-not $chocoTest.IsAvailable) {
                throw "Chocolatey is not available. Please install Chocolatey first."
            }
            
            # Build command arguments
            $arguments = @("search", $SearchTerm, "--source", $Source, "--limit-output")
            
            # Execute command
            Write-LogFileMessage -Message "Executing: choco $($arguments -join ' ')" -Level "DEBUG"
            $output = & $ChocoExecutable $arguments 2>&1
            $exitCode = $LASTEXITCODE
            
            if ($exitCode -ne 0) {
                throw "Package search command failed with exit code $exitCode"
            }
            
            # Parse output
            $packages = @()
            $outputLines = $output | Where-Object { $_ -match "^\S+\|\S+" } | Select-Object -First $MaxResults
            
            foreach ($line in $outputLines) {
                if ($line -match "^([^|]+)\|([^|]+)") {
                    $packages += [PSCustomObject]@{
                        Name = $matches[1].Trim()
                        Version = $matches[2].Trim()
                        Source = $Source
                        SearchTerm = $SearchTerm
                    }
                }
            }
            
            Write-LogFileMessage -Message "Found $($packages.Count) packages matching '$SearchTerm'" -Level "INFO"
            return $packages
        }
        catch {
            Write-LogFileMessage -Message "Error searching packages for '$SearchTerm': $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
}

# Get Chocolatey configuration and features
function Get-ChocoConfig {
    [CmdletBinding()]
    param()
    
    begin {
        Write-LogFileMessage -Message "Getting Chocolatey configuration" -Level "INFO"
    }
    
    process {
        try {
            # Test Chocolatey availability
            $chocoTest = Test-ChocolateyAvailability
            if (-not $chocoTest.IsAvailable) {
                throw "Chocolatey is not available. Please install Chocolatey first."
            }
            
            # Get configuration
            $configOutput = & $ChocoExecutable config list 2>&1
            $featuresOutput = & $ChocoExecutable feature list 2>&1
            
            # Parse configuration
            $config = @{}
            foreach ($line in $configOutput) {
                if ($line -match "^(\S+)\s*=\s*(.*)") {
                    $config[$matches[1]] = $matches[2]
                }
            }
            
            # Parse features
            $features = @{}
            foreach ($line in $featuresOutput) {
                if ($line -match "^(\S+)\s*\[(Enabled|Disabled)\]") {
                    $features[$matches[1]] = $matches[2] -eq "Enabled"
                }
            }
            
            $result = [PSCustomObject]@{
                Configuration = $config
                Features = $features
                ChocolateyVersion = (Test-ChocolateyAvailability).Version
                InstallPath = $env:ChocolateyInstall
            }
            
            Write-LogFileMessage -Message "Retrieved Chocolatey configuration and features" -Level "INFO"
            return $result
        }
        catch {
            Write-LogFileMessage -Message "Error getting Chocolatey configuration: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
}

# Install ChocoHelper script to PowerShell module directories
function Install-ChocoHelper {
    [CmdletBinding(DefaultParameterSetName = 'Both')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName = 'PowerShell5')]
        [switch]$PowerShell5,
        
        [Parameter(Mandatory=$true, ParameterSetName = 'PowerShell7')]
        [switch]$PowerShell7,
        
        [Parameter(Mandatory=$true, ParameterSetName = 'Both')]
        [switch]$Both = $true
    )
    
    begin {
        Write-LogFileMessage -Message "Starting ChocoHelper installation" -Level "INFO"
        
        # Define source URL and target paths
        $sourceUrl = "https://raw.githubusercontent.com/SYNTHETIXMIND/pubrepo/refs/heads/main/PowerShellScripts/ChocoHelper.psm1"
        $scriptFileName = "ChocoHelper.psm1"
        
        $installPaths = @{
            PowerShell5 = @("C:\Program Files\WindowsPowerShell\Modules\")
            PowerShell7 = @(
                "C:\Program Files\PowerShell\Modules",
                "C:\Program Files\PowerShell\7\Modules"
            )
        }
    }
    
    process {
        try {
            # Check if running with administrative privileges
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                throw "Administrator rights required to install to PowerShell module directories. Please run as Administrator."
            }
            
            # Download the script content
            Write-LogFileMessage -Message "Downloading ChocoHelper script from: $sourceUrl" -Level "INFO"
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                $webClient = New-Object System.Net.WebClient
                $scriptContent = $webClient.DownloadString($sourceUrl)
                $webClient.Dispose()
            }
            catch {
                throw "Failed to download script from GitHub: $($_.Exception.Message)"
            }
            
            if ([string]::IsNullOrEmpty($scriptContent)) {
                throw "Downloaded script content is empty"
            }
            
            $installResults = @()
            $targetVersions = @()
            
            # Determine target versions based on parameters
            if ($PowerShell5 -or $Both) {
                $targetVersions += "PowerShell5"
            }
            if ($PowerShell7 -or $Both) {
                $targetVersions += "PowerShell7"
            }
            
            foreach ($version in $targetVersions) {
                foreach ($basePath in $installPaths[$version]) {
                    try {
                        # Check if the base directory exists
                        if (-not (Test-Path $basePath)) {
                            Write-LogFileMessage -Message "Directory does not exist, skipping: $basePath" -Level "WARNING"
                            $installResults += [PSCustomObject]@{
                                Path = $basePath
                                Success = $false
                                Message = "Directory does not exist"
                                Version = $version
                            }
                            continue
                        }
                        
                        # Create ChocoHelper module directory
                        $moduleDir = Join-Path $basePath "ChocoHelper"
                        if (-not (Test-Path $moduleDir)) {
                            New-Item -Path $moduleDir -ItemType Directory -Force | Out-Null
                            Write-LogFileMessage -Message "Created module directory: $moduleDir" -Level "INFO"
                        }
                        
                        # Save the script file
                        $scriptPath = Join-Path $moduleDir $scriptFileName
                        $utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $false
                        [System.IO.File]::WriteAllText($scriptPath, $scriptContent, $utf8NoBomEncoding)
                        
                        # Verify installation
                        if (Test-Path $scriptPath) {
                            Write-LogFileMessage -Message "Successfully installed ChocoHelper to: $scriptPath" -Level "INFO"
                            $installResults += [PSCustomObject]@{
                                Path = $scriptPath
                                Success = $true
                                Message = "Installation successful"
                                Version = $version
                                FileSize = (Get-Item $scriptPath).Length
                            }
                        } else {
                            throw "File was not created successfully"
                        }
                    }
                    catch {
                        Write-LogFileMessage -Message "Failed to install to $basePath`: $($_.Exception.Message)" -Level "ERROR"
                        $installResults += [PSCustomObject]@{
                            Path = $basePath
                            Success = $false
                            Message = $_.Exception.Message
                            Version = $version
                        }
                    }
                }
            }
            
            # Create summary result
            $successCount = ($installResults | Where-Object { $_.Success }).Count
            $totalCount = $installResults.Count
            
            $summary = [PSCustomObject]@{
                TotalAttempts = $totalCount
                SuccessfulInstalls = $successCount
                FailedInstalls = $totalCount - $successCount
                InstallResults = $installResults
                SourceUrl = $sourceUrl
                ScriptFileName = $scriptFileName
                InstallationComplete = ($successCount -gt 0)
            }
            
            if ($summary.InstallationComplete) {
                Write-LogFileMessage -Message "ChocoHelper installation completed. $successCount of $totalCount installations successful." -Level "INFO"
                Write-Host ""
                Write-Host "ChocoHelper Installation Summary:" -ForegroundColor Green
                Write-Host "Successfully installed to $successCount of $totalCount locations" -ForegroundColor White
                Write-Host ""
                Write-Host "To use ChocoHelper in your PowerShell sessions:" -ForegroundColor Yellow
                Write-Host "Import-Module ChocoHelper" -ForegroundColor Gray
                Write-Host "or" -ForegroundColor White
                Write-Host ". `$((Get-Module ChocoHelper -ListAvailable).Path)" -ForegroundColor Gray
                Write-Host ""
            } else {
                Write-LogFileMessage -Message "ChocoHelper installation failed for all locations" -Level "ERROR"
            }
            
            return $summary
        }
        catch {
            Write-LogFileMessage -Message "Error during ChocoHelper installation: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    }
}

# Display help information for all available functions
function Show-ChocoHelp {
    [CmdletBinding()]
    param()
    
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "       PowerShell Chocolatey Helper Module" -ForegroundColor Yellow
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This module provides comprehensive PowerShell functions for Chocolatey package management." -ForegroundColor White
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Green
    Write-Host "  Import-Module ChocoHelper   # Import the module to load functions" -ForegroundColor Gray
    Write-Host "  Show-ChocoHelp              # Display this help information" -ForegroundColor Gray
    Write-Host ""
    Write-Host "AVAILABLE FUNCTIONS:" -ForegroundColor Green
    Write-Host ""
    
    $functions = @(
        @{
            Name = "Test-ChocolateyAvailability"
            Description = "Check if Chocolatey is installed and available"
            Example = "Test-ChocolateyAvailability"
        },
        @{
            Name = "Install-Chocolatey"
            Description = "Install Chocolatey package manager"
            Example = "Install-Chocolatey -Force"
        },
        @{
            Name = "Install-ChocoPackage"
            Description = "Install a package using Chocolatey"
            Example = "Install-ChocoPackage -PackageName 'notepadplusplus' -Force"
        },
        @{
            Name = "Uninstall-ChocoPackage"
            Description = "Uninstall a package using Chocolatey"
            Example = "Uninstall-ChocoPackage -PackageName 'notepadplusplus'"
        },
        @{
            Name = "Update-ChocoPackages"
            Description = "Update packages (specify -PackageName or use -All switch)"
            Example = "Update-ChocoPackages -All    # or    Update-ChocoPackages -PackageName 'git'"
        },
        @{
            Name = "Get-ChocoInstalledPackages"
            Description = "Get list of installed Chocolatey packages"
            Example = "Get-ChocoInstalledPackages | Format-Table"
        },
        @{
            Name = "Get-ChocoOutdatedPackages"
            Description = "Get list of packages that need updates"
            Example = "Get-ChocoOutdatedPackages | Format-Table"
        },
        @{
            Name = "Get-ChocoPackageInfo"
            Description = "Get detailed information about a package"
            Example = "Get-ChocoPackageInfo -PackageName 'git'"
        },
        @{
            Name = "Search-ChocoPackages"
            Description = "Search for packages in Chocolatey repository"
            Example = "Search-ChocoPackages -SearchTerm 'browser'"
        },
        @{
            Name = "Get-ChocoConfig"
            Description = "Get Chocolatey configuration and features"
            Example = "Get-ChocoConfig"
        },
        @{
            Name = "Install-ChocoHelper"
            Description = "Install ChocoHelper script to PowerShell module directories"
            Example = "Install-ChocoHelper -Both -SelfBootstrap    # First-time bootstrap installation"
        }
    )
    
    foreach ($func in $functions) {
        Write-Host "  $($func.Name)" -ForegroundColor Yellow
        Write-Host "    $($func.Description)" -ForegroundColor White
        Write-Host "    Example: $($func.Example)" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "QUICK START EXAMPLES:" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # 0. Install ChocoHelper to module directories (first-time setup)" -ForegroundColor Cyan
    Write-Host "  Install-ChocoHelper -Both -SelfBootstrap" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # 1. First check if Chocolatey is installed" -ForegroundColor Cyan
    Write-Host "  Test-ChocolateyAvailability" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # 2. If not installed, install Chocolatey" -ForegroundColor Cyan
    Write-Host "  Install-Chocolatey" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # 3. Install a package" -ForegroundColor Cyan
    Write-Host "  Install-ChocoPackage -PackageName 'git'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # 4. List installed packages" -ForegroundColor Cyan
    Write-Host "  Get-ChocoInstalledPackages" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # 5. Check for updates" -ForegroundColor Cyan
    Write-Host "  Get-ChocoOutdatedPackages" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # 6. Update all packages" -ForegroundColor Cyan
    Write-Host "  Update-ChocoPackages -All" -ForegroundColor Gray
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "For more information about Chocolatey, visit: https://chocolatey.org" -ForegroundColor White
    Write-Host "ChocoHelper by SYNTHETIXMIND LTD - https://synthetixmind.com" -ForegroundColor White
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
}

# Export all functions for module usage
Export-ModuleMember -Function Test-ChocolateyAvailability, Install-Chocolatey, Install-ChocoPackage, Uninstall-ChocoPackage, Update-ChocoPackages, Get-ChocoInstalledPackages, Get-ChocoOutdatedPackages, Get-ChocoPackageInfo, Search-ChocoPackages, Get-ChocoConfig, Install-ChocoHelper, Show-ChocoHelp


<# End of Script #>
