<#PSScriptInfo
.VERSION 0.1.1.0
.GUID bf533bc1-76d2-4c13-a13d-1d8946c4e190
.AUTHOR Thomas Dobler - tom@synthetixmind.com - SYNTHETIXMIND LTD
.COMPANYNAME SYNTHETIXMIND LTD - https://synthetixmind.com
.COPYRIGHT (C) 2025 by SYNTHETIXMIND LTD - All rights reserved
.TAGS Logon, Security, Cleanup, Defender, SystemMaintenance
.LICENSEURI https://synthetixmind.com
.PROJECTURI https://synthetixmind.com
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES

Change History of this Script by Schema Major.Minor.Build.Revision, only Major Versions should be used in production
Version     |Type      |Date (Y/M/D)   |User                |Note
0.0.0.1     |Build     |2025/09/07     |Thomas Dobler       |Initial creation of comprehensive logon script with security hardening, system cleanup, and performance optimization features
0.1.0.0     |Minor     |2025/09/07     |Thomas Dobler       |Added InstallLogonScript parameter and scheduled task creation functionality for automatic logon script deployment
0.1.1.0     |Build     |2025/09/07     |Thomas Dobler       |Moved InstallLogonScript parameter to top and relocated scheduled task installation to execute early in script flow
#>

# .FILENAME P5_SM_LogonScript.ps1

# Requires -Module $null
<# 
.DESCRIPTION 
 Comprehensive logon script for Windows systems that performs security hardening, system cleanup, and performance optimization. 
 The script includes desktop icon management, software updates, defender configuration, system cleanup, and optional browser cache cleaning.
#>

# Parameters - Configure these variables according to your environment
param(
    [bool]$InstallLogonScript = $true,          # Enable/disable scheduled task creation for logon script
    [bool]$FullScan = $true,                    # Enable/disable full defender scan
    [int]$DownloadRetentionDays = 30,           # Days to keep download folder files
    [int]$RetentionDays = 7,                    # Days to keep recycle bin files (empty = delete all)
    [bool]$CleanBrowserCache = $false,          # Enable/disable browser cache cleanup
    [bool]$EnablePerformanceOptimization = $true, # Enable/disable performance optimization
    [bool]$EnableNetworkSecurityCheck = $true   # Enable/disable network security validation
)

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

# Install required modules for modern Windows Update management
Install-RequiredModules -ModuleNames "PSWindowsUpdate" -Force

# Install Logon Script as Scheduled Task (if enabled)
if ($InstallLogonScript) {
    Write-Host "Installing logon script as scheduled task..." -ForegroundColor Yellow
    try {
        # Create SM folder in Task Scheduler if it doesn't exist
        $TaskFolderName = "SM"
        $TaskName = "SM_LogonScript"
        $ScriptPath = "C:\Scripts\P5_SM_LogonScript.ps1"
        
        # Create the Scripts directory if it doesn't exist
        $ScriptsDir = "C:\Scripts"
        if (-not (Test-Path $ScriptsDir)) {
            New-Item -Path $ScriptsDir -ItemType Directory -Force | Out-Null
        }
        
        # Copy this script to the Scripts directory
        $CurrentScriptPath = $MyInvocation.MyCommand.Path
        if ($CurrentScriptPath -and (Test-Path $CurrentScriptPath)) {
            Copy-Item -Path $CurrentScriptPath -Destination $ScriptPath -Force -ErrorAction SilentlyContinue
        }
        
        # Check if task folder exists, create if not
        try {
            $TaskService = New-Object -ComObject "Schedule.Service"
            $TaskService.Connect()
            $RootFolder = $TaskService.GetFolder("\")
            try {
                $SMFolder = $RootFolder.GetFolder($TaskFolderName)
            }
            catch {
                $SMFolder = $RootFolder.CreateFolder($TaskFolderName)
            }
        }
        catch {
            Write-Warning "Failed to create task folder: $_"
        }
        
        # Create scheduled task
        $TaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
        $TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
        $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Register the task
        Register-ScheduledTask -TaskName $TaskName -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -Principal $TaskPrincipal -TaskPath "\$TaskFolderName\" -Force | Out-Null
        
        Write-Host "Scheduled task '$TaskName' created successfully in folder '$TaskFolderName'" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to create scheduled task: $_"
    }
}

Write-Host "Starting comprehensive system maintenance and security hardening..." -ForegroundColor Green

try {
    # Step 1: Take snapshot of desktop icons
    Write-Host "Taking snapshot of desktop icons..." -ForegroundColor Yellow
    $IconSnapshot = (Get-ChildItem "$env:USERPROFILE\Desktop", "$env:SystemDrive\Users\Public\Desktop" -ErrorAction SilentlyContinue).FullName

    # Step 2: Upgrade Chocolatey packages
    Write-Host "Upgrading Chocolatey packages..." -ForegroundColor Yellow
    try {
        $chocoPath = Get-Command choco -ErrorAction SilentlyContinue
        if ($chocoPath) {
            Start-Process -FilePath "choco" -ArgumentList "upgrade", "all", "-y", "--acceptlicense", "--ignore-checksums" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Warning "Chocolatey upgrade failed: $_"
    }

    # Step 3: Install Windows Updates using modern approach
    Write-Host "Installing Windows Updates..." -ForegroundColor Yellow
    try {
        Import-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
        Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Write-Warning "Windows Update installation failed: $_"
    }

    # Step 4: Update PowerShell help files
    Write-Host "Updating PowerShell help files..." -ForegroundColor Yellow
    try {
        Update-Help -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "PowerShell help update failed: $_"
    }

    # Step 5: Update installed PowerShell modules
    Write-Host "Updating PowerShell modules..." -ForegroundColor Yellow
    try {
        Get-InstalledModule | Update-Module -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Module update failed: $_"
    }

    # Step 6: Remove new desktop shortcuts
    Write-Host "Cleaning new desktop shortcuts..." -ForegroundColor Yellow
    try {
        (Get-ChildItem "$env:USERPROFILE\Desktop", "$env:SystemDrive\Users\Public\Desktop" -ErrorAction SilentlyContinue).FullName | 
        Where-Object {$_ -notin $IconSnapshot} | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Desktop cleanup failed: $_"
    }

    # Step 7: Configure Windows Defender settings
    Write-Host "Configuring Windows Defender settings..." -ForegroundColor Yellow
    try {
        # Enhanced Defender configuration
        Set-MpPreference -DisableEmailScanning:$false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableRemovableDriveScanning:$false -ErrorAction SilentlyContinue
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
        Set-MpPreference -ScanOnlyIfIdleEnabled:$false -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
        Set-MpPreference -DisableRealtimeMonitoring:$false -ErrorAction SilentlyContinue

        # Force Defender into sandbox
        [Environment]::SetEnvironmentVariable("MP_FORCE_USE_SANDBOX", 1, "Machine")
    }
    catch {
        Write-Warning "Defender configuration failed: $_"
    }

    # Step 8: Configure Attack Surface Reduction Rules
    Write-Host "Configuring Attack Surface Reduction Rules..." -ForegroundColor Yellow
    try {
        $ReductionRules = @(
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block all Office applications from creating child processes
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",  # Block execution of potentially obfuscated scripts
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",  # Block Office applications from creating executable content
            "3B576869-A4EC-4529-8536-B80A7769E899",  # Block Office applications from injecting code into other processes
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",  # Block JavaScript or VBScript from launching downloaded executable content
            "D3E037E1-3EB8-44C8-A917-57927947596D",  # Block executable content from email client and webmail
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",  # Block untrusted and unsigned processes that run from USB
            "01443614-cd74-433a-b99e-2ecdc07bfc25",  # Use advanced protection against ransomware
            "c1db55ab-c21a-4637-bb3f-a12568109d35",  # Block credential stealing from the Windows local security authority subsystem
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",  # Block process creations originating from PSExec and WMI commands
            "d1e49aac-8f56-4280-b9ba-993a6d77406c",  # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",  # Block Office communication applications from creating child processes
            "26190899-1602-49e8-8b27-eb1d0a1ce869",  # Block Adobe Reader from creating child processes
            "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",  # Block persistence through WMI event subscription
            "e6db77e5-3df2-4cf1-b95a-636979351e5b"   # Block rebooting machine in Safe Mode
        )

        foreach ($Rule in $ReductionRules) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $Rule -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Warning "Attack Surface Reduction configuration failed: $_"
    }

    # Step 9: Network Security Validation
    if ($EnableNetworkSecurityCheck) {
        Write-Host "Performing network security validation..." -ForegroundColor Yellow
        try {
            # Check Windows Firewall status
            $FirewallProfiles = Get-NetFirewallProfile
            foreach ($Profile in $FirewallProfiles) {
                if ($Profile.Enabled -eq $false) {
                    Set-NetFirewallProfile -Profile $Profile.Name -Enabled True -ErrorAction SilentlyContinue
                }
            }

            # Check network adapter security settings
            $NetworkAdapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
            foreach ($Adapter in $NetworkAdapters) {
                # Disable IPv6 if not needed (optional - can be configured)
                # Disable-NetAdapterBinding -Name $Adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Warning "Network security validation failed: $_"
        }
    }

    # Step 10: Performance Optimization
    if ($EnablePerformanceOptimization) {
        Write-Host "Performing system performance optimization..." -ForegroundColor Yellow
        try {
            # Memory cleanup
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()

            # Clear system file cache
            $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
            if ($OSInfo.FreePhysicalMemory -lt 1048576) {  # Less than 1GB free
                # Clear standby memory if low on physical memory
                if (Test-Path "C:\Windows\System32\RAMMap.exe") {
                    Start-Process -FilePath "C:\Windows\System32\RAMMap.exe" -ArgumentList "-Et" -WindowStyle Hidden -ErrorAction SilentlyContinue
                }
            }

            # Optimize services (disable unnecessary services)
            $ServicesToOptimize = @("Fax", "TabletInputService", "WerSvc", "WSearch")
            foreach ($Service in $ServicesToOptimize) {
                $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
                if ($ServiceObj -and $ServiceObj.StartType -ne "Disabled") {
                    Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
                    Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            Write-Warning "Performance optimization failed: $_"
        }
    }

    # Step 11: Browser Cache Cleanup (Optional)
    if ($CleanBrowserCache) {
        Write-Host "Cleaning browser caches..." -ForegroundColor Yellow
        try {
            # Chrome cache cleanup
            $ChromePaths = @(
                "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
                "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache2\entries",
                "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies",
                "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Web Data"
            )
            foreach ($Path in $ChromePaths) {
                if (Test-Path $Path) {
                    Remove-Item -Path "$Path\*" -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

            # Firefox cache cleanup
            $FirefoxProfiles = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -ErrorAction SilentlyContinue
            foreach ($Profile in $FirefoxProfiles) {
                $CachePath = Join-Path $Profile.FullName "cache2"
                if (Test-Path $CachePath) {
                    Remove-Item -Path "$CachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

            # Edge cache cleanup
            $EdgePaths = @(
                "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
                "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies"
            )
            foreach ($Path in $EdgePaths) {
                if (Test-Path $Path) {
                    Remove-Item -Path "$Path\*" -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            Write-Warning "Browser cache cleanup failed: $_"
        }
    }

    # Step 12: Update Defender signatures
    Write-Host "Updating Windows Defender signatures..." -ForegroundColor Yellow
    try {
        Update-MpSignature -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Defender signature update failed: $_"
    }

    # Step 13: Run full scan if enabled
    if ($FullScan) {
        Write-Host "Starting Windows Defender full scan..." -ForegroundColor Yellow
        try {
            Start-MpScan -ScanType FullScan -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Defender full scan failed to start: $_"
        }
    }

    # Step 14: System cleanup with DISM
    Write-Host "Performing system cleanup with DISM..." -ForegroundColor Yellow
    try {
        Start-Process -FilePath "dism" -ArgumentList "/online", "/Cleanup-Image", "/StartComponentCleanup", "/ResetBase", "/SPSuperseded" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "DISM cleanup failed: $_"
    }

    # Step 15: Disk cleanup using cleanmgr
    Write-Host "Performing advanced disk cleanup..." -ForegroundColor Yellow
    try {
        $HKLM = [UInt32] "0x80000002"
        $strKeyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        $strValueName = "StateFlags0065"

        $subkeys = Get-ChildItem -Path "HKLM:\$strKeyPath" -Name -ErrorAction SilentlyContinue
        foreach ($subkey in $subkeys) {
            try {
                New-ItemProperty -Path "HKLM:\$strKeyPath\$subkey" -Name $strValueName -PropertyType DWord -Value 2 -ErrorAction SilentlyContinue | Out-Null
            }
            catch { }
        }

        Start-Process -FilePath "cleanmgr" -ArgumentList "/sagerun:65" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue

        foreach ($subkey in $subkeys) {
            try {
                Remove-ItemProperty -Path "HKLM:\$strKeyPath\$subkey" -Name $strValueName -ErrorAction SilentlyContinue | Out-Null
            }
            catch { }
        }
    }
    catch {
        Write-Warning "Disk cleanup failed: $_"
    }

    # Step 16: Clean Downloads folder
    if ($DownloadRetentionDays -gt 0) {
        Write-Host "Cleaning Downloads folder (older than $DownloadRetentionDays days)..." -ForegroundColor Yellow
        try {
            $DownloadsPath = "$env:USERPROFILE\Downloads"
            $CutoffDate = (Get-Date).AddDays(-$DownloadRetentionDays)
            Get-ChildItem -Path $DownloadsPath -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $CutoffDate } |
            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Downloads folder cleanup failed: $_"
        }
    }

    # Step 17: Clean Recycle Bin
    Write-Host "Cleaning Recycle Bin..." -ForegroundColor Yellow
    try {
        if ($RetentionDays -eq 0 -or $RetentionDays -eq $null) {
            # Empty entire recycle bin
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        } else {
            # Clean items older than retention period
            $Shell = New-Object -ComObject Shell.Application
            $Recycler = $Shell.NameSpace(0xa)
            foreach ($item in $Recycler.Items()) {
                try {
                    $DeletedDate = $Recycler.GetDetailsOf($item, 2) -replace "\u200f|\u200e", ""
                    $DeletedDatetime = Get-Date $DeletedDate
                    [Int]$DeletedDays = (New-TimeSpan -Start $DeletedDatetime -End $(Get-Date)).Days
                    if ($DeletedDays -ge $RetentionDays) {
                        Remove-Item -Path $item.Path -Confirm:$false -Force -Recurse -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    continue
                }
            }
        }
    }
    catch {
        Write-Warning "Recycle Bin cleanup failed: $_"
    }

    # Step 18: Reload Registry
    Write-Host "Reloading Registry..." -ForegroundColor Yellow
    try {
        Start-Process -FilePath "RUNDLL32.EXE" -ArgumentList "USER32.DLL,UpdatePerUserSystemParameters", ",1", ",True" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Registry reload failed: $_"
    }

    Write-Host "System maintenance and security hardening completed successfully!" -ForegroundColor Green

}
catch {
    Write-Error "Critical error during system maintenance: $_"
}

<#
===============================================================================
MANUAL INSTALLATION EXAMPLES - Scheduled Task Creation
===============================================================================

# Example 1: Create scheduled task manually using PowerShell
# Run the following commands in an elevated PowerShell session:

# Create the SM folder in Task Scheduler
$TaskService = New-Object -ComObject "Schedule.Service"
$TaskService.Connect()
$RootFolder = $TaskService.GetFolder("\")
try { $SMFolder = $RootFolder.GetFolder("SM") } catch { $SMFolder = $RootFolder.CreateFolder("SM") }

# Create the scheduled task
$TaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"C:\Scripts\P5_SM_LogonScript.ps1`""
$TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "SM_LogonScript" -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -Principal $TaskPrincipal -TaskPath "\SM\" -Force

# Example 2: Create scheduled task using SCHTASKS command
# Run the following command in an elevated Command Prompt:
# schtasks /create /tn "SM\SM_LogonScript" /tr "PowerShell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File \"C:\Scripts\P5_SM_LogonScript.ps1\"" /sc onlogon /ru SYSTEM /rl highest /f

# Example 3: Import task from XML (create XML file first)
# Save the following XML content as "SM_LogonScript.xml" and import:
# schtasks /create /tn "SM\SM_LogonScript" /xml "SM_LogonScript.xml" /f

# XML Content for Example 3:

<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-09-07T00:00:00</Date>
    <Author>SYNTHETIXMIND LTD</Author>
    <Description>SYNTHETIXMIND Logon Script for system maintenance and security hardening</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>PowerShell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Scripts\P5_SM_LogonScript.ps1"</Arguments>
    </Exec>
  </Actions>
</Task>


# Example 4: Remove the scheduled task
# Remove-ScheduledTask -TaskName "SM_LogonScript" -TaskPath "\SM\" -Confirm:$false

# Example 5: Check if task exists and get status
# Get-ScheduledTask -TaskName "SM_LogonScript" -TaskPath "\SM\" -ErrorAction SilentlyContinue

===============================================================================
#>

<# End of Script #>
