<#PSScriptInfo
.VERSION 0.0.0.1
.GUID 576e8b21-7ebc-4d82-a1e2-bdd6bf67e713
.AUTHOR Thomas Dobler - support@synthetixmind.com - SYNTHETIXMIND LTD
.COMPANYNAME SYNTHETIXMIND LTD
.COPYRIGHT (C) 2025 by SYNTHETIXMIND LTD - All rights reserved
.TAGS Backup PowerShellUniversal Zip Archive
.LICENSEURI 
.PROJECTURI 
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES

Change History of this Script by Schema Major.Minor.Build.Revision,only Major Versions should be used in production
Version     |Type      |Date (Y/M/D)   |User                |Note
0.0.0.1     |New       |2025/03/06     |Thomas Dobler       |Initial creation of script to backup PowerShell Universal folders to ZIP file
#>

# .FILENAME P5_PSUniversalBackup.ps1 

# Requires -Module $null
<# 
.DESCRIPTION 
 This script creates a backup of PowerShell Universal folders and configuration files into a ZIP archive.
 The backup includes %ProgramData%\UniversalAutomation folder and %ProgramData%\PowerShellUniversal\appsettings.json file.
 The ZIP file is created with a timestamp in the filename format: SM_PS_Backup<yyyy-MM-dd>.zip
#> 

# Variable declarations
$BackupDestinationPath = "C:\Temp" # Set the path where the ZIP file will be created

# Script code
function Backup-PSUniversalFolders {
    [CmdletBinding()]
    param()

    begin {
        # Create timestamp for the zip filename
        $timestamp = Get-Date -Format "yyyy-MM-dd"
        $zipFileName = "SM_PS_Backup$timestamp.zip"
        $zipFilePath = Join-Path -Path $BackupDestinationPath -ChildPath $zipFileName

        # Define source paths to backup
        $universalAutomationPath = Join-Path -Path $env:ProgramData -ChildPath "UniversalAutomation"
        $appSettingsPath = Join-Path -Path $env:ProgramData -ChildPath "PowerShellUniversal\appsettings.json"
        
        # Create temporary folder for organizing files
        $tempFolderPath = Join-Path -Path $env:TEMP -ChildPath "PSUniversalBackup_$timestamp"
        
        # Ensure the destination directory exists
        if (-not (Test-Path -Path $BackupDestinationPath)) {
            try {
                $null = New-Item -Path $BackupDestinationPath -ItemType Directory -Force
                Write-Verbose "Created backup destination directory: $BackupDestinationPath"
            }
            catch {
                Write-Error "Failed to create backup destination directory: $_"
                return $false
            }
        }
    }

    process {
        try {
            # Create temporary directory for staging files
            if (Test-Path -Path $tempFolderPath) {
                Remove-Item -Path $tempFolderPath -Recurse -Force
            }
            $null = New-Item -Path $tempFolderPath -ItemType Directory -Force
            Write-Verbose "Created temporary directory: $tempFolderPath"

            # Check if the source paths exist
            $pathsToCheck = @($universalAutomationPath, $appSettingsPath)
            $missingPaths = $pathsToCheck | Where-Object { -not (Test-Path -Path $_) }
            
            if ($missingPaths.Count -gt 0) {
                Write-Warning "The following paths do not exist and will be skipped:"
                $missingPaths | ForEach-Object { Write-Warning "  - $_" }
            }

            # Copy UniversalAutomation folder if it exists
            if (Test-Path -Path $universalAutomationPath) {
                $universalAutomationDestination = Join-Path -Path $tempFolderPath -ChildPath "UniversalAutomation"
                $null = New-Item -Path $universalAutomationDestination -ItemType Directory -Force
                
                # Use robocopy for better handling of large directories and special files
                $robocopyArgs = @(
                    $universalAutomationPath
                    $universalAutomationDestination
                    "/E"      # Copy subdirectories, including empty ones
                    "/COPY:DAT" # Copy data, attributes, and timestamps
                    "/R:3"    # Retry 3 times
                    "/W:3"    # Wait 3 seconds between retries
                    "/NFL"    # No file listing
                    "/NDL"    # No directory listing
                    "/NJH"    # No job header
                    "/NJS"    # No job summary
                )
                
                Start-Process "robocopy.exe" -ArgumentList $robocopyArgs -NoNewWindow -Wait
                Write-Verbose "Copied UniversalAutomation folder to temporary location"
            }

            # Copy appsettings.json if it exists
            if (Test-Path -Path $appSettingsPath) {
                $appSettingsDestDir = Join-Path -Path $tempFolderPath -ChildPath "PowerShellUniversal"
                $null = New-Item -Path $appSettingsDestDir -ItemType Directory -Force
                Copy-Item -Path $appSettingsPath -Destination $appSettingsDestDir -Force
                Write-Verbose "Copied appsettings.json to temporary location"
            }

            # Create the ZIP file using .NET
            if (Test-Path -Path $zipFilePath) {
                Remove-Item -Path $zipFilePath -Force
                Write-Verbose "Removed existing ZIP file: $zipFilePath"
            }

            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::CreateFromDirectory($tempFolderPath, $zipFilePath)
            
            Write-Output "Backup completed successfully. ZIP file created at: $zipFilePath"
            
            # Return information about the backup
            $result = [PSCustomObject]@{
                BackupFile  = $zipFilePath
                CreatedOn   = (Get-Date)
                FileSize    = (Get-Item -Path $zipFilePath).Length
                FileSizeMB  = [Math]::Round((Get-Item -Path $zipFilePath).Length / 1MB, 2)
                Success     = $true
            }
            
            return $result
        }
        catch {
            Write-Error "Failed to create backup: $_"
            return [PSCustomObject]@{
                BackupFile = $null
                CreatedOn  = $null
                FileSize   = 0
                FileSizeMB = 0
                Success    = $false
                Error      = $_.Exception.Message
            }
        }
    }

    end {
        # Clean up the temporary directory
        if (Test-Path -Path $tempFolderPath) {
            Remove-Item -Path $tempFolderPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Verbose "Cleaned up temporary directory"
        }
    }
}

# Execute the backup function
$backupResult = Backup-PSUniversalFolders -Verbose
$backupResult | Format-Table -AutoSize

<# End of Script #>