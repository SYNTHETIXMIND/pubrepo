
<#
.SYNOPSIS
Automates Git add, commit, and push operations with optional features for GitHub automation.

.DESCRIPTION
This script performs a sequence of Git commands: `git add .`, `git commit` with a provided message, and `git push` to a specified branch on the 'origin' remote.
It includes optional parameters to change the working directory to a repository path, specify a different branch than 'master', create and push a Git tag, use force-with-lease for pushing, and perform a dry run to preview commands without execution.
Outputs are color-coded to indicate success (green), warnings/information (yellow), and errors (red).

.PARAMETER CommitMessage
Specifies the commit message to be used for the `git commit` command. This parameter is mandatory.

.PARAMETER Branch
Specifies the branch to push to on the 'origin' remote. Defaults to 'master'.

.PARAMETER RepoPath
Specifies the file path to the Git repository where the commands should be executed. If not specified, the script runs in the current directory.

.PARAMETER TagName
Specifies a tag name to create after a successful commit and push. This is an optional parameter.

.PARAMETER TagMessage
Provides a message for an annotated tag when using the -TagName parameter. If omitted, a lightweight tag is created.

.PARAMETER ForcePush
When specified, uses `git push origin <branch> --force-with-lease` instead of a standard push. Use with caution.

.PARAMETER DryRun
When specified, the script will print the Git commands that would be executed but will not run them. Useful for testing the script logic.

.AUTHOR
Thomas Dobler
SYNTHETIXMIND LTD

.DATE
June 1, 2025

.MODIFIED
June 1, 2025 (Initial version with specified header)

.VERSION
1.0

.NOTES
Requires Git to be installed and configured in the system's PATH.
Ensure you have necessary permissions to push to the remote repository.
The `-ForcePush` option can overwrite remote history and should be used carefully.
Exit codes are used to indicate success (0) or failure (non-zero) for specific steps.

.EXAMPLE
.\P5_GitUpdate.ps1 -CommitMessage "Fix: Resolve issue with login form"
Description: Adds all changes, commits with the specified message, and pushes to the 'master' branch in the current directory.

.EXAMPLE
.\P5_GitUpdate.ps1 -CommitMessage "feat: Implement new user profile page" -Branch "develop" -RepoPath "C:\Projects\MyWebApp"
Description: Changes directory to "C:\Projects\MyWebApp", adds changes, commits, and pushes to the 'develop' branch.

.EXAMPLE
.\P5_GitUpdate.ps1 -CommitMessage "Release: Version 1.0" -TagName "v1.0" -TagMessage "Initial stable release"
Description: Adds changes, commits, pushes to 'master', creates an annotated tag 'v1.0' with the specified message, and pushes the tag.

.EXAMPLE
.\P5_GitUpdate.ps1 -CommitMessage "Test Dry Run" -DryRun -Branch "feature/test" -RepoPath "D:\Code\TestRepo"
Description: Performs a dry run. Outputs the commands that would be executed for the specified path and branch without making any changes.

#>
param(
    [Parameter(Mandatory = $true)]
    [string]$CommitMessage,

    # Optional parameters
    [string]$Branch = 'master', # Default branch is 'master'
    [string]$RepoPath, # Optional path to the Git repository
    [string]$TagName, # Optional tag name to create after push
    [string]$TagMessage = "", # Optional tag message for annotated tags
    [switch]$ForcePush, # Optional switch to force push
    [switch]$DryRun            # Optional switch for a dry run (commands are printed, not executed)
)

Write-Host "Starting Git automation..."

# Change directory if RepoPath is specified
if (-not [string]::IsNullOrEmpty($RepoPath)) {
    Write-Host "Attempting to change directory to: $RepoPath"
    try {
        Set-Location -Path $RepoPath
        Write-Host "Successfully changed directory to: $RepoPath" -ForegroundColor Green
    }
    catch {
        Write-Host "Error setting location to ${RepoPath}: $($_.Exception.Message)" -ForegroundColor Red
        exit 1 # Exit with a non-zero status code indicating failure
    }
}
else {
    Write-Host "No repository path specified. Using current directory: $(Get-Location)"
}

# Step 1: git add .
Write-Host "Executing: git add ."
if (-not $DryRun) {
    git add .
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error during git add . Exit code: $LASTEXITCODE" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    else {
        Write-Host "git add . completed." -ForegroundColor Green
    }
}
else {
    Write-Host "(Dry Run) Would execute: git add ."
}


# Step 2: git commit -m $CommitMessage
Write-Host "Executing: git commit -m '$CommitMessage'"
if (-not $DryRun) {
    # Using Invoke-Expression for more robust handling of command string and exit code
    Invoke-Expression "git commit -m '$CommitMessage'"
    $commitExitCode = $LASTEXITCODE
    if ($commitExitCode -ne 0) {
        # Git commit returns non-zero if there's nothing to commit, which might be acceptable
        # Check if the error is specifically about nothing to commit. This is a common scenario.
        # A more robust check would involve parsing the command output for specific messages.
        # For simplicity, we'll assume exit code 1 might indicate nothing to commit.
        if ($commitExitCode -eq 1) {
            Write-Host "No changes staged for commit." -ForegroundColor Yellow # Use Yellow for warnings/info about no changes
        }
        else {
            Write-Host "Error during git commit. Exit code: $commitExitCode" -ForegroundColor Red
            exit $commitExitCode
        }
    }
    else {
        Write-Host "git commit completed successfully." -ForegroundColor Green
    }
}
else {
    Write-Host "(Dry Run) Would execute: git commit -m '$CommitMessage'"
}


# Step 3: git push
$pushCommand = "git push origin $Branch"
if ($ForcePush) {
    $pushCommand = "git push origin $Branch --force-with-lease"
    Write-Host "Force push option enabled. Using: $pushCommand" -ForegroundColor Yellow # Indicate force push as a cautionary action
}
Write-Host "Executing: $pushCommand"
if (-not $DryRun) {
    Invoke-Expression $pushCommand
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error during git push. Exit code: $LASTEXITCODE" -ForegroundColor Red
        Write-Host "Please check your Git configuration, branch name ('$Branch'), and remote ('origin')." -ForegroundColor Red
        Write-Host "If this is the first push to the remote, you might need to run 'git push -u origin $Branch' manually first." -ForegroundColor Red
        exit $LASTEXITCODE
    }
    else {
        Write-Host "git push completed." -ForegroundColor Green
    }
}
else {
    Write-Host "(Dry Run) Would execute: $pushCommand"
}


# Step 4: Optional Tagging
if (-not [string]::IsNullOrEmpty($TagName)) {
    Write-Host "Tag name '$TagName' provided. Creating tag."
    $tagCommand = "git tag"
    if (-not [string]::IsNullOrEmpty($TagMessage)) {
        $tagCommand = "git tag -a '$TagName' -m '$TagMessage'"
        Write-Host "Executing: $tagCommand (Annotated Tag)"
    }
    else {
        $tagCommand = "git tag '$TagName'"
        Write-Host "Executing: $tagCommand (Lightweight Tag)"
    }

    if (-not $DryRun) {
        Invoke-Expression $tagCommand
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error creating tag '$TagName'. Exit code: $LASTEXITCODE" -ForegroundColor Red
            exit $LASTEXITCODE
        }
        else {
            Write-Host "Tag '$TagName' created successfully." -ForegroundColor Green
        }

        # Push tags
        Write-Host "Executing: git push origin --tags"
        git push origin --tags
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error pushing tags. Exit code: $LASTEXITCODE" -ForegroundColor Red
            exit $LASTEXITCODE
        }
        else {
            Write-Host "Tags pushed successfully." -ForegroundColor Green
        }

    }
    else {
        Write-Host "(Dry Run) Would execute: $tagCommand"
        Write-Host "(Dry Run) Would execute: git push origin --tags"
    }
}


Write-Host "Git automation process finished." -ForegroundColor Green

