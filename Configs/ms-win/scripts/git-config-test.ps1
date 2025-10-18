# Test script to check if required tools are installed

param(
    [switch]$Undo
)

# Function to print colored messages
function Log-Info {
    param([string]$Message)
    Write-Host "[" -NoNewline
    Write-Host "INFO" -ForegroundColor Blue -NoNewline
    Write-Host "] $Message"
}

function Log-Success {
    param([string]$Message)
    Write-Host "[" -NoNewline
    Write-Host "SUCCESS" -ForegroundColor Green -NoNewline
    Write-Host "] $Message"
}

function Log-Warning {
    param([string]$Message)
    Write-Host "[" -NoNewline
    Write-Host "WARNING" -ForegroundColor Yellow -NoNewline
    Write-Host "] $Message"
}

function Log-Error {
    param([string]$Message)
    Write-Host "[" -NoNewline
    Write-Host "ERROR" -ForegroundColor Red -NoNewline
    Write-Host "] $Message"
}

function Log-Test {
    param([string]$Message)
    Write-Host "[" -NoNewline
    Write-Host "TEST MODE" -ForegroundColor Cyan -NoNewline
    Write-Host "] $Message"
}

# Function to check tools
function Check-Tools {
    Log-Info "Checking installed tools..."
    $tools = @('git', 'gpg')
    $installed = @()
    $notInstalled = @()
    foreach ($tool in $tools) {
        if (Get-Command $tool -ErrorAction SilentlyContinue) {
            $installed += $tool
        }
        else {
            $notInstalled += $tool
        }
    }
    if ($installed.Count -gt 0) {
        Log-Success "Installed tools: $($installed -join ', ')"
    }
    if ($notInstalled.Count -gt 0) {
        Log-Warning "Not installed tools: $($notInstalled -join ', ')"
        # Check if on Windows and offer Scoop
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $onWindows = $IsWindows
        }
        else {
            $onWindows = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
        }
        Log-Info "Detected OS: $(if ($onWindows) { 'Windows' } else { 'Non-Windows' })"
        if ($onWindows) {
            Log-Info "On Windows. Checking if Scoop is available for auto-installation."
            if (Get-Command scoop -ErrorAction SilentlyContinue) {
                Log-Success "Scoop is installed."
                foreach ($tool in $notInstalled) {
                    $install = Read-Host "Do you want to install $tool using Scoop? (y/n)"
                    if ($install -match '^[Yy]$') {
                        Log-Info "Installing $tool with Scoop..."
                        & scoop install $tool
                        if ($LASTEXITCODE -eq 0) {
                            Log-Success "$tool installed successfully."
                        }
                        else {
                            Log-Error "Failed to install $tool."
                        }
                    }
                }
            }
            else {
                Log-Warning "Scoop is not installed. Install Scoop first for auto-installation."
            }
        }
    }
}

# Check for undo command
if ($Undo) {
    Log-Info "Reverting Git configuration (simulated)..."
    # Check for backup
    if (Test-Path ".bkp\git_config_backup.txt") {
        Log-Info "Would restore from backup..."
        Log-Success "Configuration restored from backup (simulated)."
    }
    else {
        Log-Success "Git commit signing has been disabled (simulated)."
    }
    exit 0
}

# Simulate configuration
Log-Test "Would create backup directory: New-Item -ItemType Directory -Path .bkp"

# Simulate backup
Log-Info "Creating backup of current Git configuration (simulated)..."
Log-Test "Would create backup file: .bkp\git_config_backup.txt"
Log-Test "Would backup: user.name, user.email, user.signingkey, commit.gpgsign, core.editor, merge.tool, diff.tool"
Log-Success "Backup created at .bkp\git_config_backup.txt (simulated)"

# Simulate basic Git settings
Log-Info "Configuring basic Git settings (simulated)..."

$totalQuestions = 7
$currentQuestion = 1

# Simulate progress
function Show-Progress {
    $progress = [math]::Round(($currentQuestion * 100) / $totalQuestions)
    Write-Progress -Activity "Git Configuration (Simulated)" -Status "Progress: $progress% ($currentQuestion/$totalQuestions)" -PercentComplete $progress
}

# Simulate user name
Show-Progress
$currentName = "simulated_user"
Log-Test "Would check current user.name: $currentName"
Log-Test "Would prompt: Enter new user.name (or press Enter to keep current, '/skip' to skip)"
$userName = "test_user"
Log-Test "Simulated input: $userName"
Log-Test "Would run: git config --global user.name $userName"
Log-Success "Set user.name to: $userName (simulated)"
$currentQuestion++

# Simulate user email
Show-Progress
$currentEmail = "simulated@example.com"
Log-Test "Would check current user.email: $currentEmail"
Log-Test "Would prompt: Enter new user.email (or press Enter to keep current, '/skip' to skip)"
$userEmail = "test@example.com"
Log-Test "Simulated input: $userEmail"
Log-Test "Would run: git config --global user.email $userEmail"
Log-Success "Set user.email to: $userEmail (simulated)"
$currentQuestion++

# Simulate editor
Show-Progress
$currentEditor = "nano"
Log-Test "Would check current core.editor: $currentEditor"
Log-Test "Would prompt: Enter editor command (e.g., notepad, code --wait) or press Enter to skip"
$editor = "code --wait"
Log-Test "Simulated input: $editor"
Log-Test "Would run: git config --global core.editor $editor"
Log-Success "Set core.editor to: $editor (simulated)"
$currentQuestion++

# Simulate merge tool
Show-Progress
$currentMerge = "vimdiff"
Log-Test "Would check current merge.tool: $currentMerge"
Log-Test "Would prompt: Enter merge tool (e.g., vimdiff, meld) or press Enter to skip"
$mergeTool = "meld"
Log-Test "Simulated input: $mergeTool"
Log-Test "Would run: git config --global merge.tool $mergeTool"
Log-Success "Set merge.tool to: $mergeTool (simulated)"
$currentQuestion++

# Simulate diff tool
Show-Progress
$currentDiff = "vimdiff"
Log-Test "Would check current diff.tool: $currentDiff"
Log-Test "Would prompt: Enter diff tool (e.g., vimdiff, meld) or press Enter to skip"
$diffTool = "meld"
Log-Test "Simulated input: $diffTool"
Log-Test "Would run: git config --global diff.tool $diffTool"
Log-Success "Set diff.tool to: $diffTool (simulated)"
$currentQuestion++

# Simulate GPG
Log-Info "Checking for existing GPG keys (simulated)..."
$gpgKeys = @("simulated_key1", "simulated_key2")
if ($gpgKeys.Count -gt 0) {
    Show-Progress
    Log-Info "Available GPG keys (simulated):"
    $index = 1
    foreach ($key in $gpgKeys) {
        Log-Test "$index) $key"
        $index++
    }
    Log-Test "$index) Create a new GPG key"
    $createNewIndex = $index
    $index++
    Log-Test "$index) Do not use GPG signing"
    $choice = "1"
    Log-Test "Simulated choice: $choice"
    if ([int]$choice -ge 1 -and [int]$choice -lt $createNewIndex) {
        $selectedKey = $gpgKeys[[int]$choice - 1]
        Log-Test "Would run: git config --global user.signingkey $selectedKey"
        Log-Test "Would run: git config --global commit.gpgsign true"
        Log-Success "Git commit signing has been configured (simulated)."
        Log-Test "Would display: Copy the following public key and add it to your GitHub account (Settings > SSH and GPG keys > New GPG key):"
        Log-Test "Would run: gpg --armor --export $selectedKey"
    }
}
else {
    Log-Test "Would generate new GPG key"
    Log-Test "Would prompt for GPG name, email, passphrase"
    Log-Test "Would create GPG key"
    Log-Test "Would configure Git for signing"
}

Log-Success "Git configuration completed (simulated)."