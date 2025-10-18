# Script to configure Git settings including user info and commit signing with GPG

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
    Log-Info "Reverting Git configuration..."
    # Check for backup
    if (Test-Path ".bkp\git_config_backup.txt") {
        Log-Info "Restoring from backup..."
        # Restore original values
        Get-Content ".bkp\git_config_backup.txt" | ForEach-Object {
            if ($_ -match '^([^=]+)=(.*)$') {
                $key = $matches[1]
                $value = $matches[2]
                if ($key -in @('user.name', 'user.email', 'user.signingkey', 'commit.gpgsign', 'core.editor', 'merge.tool', 'diff.tool')) {
                    if ($value) {
                        & git config --global $key $value
                    }
                    else {
                        & git config --global --unset $key 2>$null
                    }
                }
            }
        }
        Log-Success "Configuration restored from backup."
    }
    else {
        # Default undo behavior
        & git config --global --unset user.signingkey 2>$null
        & git config --global commit.gpgsign false
        Log-Success "Git commit signing has been disabled."
    }
    exit 0
}

# Check tools
Check-Tools

# Create backup directory if it doesn't exist
if (!(Test-Path ".bkp")) {
    New-Item -ItemType Directory -Path ".bkp" | Out-Null
}

# Backup current Git config values
Log-Info "Creating backup of current Git configuration..."
$backupFile = ".bkp\git_config_backup.txt"
"# Git config backup created on $(Get-Date)" | Out-File -FilePath $backupFile
"user.name=$(& git config --global user.name 2>$null)" | Out-File -FilePath $backupFile -Append
"user.email=$(& git config --global user.email 2>$null)" | Out-File -FilePath $backupFile -Append
"user.signingkey=$(& git config --global user.signingkey 2>$null)" | Out-File -FilePath $backupFile -Append
"commit.gpgsign=$(& git config --global commit.gpgsign 2>$null; if (!$?) { 'false' })" | Out-File -FilePath $backupFile -Append
"core.editor=$(& git config --global core.editor 2>$null)" | Out-File -FilePath $backupFile -Append
"merge.tool=$(& git config --global merge.tool 2>$null)" | Out-File -FilePath $backupFile -Append
"diff.tool=$(& git config --global diff.tool 2>$null)" | Out-File -FilePath $backupFile -Append
Log-Success "Backup created at $backupFile"

# Check if required tools are installed
if (Get-Command git -ErrorAction SilentlyContinue) {
    Log-Success "Git is installed"
}
else {
    Log-Error "Git is not installed. Please install Git first."
    exit 1
}

# Configure basic Git settings
Log-Info "Configuring basic Git settings..."

$totalQuestions = 7
$currentQuestion = 1

# Function to show progress
function Show-Progress {
    $progress = [math]::Round(($currentQuestion * 100) / $totalQuestions)
    Write-Progress -Activity "Git Configuration" -Status "Progress: $progress% ($currentQuestion/$totalQuestions)" -PercentComplete $progress
}

# Get user name
Show-Progress
$currentName = & git config --global user.name 2>$null
if ($currentName) {
    Write-Host "Current user.name: $currentName"
    $userName = Read-Host "Enter new user.name (or press Enter to keep current, '/skip' to skip)"
}
else {
    $userName = Read-Host "Enter user.name (or press Enter to skip)"
}
if ($userName -and $userName -ne '/skip') {
    & git config --global user.name $userName
    Log-Success "Set user.name to: $userName"
}
elseif ($currentName) {
    Log-Info "Kept existing user.name: $currentName"
}
else {
    Log-Info "Skipped user.name configuration"
}
$currentQuestion++

# Get user email
Show-Progress
$currentEmail = & git config --global user.email 2>$null
if ($currentEmail) {
    Write-Host "Current user.email: $currentEmail"
    $userEmail = Read-Host "Enter new user.email (or press Enter to keep current, '/skip' to skip)"
}
else {
    $userEmail = Read-Host "Enter user.email (or press Enter to skip)"
}
if ($userEmail -and $userEmail -ne '/skip') {
    & git config --global user.email $userEmail
    Log-Success "Set user.email to: $userEmail"
}
elseif ($currentEmail) {
    Log-Info "Kept existing user.email: $currentEmail"
}
else {
    Log-Info "Skipped user.email configuration"
}
$currentQuestion++

# Optional: Configure editor
Show-Progress
$currentEditor = & git config --global core.editor 2>$null
Write-Host "Configure Git editor (optional):"
Write-Host "Current core.editor: $($currentEditor ? $currentEditor : 'none')"
$editor = Read-Host "Enter editor command (e.g., notepad, code --wait) or press Enter to skip"
if ($editor -and $editor -ne '/skip') {
    & git config --global core.editor $editor
    Log-Success "Set core.editor to: $editor"
}
else {
    Log-Info "Skipped core.editor configuration"
}
$currentQuestion++

# Optional: Configure merge tool
Show-Progress
$currentMerge = & git config --global merge.tool 2>$null
Write-Host "Configure Git merge tool (optional):"
Write-Host "Current merge.tool: $($currentMerge ? $currentMerge : 'none')"
$mergeTool = Read-Host "Enter merge tool (e.g., vimdiff, meld) or press Enter to skip"
if ($mergeTool -and $mergeTool -ne '/skip') {
    & git config --global merge.tool $mergeTool
    Log-Success "Set merge.tool to: $mergeTool"
}
else {
    Log-Info "Skipped merge.tool configuration"
}
$currentQuestion++

# Optional: Configure diff tool
Show-Progress
$currentDiff = & git config --global diff.tool 2>$null
Write-Host "Configure Git diff tool (optional):"
Write-Host "Current diff.tool: $($currentDiff ? $currentDiff : 'none')"
$diffTool = Read-Host "Enter diff tool (e.g., vimdiff, meld) or press Enter to skip"
if ($diffTool -and $diffTool -ne '/skip') {
    & git config --global diff.tool $diffTool
    Log-Success "Set diff.tool to: $diffTool"
}
else {
    Log-Info "Skipped diff.tool configuration"
}
$currentQuestion++

# Now proceed with GPG signing configuration
if (Get-Command gpg -ErrorAction SilentlyContinue) {
    Log-Success "GPG is installed"
}
else {
    Log-Warning "GPG is not installed. Skipping commit signing configuration."
    Log-Success "Basic Git configuration completed."
    exit 0
}

Log-Info "Checking for existing GPG keys..."

# Check if user has GPG secret keys
$gpgKeys = & gpg --list-secret-keys --keyid-format LONG 2>$null | Select-String -Pattern '^sec' | ForEach-Object { $_.Line -split ' +' | Select-Object -Index 1 -Split '/' | Select-Object -Last 1 }

if (-not $gpgKeys) {
    Show-Progress
    Log-Warning "No existing keys found"
    $generateKey = Read-Host "Would you like to generate a new GPG key? (y/n, or press Enter to skip)"
    if ($generateKey -match '^[Yy]$') {
        Log-Info "Generating a new GPG key..."
        & gpg --full-generate-key
        # Re-check for keys after generation
        $gpgKeys = & gpg --list-secret-keys --keyid-format LONG 2>$null | Select-String -Pattern '^sec' | ForEach-Object { $_.Line -split ' +' | Select-Object -Index 1 -Split '/' | Select-Object -Last 1 }
        if (-not $gpgKeys) {
            Log-Error "Failed to generate GPG key. Exiting."
            exit 1
        }
    }
    else {
        Log-Info "Skipping GPG key generation."
        & git config --global commit.gpgsign false
        Log-Success "Git commit signing has been disabled."
        exit 0
    }
    $currentQuestion++
}

Show-Progress
Log-Info "Available GPG keys:"
$keyArray = @()
$index = 1
foreach ($key in $gpgKeys) {
    $keyInfo = & gpg --list-secret-keys --keyid-format LONG $key 2>$null | Select-String -Pattern '^uid' | Select-Object -First 1 | ForEach-Object { $_.Line -replace '^uid *', '' }
    Write-Host "$index) $key - $keyInfo"
    $keyArray += $key
    $index++
}

Write-Host "$index) Create a new GPG key"
$createNewIndex = $index
$index++
Write-Host "$index) Do not use GPG signing"

$choice = Read-Host "Select an option (enter number, or press Enter to skip)"

if (-not $choice -or $choice -eq '/skip') {
    Log-Info "Skipped GPG signing configuration."
    & git config --global commit.gpgsign false
    Log-Success "Git commit signing has been disabled."
}
elseif ([int]$choice -ge 1 -and [int]$choice -lt $createNewIndex) {
    $selectedKey = $keyArray[[int]$choice - 1]
    Log-Info "Configuring Git to sign commits with key: $selectedKey"
    & git config --global user.signingkey $selectedKey
    & git config --global commit.gpgsign true
    Log-Success "Git commit signing has been configured."
    Write-Host "Copy the following public key and add it to your GitHub account (Settings > SSH and GPG keys > New GPG key):"
    Write-Host
    & gpg --armor --export $selectedKey
    Write-Host
}
elseif ([int]$choice -eq $createNewIndex) {
    # Create new GPG key
    Log-Info "Creating a new GPG key..."
    
    # Get git user name and email as defaults
    $gitName = & git config --global user.name 2>$null
    $gitEmail = & git config --global user.email 2>$null
    
    $gpgName = Read-Host "GPG Key Name (default: $gitName, or '/skip' to skip creation)"
    if ($gpgName -eq '/skip') {
        Log-Info "Skipped GPG key creation."
        & git config --global commit.gpgsign false
        Log-Success "Git commit signing has been disabled."
        return
    }
    $gpgName = if ($gpgName) { $gpgName } else { $gitName }
    
    $gpgEmail = Read-Host "GPG Key Email (default: $gitEmail, or '/skip' to skip creation)"
    if ($gpgEmail -eq '/skip') {
        Log-Info "Skipped GPG key creation."
        & git config --global commit.gpgsign false
        Log-Success "Git commit signing has been disabled."
        return
    }
    $gpgEmail = if ($gpgEmail) { $gpgEmail } else { $gitEmail }
    
    $gpgPassphrase = Read-Host "GPG Key Passphrase (leave blank for no passphrase)" -AsSecureString
    $gpgPassphrasePlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($gpgPassphrase))
    
    # Create batch file for gpg
    $batchFile = [System.IO.Path]::GetTempFileName()
    @"
%echo Generating GPG key...
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: $gpgName
Name-Email: $gpgEmail
Expire-Date: 0
"@ | Out-File -FilePath $batchFile
    if ($gpgPassphrasePlain) {
        "Passphrase: $gpgPassphrasePlain" | Out-File -FilePath $batchFile -Append
    }
    @"
%commit
%echo GPG key generated successfully.
"@ | Out-File -FilePath $batchFile -Append
    
    # Generate the key
    & gpg --batch --generate-key $batchFile
    Remove-Item $batchFile
    
    # Get the new key ID
    $newKey = & gpg --list-secret-keys --keyid-format LONG 2>$null | Select-String -Pattern '^sec' | Select-Object -Last 1 | ForEach-Object { $_.Line -split ' +' | Select-Object -Index 1 -Split '/' | Select-Object -Last 1 }
    
    if ($newKey) {
        Log-Success "New GPG key created: $newKey"
        Log-Info "Configuring Git to sign commits with the new key..."
        & git config --global user.signingkey $newKey
        & git config --global commit.gpgsign true
        Log-Success "Git commit signing has been configured with the new key."
        Write-Host "Copy the following public key and add it to your GitHub account (Settings > SSH and GPG keys > New GPG key):"
        Write-Host
        & gpg --armor --export $newKey
        Write-Host
    }
    else {
        Log-Error "Failed to create GPG key."
        exit 1
    }
}
elseif ([int]$choice -eq $index) {
    Log-Info "Disabling Git commit signing."
    & git config --global commit.gpgsign false
    Log-Success "Git commit signing has been disabled."
}
else {
    Log-Error "Invalid choice. Exiting."
    exit 1
}

Log-Success "Git configuration completed."