<#
.SYNOPSIS
    Script to configure Git settings including user info and commit signing with GPG or SSH.
.PARAMETER Undo
    Reverts Git configuration settings using the backup file if it exists.
#>

param (
    [switch]$Undo
)

#==============================================================================
# Logging Functions
#==============================================================================

function Log-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Log-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Log-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Log-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

#==============================================================================
# Helper Functions
#==============================================================================

function Check-Tools {
    Log-Info "Checking installed tools..."
    $tools = @("git", "gpg", "ssh-keygen")
    $installed = [System.Collections.ArrayList]@()
    $not_installed = [System.Collections.ArrayList]@()

    foreach ($tool in $tools) {
        if (Get-Command $tool -ErrorAction SilentlyContinue) {
            [void]$installed.Add($tool)
        }
        else {
            [void]$not_installed.Add($tool)
        }
    }

    if ($installed.Count -gt 0) {
        Log-Success "Installed tools: $($installed -join ', ')"
    }
    if ($not_installed.Count -gt 0) {
        Log-Warning "Not installed tools: $($not_installed -join ', ')"
    }
}

# Helper to get git config, returning an empty string if not set
function Get-GitConfig {
    param([string]$Key)
    try {
        # Use & to ensure we call the command
        # Redirect stderr to null
        $value = & "git" "config" "--global" $Key 2>$null

        # git config returns 1 if key is not found, 0 if found.
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrEmpty($value)) {
            return $value.Trim()
        }
    }
    catch {
        # This catch block will handle if 'git' command itself fails to run
    }
    return "" # Return empty if key not found or any error
}

# Helper to set git config with error handling
function Set-GitConfig {
    param([string]$Key, [string]$Value)
    try {
        if ([string]::IsNullOrEmpty($Value)) {
            & git config --global --unset "$Key" 2>$null
            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 5) { # code 5 is "key not found", which is fine for unset
                Log-Warning "Failed to unset git config: $Key"
            }
        } else {
            & git config --global "$Key" "$Value"
            if ($LASTEXITCODE -ne 0) {
                Log-Error "Failed to set git config $Key to $Value"
                return $false
            }
        }
        return $true
    }
    catch {
        Log-Error "Failed to set git config $Key : $($_.Exception.Message)"
        return $false
    }
}

# Helper to generate SSH key with user choice
function Generate-SSHKey-Interactive {
    param(
        [string]$Email,
        [string]$SshDir
    )

    Write-Host "`nSelect Algorithm:"
    Write-Host "1) Ed25519 (Recommended)"
    Write-Host "   - Most secure and fastest performance."
    Write-Host "   - Best for: GitHub, GitLab, AWS, and modern Linux servers."
    Write-Host "2) RSA (4096 bit)"
    Write-Host "   - Maximum compatibility (Legacy)."
    Write-Host "   - Use ONLY if the target system does not support Ed25519."

    $algoChoice = Read-Host "Choice [1 or 2]"

    if ($algoChoice -eq "2") {
        $ssh_filename = Read-Host "Enter filename for SSH key (default: id_rsa)"
        if ([string]::IsNullOrEmpty($ssh_filename)) { $ssh_filename = 'id_rsa' }
        $private_key_path = Join-Path $SshDir $ssh_filename
        $public_key_path = "${private_key_path}.pub"

        # REMOVED: -N '""' to allow ssh-keygen to ask for a passphrase interactively
        Write-Host "You will now be asked to enter a passphrase. Leave empty for no passphrase." -ForegroundColor Cyan
        ssh-keygen -t rsa -b 4096 -C "$Email" -f "$private_key_path"
    }
    else {
        # Default to Ed25519
        $ssh_filename = Read-Host "Enter filename for SSH key (default: id_ed25519)"
        if ([string]::IsNullOrEmpty($ssh_filename)) { $ssh_filename = 'id_ed25519' }
        $private_key_path = Join-Path $SshDir $ssh_filename
        $public_key_path = "${private_key_path}.pub"

        # REMOVED: -N '""' to allow ssh-keygen to ask for a passphrase interactively
        Write-Host "You will now be asked to enter a passphrase. Leave empty for no passphrase." -ForegroundColor Cyan
        ssh-keygen -t ed25519 -C "$Email" -f "$private_key_path"
    }

    return @{
        Private = $private_key_path
        Public = $public_key_path
    }
}

# Helper to save the current git config state as the new backup
function Save-Backup {
    param([string]$BackupFile)
    $content = @()
    $content += "# Git config backup created on $(Get-Date)"
    $content += "user.name=$(Get-GitConfig 'user.name')"
    $content += "user.email=$(Get-GitConfig 'user.email')"
    $content += "user.signingkey=$(Get-GitConfig 'user.signingkey')"
    $cs = Get-GitConfig 'commit.gpgsign'
    if ([string]::IsNullOrEmpty($cs)) { $cs = 'false' }
    $content += "commit.gpgsign=$cs"
    $content += "gpg.format=$(Get-GitConfig 'gpg.format')"
    $content += "core.editor=$(Get-GitConfig 'core.editor')"
    $content += "merge.tool=$(Get-GitConfig 'merge.tool')"
    $content += "diff.tool=$(Get-GitConfig 'diff.tool')"
    try {
        $content | Set-Content $BackupFile -ErrorAction Stop
        Log-Success "Backup updated at $BackupFile"
    } catch {
        Log-Error "Failed to update backup: $($_.Exception.Message)"
    }
}


function Read-BackupConfig {
    param([string]$BackupFile)
    $map = @{}
    if (Test-Path $BackupFile) {
        Get-Content $BackupFile | ForEach-Object {
            if ($_ -match '^([^#][^=]+)=(.*)$') {
                $k = $matches[1].Trim()
                $v = $matches[2].Trim()
                $map[$k] = $v
            }
        }
    }
    return $map
}

# Helper to resolve a config value using the 3-tier logic:
#   1. Live config already set  -> skip, return current live value
#   2. Missing but backup has it -> show backup value, ask to confirm
#   3. Missing from both         -> prompt user with $DefaultPrompt
# Returns the final value that should be active (whether changed or not).
function Resolve-ConfigValue {
    param(
        [string]$Key,
        [hashtable]$Backup,
        [string]$PromptNew,       # prompt text when no value exists anywhere
        [string]$FallbackDefault  # hard-coded default (e.g. "main") used only when missing everywhere
    )

    $live = Get-GitConfig $Key

    # Tier 1: already set in live config -> leave it alone
    if (-not [string]::IsNullOrEmpty($live)) {
        Log-Info "Keeping existing $Key`: $live"
        return $live
    }

    # Tier 2: missing from live but backup has it
    if ($Backup.ContainsKey($Key) -and -not [string]::IsNullOrEmpty($Backup[$Key])) {
        $bval = $Backup[$Key]
        Write-Host "`n$Key is not set. Backup has: $bval" -ForegroundColor Cyan
        $confirm = Read-Host "Restore this value? (y/n, or press Enter for yes)"
        if ([string]::IsNullOrEmpty($confirm) -or $confirm -match '^[Yy]$') {
            if (Set-GitConfig -Key $Key -Value $bval) {
                Log-Success "Restored $Key from backup: $bval"
            }
            return $bval
        } else {
            # User said no -> fall through to prompt
            Write-Host ""
        }
    }

    # Tier 3: prompt user
    $input = Read-Host $PromptNew
    if (-not [string]::IsNullOrEmpty($input) -and $input -ne "/skip") {
        if (Set-GitConfig -Key $Key -Value $input) {
            Log-Success "Set $Key to: $input"
        }
        return $input
    } elseif (-not [string]::IsNullOrEmpty($FallbackDefault)) {
        if (Set-GitConfig -Key $Key -Value $FallbackDefault) {
            Log-Success "Set $Key to default: $FallbackDefault"
        }
        return $FallbackDefault
    }

    Log-Info "Skipped $Key configuration"
    return ""
}

# Helper to show progress
$total_questions = 7
$current_question = 1
function Show-Progress {
    $progress = [int](($script:current_question * 100) / $script:total_questions)
    $bar_length = 20
    $filled = [int](($progress * $bar_length) / 100)
    $empty = $bar_length - $filled
    $bar = ("#" * $filled) + (" " * $empty)
    Write-Host "`rProgress: [$bar] $progress% ($script:current_question/$script:total_questions)" -NoNewline
}

#==============================================================================
# Undo Logic
#==============================================================================

if ($Undo) {
    Log-Info "Reverting Git configuration..."
    $backupDir = ".bkp"
    $backupFile = Join-Path $backupDir "git_config_backup.txt"

    if (Test-Path $backupFile) {
        Log-Info "Restoring from backup..."
        $validKeys = @('user.name', 'user.email', 'user.signingkey', 'commit.gpgsign', 'gpg.format', 'core.editor', 'merge.tool', 'diff.tool')

        Get-Content $backupFile | ForEach-Object {
            if ($_ -match '^([^#][^=]+)=(.*)$') {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()

                if ($validKeys -contains $key) {
                    if ([string]::IsNullOrEmpty($value) -or $value -eq '""') {
                        Set-GitConfig -Key $key -Value ""
                    }
                    else {
                        Set-GitConfig -Key $key -Value $value
                    }
                }
            }
        }
        Log-Success "Configuration restored from backup."
    }
    else {
        # Default undo behavior if no backup
        Set-GitConfig -Key "user.signingkey" -Value ""
        Set-GitConfig -Key "commit.gpgsign" -Value "false"
        Log-Success "Git commit signing has been disabled (no backup file found)."
    }
    exit 0
}

#==============================================================================
# Main Script
#==============================================================================

Check-Tools

# Create backup directory
$backupDir = ".bkp"
$backupFile = Join-Path $backupDir "git_config_backup.txt"
if (-not (Test-Path $backupDir)) {
    New-Item -Path $backupDir -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
}

# Load existing backup BEFORE we overwrite it, so we can use it as reference
$backupMap = Read-BackupConfig -BackupFile $backupFile

# Fixed Backup Section
Log-Info "Creating backup of current Git configuration..."
$backupContent = @()
$backupContent += "# Git config backup created on $(Get-Date)"
$backupContent += "user.name=$(Get-GitConfig 'user.name')"
$backupContent += "user.email=$(Get-GitConfig 'user.email')"
$backupContent += "user.signingkey=$(Get-GitConfig 'user.signingkey')"

$commitSign = Get-GitConfig 'commit.gpgsign'
if ([string]::IsNullOrEmpty($commitSign)) { $commitSign = 'false' }
$backupContent += "commit.gpgsign=$commitSign"

$backupContent += "gpg.format=$(Get-GitConfig 'gpg.format')"
$backupContent += "core.editor=$(Get-GitConfig 'core.editor')"
$backupContent += "merge.tool=$(Get-GitConfig 'merge.tool')"
$backupContent += "diff.tool=$(Get-GitConfig 'diff.tool')"

try {
    $backupContent | Set-Content $backupFile -ErrorAction Stop
    Log-Success "Backup created at $backupFile"
} catch {
    Log-Error "Failed to create backup: $($_.Exception.Message)"
}

# Check if required tools are installed
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Log-Error "Git is not installed. Please install Git first."
    exit 1
} else {
    Log-Success "Git is installed"
}

# --- Configure basic Git settings ---
Log-Info "Configuring basic Git settings..."

# Get user name
Show-Progress
$user_name = Resolve-ConfigValue -Key 'user.name' -Backup $backupMap `
    -PromptNew "`nEnter user.name (or press Enter to skip):"
$script:current_question++

# Get user email
Show-Progress
$user_email = Resolve-ConfigValue -Key 'user.email' -Backup $backupMap `
    -PromptNew "`nEnter user.email (or press Enter to skip):"
$script:current_question++

# Get default branch name
Show-Progress
Resolve-ConfigValue -Key 'init.defaultBranch' -Backup $backupMap `
    -PromptNew "`nEnter default branch name (or press Enter to use 'main'):" `
    -FallbackDefault "main" | Out-Null
$script:current_question++

# Optional: Configure editor
Show-Progress
Resolve-ConfigValue -Key 'core.editor' -Backup $backupMap `
    -PromptNew "`nEnter editor command (e.g., nano, vim, 'code --wait') or press Enter to skip:" | Out-Null
$script:current_question++

# Optional: Configure merge tool
Show-Progress
Resolve-ConfigValue -Key 'merge.tool' -Backup $backupMap `
    -PromptNew "`nEnter merge tool (e.g., vimdiff, meld) or press Enter to skip:" | Out-Null
$script:current_question++

# Optional: Configure diff tool
Show-Progress
Resolve-ConfigValue -Key 'diff.tool' -Backup $backupMap `
    -PromptNew "`nEnter diff tool (e.g., vimdiff, meld) or press Enter to skip:" | Out-Null
$script:current_question++

# --- Ask user to choose between SSH or GPG signing ---
Show-Progress
# --- Ask user to choose between SSH or GPG signing ---
Show-Progress

# Check if signing is already fully configured in live config - skip if so
$live_signingkey = Get-GitConfig 'user.signingkey'
$live_gpgsign    = Get-GitConfig 'commit.gpgsign'
$live_gpgformat  = Get-GitConfig 'gpg.format'

if (-not [string]::IsNullOrEmpty($live_signingkey) -and -not [string]::IsNullOrEmpty($live_gpgsign)) {
    Log-Info "Commit signing already configured (signingkey: $live_signingkey, gpgsign: $live_gpgsign). Skipping."
    $script:current_question++
    Write-Host ""
    Log-Success "Git configuration completed."

    Save-Backup -BackupFile $backupFile
    exit 0
}

# Check if signing config is missing from live but present in backup
if ([string]::IsNullOrEmpty($live_signingkey) -and $backupMap.ContainsKey('user.signingkey') -and -not [string]::IsNullOrEmpty($backupMap['user.signingkey'])) {
    Write-Host "`nCommit signing was previously configured." -ForegroundColor Cyan
    Write-Host "  signingkey : $($backupMap['user.signingkey'])"
    Write-Host "  gpgsign    : $($backupMap['commit.gpgsign'])"
    Write-Host "  gpg.format : $($backupMap['gpg.format'])"
    $restoreSigning = Read-Host "Restore signing config from backup? (y/n, or press Enter for yes)"
    if ([string]::IsNullOrEmpty($restoreSigning) -or $restoreSigning -match '^[Yy]$') {
        Set-GitConfig -Key 'user.signingkey' -Value $backupMap['user.signingkey']
        Set-GitConfig -Key 'commit.gpgsign'  -Value $backupMap['commit.gpgsign']
        Set-GitConfig -Key 'gpg.format'      -Value $backupMap['gpg.format']
        Log-Success "Signing configuration restored from backup."
        $script:current_question++
        Write-Host ""
        Log-Success "Git configuration completed."

        Save-Backup -BackupFile $backupFile
        exit 0
    }
    # User declined restore -> fall through to normal signing prompt
}

Write-Host "`nChoose commit signing method:"
Write-Host "1) GPG signing"
Write-Host "2) SSH signing"
Write-Host "3) No signing"
$signing_choice = Read-Host "Select an option (1-3, or press Enter to skip):"
$script:current_question++

if ([string]::IsNullOrEmpty($signing_choice) -or $signing_choice -eq "/skip" -or $signing_choice -eq "3") {
    if ($signing_choice -eq "3") {
        Log-Info "Disabling commit signing."
    } else {
        Log-Info "Skipped commit signing configuration."
    }
    Set-GitConfig -Key "commit.gpgsign" -Value "false"
    Set-GitConfig -Key "gpg.format" -Value ""
    Set-GitConfig -Key "user.signingkey" -Value ""
    Write-Host "" # Newline after progress
    Log-Success "Git configuration completed."
    Save-Backup -BackupFile $backupFile
    exit 0
}

# --- SSH Signing Logic (From Script 2 - Correctly uses private key) ---
elseif ($signing_choice -eq "2") {
    Log-Info "Configuring SSH signing..."
    $ssh_dir = Join-Path $HOME ".ssh"
    if (-not (Test-Path $ssh_dir)) {
        New-Item -Path $ssh_dir -ItemType Directory | Out-Null
    }

    # List existing SSH keys
    $ssh_keys = [System.Collections.ArrayList]@()
    if (Test-Path $ssh_dir) {
        Get-ChildItem -Path $ssh_dir -Filter "*.pub" | ForEach-Object {
            $private_key_path = $_.FullName.Replace('.pub', '')
            if ((Test-Path $private_key_path) -and ($_.FullName -ne $private_key_path)) {
                [void]$ssh_keys.Add($_.FullName)
            }
        }
    }

    if ($ssh_keys.Count -eq 0) {
        Log-Warning "`nNo existing SSH keys found"
        $generate_ssh_key = Read-Host "Would you like to generate a new SSH key? (y/n, or press Enter to skip)"
        if ($generate_ssh_key -match '^[Yy]$') {
            Log-Info "Generating a new SSH key..."
            $git_email = Get-GitConfig 'user.email'
            $ssh_email = Read-Host "Enter email for SSH key (default: $git_email)"
            if ([string]::IsNullOrEmpty($ssh_email)) { $ssh_email = $git_email }

            # Use Helper Function
            $new_key_paths = Generate-SSHKey-Interactive -Email $ssh_email -SshDir $ssh_dir
            $private_key_path = $new_key_paths.Private
            $public_key_path = $new_key_paths.Public

            if (Test-Path $public_key_path) {
                [void]$ssh_keys.Add($public_key_path)
                Log-Success "SSH key generated successfully"
            } else {
                Log-Error "Failed to generate SSH key"
                exit 1
            }
        } else {
            Log-Info "Skipping SSH signing configuration."
            Set-GitConfig -Key "commit.gpgsign" -Value "false"
            Write-Host "" # Newline after progress
            Log-Success "Git configuration completed."
            Save-Backup -BackupFile $backupFile
            exit 0
        }
    }

    Log-Info "`nAvailable SSH keys:"
    $index = 1
    $key_map = @{}
    foreach ($key_file in $ssh_keys) {
        $key_basename = [System.IO.Path]::GetFileName($key_file)
        $key_content = Get-Content $key_file -ErrorAction SilentlyContinue | Select-Object -First 1
        Write-Host "$index) $key_basename - $key_content"
        $key_map[$index] = $key_file
        $index++
    }

    $create_new_index = $index
    Write-Host "$create_new_index) Create a new SSH key"
    $index++
    $cancel_index = $index
    Write-Host "$cancel_index) Cancel SSH signing"

    $ssh_choice_str = Read-Host "Select an option (enter number):"
    [int]$ssh_choice = 0
    [int]::TryParse($ssh_choice_str, [ref]$ssh_choice) | Out-Null

    if ([string]::IsNullOrEmpty($ssh_choice_str) -or $ssh_choice_str -eq "/skip") {
        Log-Info "Skipped SSH signing configuration."
        Set-GitConfig -Key "commit.gpgsign" -Value "false"
    }
    elseif ($key_map.ContainsKey($ssh_choice)) {
        $selected_ssh_key_pub = $key_map[$ssh_choice]
        $private_ssh_key = $selected_ssh_key_pub.Replace('.pub', '') # Get private key path
        $key_basename = [System.IO.Path]::GetFileName($selected_ssh_key_pub)
        Log-Info "Configuring Git to sign commits with SSH key: $key_basename"

        Set-GitConfig -Key "gpg.format" -Value "ssh"
        Set-GitConfig -Key "user.signingkey" -Value $private_ssh_key # FIXED: Use private key path
        Set-GitConfig -Key "commit.gpgsign" -Value "true"
        Log-Success "Git commit signing has been configured with SSH."

        Write-Host ""
        Log-Info "SSH Key Paths:"
        Write-Host "  Private key: $private_ssh_key"
        Write-Host "  Public key:  $selected_ssh_key_pub"
        Write-Host ""
        Write-Host "Copy the following public key and add it to your GitHub account (Settings > SSH and GPG keys > New SSH key > Signing Key):"
        Write-Host ""
        Get-Content "$selected_ssh_key_pub"
        Write-Host ""
    }
    elseif ($ssh_choice -eq $create_new_index) {
        # Create new SSH key
        Log-Info "Creating a new SSH key..."
        $git_email = Get-GitConfig 'user.email'
        $ssh_email = Read-Host "Enter email for SSH key (default: $git_email)"
        if ([string]::IsNullOrEmpty($ssh_email)) { $ssh_email = $git_email }

        # Use Helper Function
        $new_key_paths = Generate-SSHKey-Interactive -Email $ssh_email -SshDir $ssh_dir
        $private_key_path = $new_key_paths.Private
        $public_key_path = $new_key_paths.Public

        if (Test-Path $public_key_path) {
            Log-Success "SSH key created successfully"
            Log-Info "Configuring Git to sign commits with the new SSH key..."
            Set-GitConfig -Key "gpg.format" -Value "ssh"
            Set-GitConfig -Key "user.signingkey" -Value $private_key_path # FIXED: Use private key path
            Set-GitConfig -Key "commit.gpgsign" -Value "true"
            Log-Success "Git commit signing has been configured with SSH."

            Write-Host ""
            Log-Info "SSH Key Paths:"
            Write-Host "  Private key: $private_key_path"
            Write-Host "  Public key:  $public_key_path"
            Write-Host ""
            Write-Host "Copy the following public key and add it to your GitHub account (Settings > SSH and GPG keys > New SSH key > Signing Key):"
            Write-Host ""
            Get-Content "$public_key_path"
            Write-Host ""
        } else {
            Log-Error "Failed to create SSH key"
            exit 1
        }
    }
    else {
        Log-Info "Cancelled SSH signing configuration."
        Set-GitConfig -Key "commit.gpgsign" -Value "false"
    }
}

# --- GPG Signing Logic (Secure generation from Script 1) ---
elseif ($signing_choice -eq "1") {
    if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) {
        Log-Warning "GPG is not installed. Skipping commit signing configuration."
        Write-Host "" # Newline after progress
        Log-Success "Basic Git configuration completed."
        Save-Backup -BackupFile $backupFile
        exit 0
    }
    Log-Success "GPG is installed"
    Log-Info "Checking for existing GPG keys..."

    # Check for GPG secret keys
    $gpg_keys_output = $(gpg --list-secret-keys --keyid-format LONG 2>$null)
    $gpg_keys = [System.Collections.ArrayList]@()
    $gpg_keys_output | ForEach-Object {
        if ($_ -match '^sec.*\/([A-F0-9]+)') {
            [void]$gpg_keys.Add($matches[1])
        }
    }

    if ($gpg_keys.Count -eq 0) {
        Log-Warning "`nNo existing keys found"
        $generate_key = Read-Host "Would you like to generate a new GPG key? (y/n, or press Enter to skip)"
        if ($generate_key -match '^[Yy]$') {
            Log-Info "Generating a new GPG key (this will be interactive)..."
            gpg --full-generate-key # Interactive

            # Re-check for keys
            $gpg_keys_output = $(gpg --list-secret-keys --keyid-format LONG 2>$null)
            $gpg_keys.Clear()
            $gpg_keys_output | ForEach-Object {
                if ($_ -match '^sec.*\/([A-F0-9]+)') {
                    [void]$gpg_keys.Add($matches[1])
                }
            }
            if ($gpg_keys.Count -eq 0) {
                Log-Error "Failed to generate GPG key. Exiting."
                exit 1
            }
        } else {
            Log-Info "Skipping GPG key generation."
            Set-GitConfig -Key "commit.gpgsign" -Value "false"
            Write-Host "" # Newline after progress
            Log-Success "Git commit signing has been disabled."
            Save-Backup -BackupFile $backupFile
            exit 0
        }
    }

    Log-Info "`nAvailable GPG keys:"
    $key_array = [System.Collections.ArrayList]@()
    $index = 1
    $key_map = @{}
    foreach ($key in $gpg_keys) {
        $key_info_output = $(gpg --list-secret-keys --keyid-format LONG $key 2>$null)
        $key_info = ""
        foreach($line in $key_info_output) {
            if ($line -match '^uid\s+(.*)') {
                $key_info = $matches[1].Trim()
                break # Emulate head -1
            }
        }
        Write-Host "$index) $key - $key_info"
        [void]$key_array.Add($key)
        $key_map[$index] = $key
        $index++
    }

    $create_new_index = $index
    Write-Host "$create_new_index) Create a new GPG key (non-interactive)"
    $index++
    $cancel_index = $index
    Write-Host "$cancel_index) Do not use GPG signing"

    $choice_str = Read-Host "Select an option (enter number, or press Enter to skip):"
    [int]$choice = 0
    [int]::TryParse($choice_str, [ref]$choice) | Out-Null

    if ([string]::IsNullOrEmpty($choice_str) -or $choice_str -eq "/skip") {
        Log-Info "Skipped GPG signing configuration."
        Set-GitConfig -Key "commit.gpgsign" -Value "false"
        Log-Success "Git commit signing has been disabled."
    }
    elseif ($key_map.ContainsKey($choice)) {
        $selected_key = $key_map[$choice]
        Log-Info "Configuring Git to sign commits with key: $selected_key"
        Set-GitConfig -Key "user.signingkey" $selected_key
        Set-GitConfig -Key "commit.gpgsign" "true"
        Set-GitConfig -Key "gpg.format" "openpgp" # Explicitly set format
        Log-Success "Git commit signing has been configured."
        Write-Host "Copy the following public key and add it to your GitHub account (Settings > SSH and GPG keys > New GPG key):"
        Write-Host ""
        gpg --armor --export "$selected_key"
        Write-Host ""
    }
    elseif ($choice -eq $create_new_index) {
        # ---
        # **SECURE GPG CREATION (From Script 1)**
        # ---
        Log-Info "Creating a new GPG key..."
        $git_name = Get-GitConfig 'user.name'
        $git_email = Get-GitConfig 'user.email'

        $gpg_name = Read-Host "GPG Key Name (default: $git_name, or '/skip' to skip creation)"
        if ($gpg_name -eq '/skip') {
            Log-Info "Skipped GPG key creation."
            Set-GitConfig -Key "commit.gpgsign" -Value "false"
            Log-Success "Git commit signing has been disabled."
            Save-Backup -BackupFile $backupFile
            exit 0
        }
        if ([string]::IsNullOrEmpty($gpg_name)) { $gpg_name = $git_name }

        $gpg_email = Read-Host "GPG Key Email (default: $git_email, or '/skip' to skip creation)"
        if ($gpg_email -eq '/skip') {
            Log-Info "Skipped GPG key creation."
            Set-GitConfig -Key "commit.gpgsign" -Value "false"
            Log-Success "Git commit signing has been disabled."
            Save-Backup -BackupFile $backupFile
            exit 0
        }
        if ([string]::IsNullOrEmpty($gpg_email)) { $gpg_email = $git_email }

        # Use AsSecureString to securely read the passphrase
        $secure_passphrase = Read-Host "GPG Key Passphrase (will not be displayed, leave blank for no passphrase):" -AsSecureString

        $batch_file = [System.IO.Path]::GetTempFileName()
        $gen_output = $null
        $new_key = $null
        $bstr = [IntPtr]::Zero

        # Use try...finally to ensure the batch file and passphrase in memory are cleared
        try {
            # Convert SecureString to BSTR (Windows-specific string)
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure_passphrase)
            # Convert BSTR to plain text string
            $gpg_passphrase = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

            # Using a PowerShell Here-String
            $batch_content = @"
%echo Generating GPG key...
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: $gpg_name
Name-Email: $gpg_email
Expire-Date: 0
"@
            if (-not [string]::IsNullOrEmpty($gpg_passphrase)) {
                $batch_content += "`nPassphrase: $gpg_passphrase"
            }
            $batch_content += "`n%commit`n%echo GPG key generated successfully."

            Set-Content -Path $batch_file -Value $batch_content

            # Generate the key and capture output (stdout and stderr)
            $gen_output = gpg --batch --generate-key "$batch_file" 2>&1
        }
        finally {
            # Securely clear the plaintext BSTR from memory
            if ($bstr -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
            # Dispose the SecureString
            $secure_passphrase.Dispose()

            # Securely delete the batch file
            if (Test-Path $batch_file) {
                Remove-Item $batch_file -Force
            }
        }

        # Parse the command output to find the new key ID reliably
        if ($gen_output) {
            $gen_output | ForEach-Object {
                if ($_ -match 'gpg: key ([A-F0-9]+) created') {
                    $new_key = $matches[1]
                    break
                }
            }
            # Fallback if 'created' line isn't found
            if ([string]::IsNullOrEmpty($new_key)) {
                $gen_output | ForEach-Object {
                        if ($_ -match 'key ([A-F0-9]+) marked as') {
                        $new_key = $matches[1]
                        break
                    }
                }
            }
        }

        if (-not [string]::IsNullOrEmpty($new_key)) {
            Log-Success "New GPG key created: $new_key"
            Log-Info "Configuring Git to sign commits with the new key..."
            Set-GitConfig -Key "user.signingkey" -Value $new_key
            Set-GitConfig -Key "commit.gpgsign" -Value "true"
            Set-GitConfig -Key "gpg.format" -Value "openpgp"
            Log-Success "Git commit signing has been configured with the new key."

            Write-Host "Copy the following public key and add it to your GitHub account (Settings > SSH and GPG keys > New GPG key):"
            Write-Host ""
            gpg --armor --export "$new_key"
            Write-Host ""
        } else {
            Log-Error "Failed to create GPG key. Output from GPG:"
            Write-Host $gen_output
            exit 1
        }
    }
    elseif ($choice -eq $cancel_index) {
        Log-Info "Disabling Git commit signing."
        Set-GitConfig -Key "commit.gpgsign" -Value "false"
        Log-Success "Git commit signing has been disabled."
    }
    else {
        Log-Error "Invalid choice. Exiting."
        exit 1
    }
}
else {
    Log-Error "Invalid choice. Exiting."
    exit 1
}

Write-Host "" # Final newline after progress
Save-Backup -BackupFile $backupFile
Log-Success "Git configuration completed."
