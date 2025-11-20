# GPG and SSH Key Manager for Windows
# Auto-detects missing tools and offers Scoop installation

function Show-Header {
    param ([string]$Title)
    Clear-Host
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "    $Title      " -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
}

function Install-Tool {
    param (
        [string]$ToolName,
        [string]$PackageName
    )

    $install = Read-Host "Tool '$ToolName' is missing. Do you want to install it using Scoop? (y/N)"
    if ($install -match "[yY]") {
        if (Get-Command scoop -ErrorAction SilentlyContinue) {
            Write-Host "Scoop detected. Installing $PackageName..." -ForegroundColor Cyan
            scoop install $PackageName

            # Reload path for the current session
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            Write-Host "Installation complete. If command fails, please restart the script." -ForegroundColor Green
        }
        else {
            Write-Warning "Scoop is not installed."
            Write-Host "To install Scoop, run:" -ForegroundColor Yellow
            Write-Host "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"
            Write-Host "irm get.scoop.sh | iex"
            Write-Host "`nPlease install Scoop manually and restart this script."
        }
    }
    else {
        Write-Host "Skipping installation. Script will continue, but $ToolName features will fail." -ForegroundColor DarkGray
    }
    Start-Sleep -Seconds 2
}

function Check-Prerequisites {
    # Check GPG
    if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) {
        Install-Tool "GPG" "gnupg"
    }

    # Check SSH
    if (-not (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Install-Tool "SSH Tools" "openssh"
    }
}

# --- SSH Functions ---

function New-SSHKey {
    if (-not (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) { Write-Warning "ssh-keygen not found"; Pause; return }
    Write-Host "Generating New SSH Key" -ForegroundColor Green
    $email = Read-Host "Enter comment (e.g., email address)"
    Write-Host "Select Algorithm:"
    Write-Host "1) Ed25519 (Recommended)"
    Write-Host "2) RSA (4096 bit)"
    $algoChoice = Read-Host "Choice"

    if ($algoChoice -eq "1") { ssh-keygen -t ed25519 -C "$email" }
    elseif ($algoChoice -eq "2") { ssh-keygen -t rsa -b 4096 -C "$email" }
    else { Write-Host "Invalid selection." -ForegroundColor Red }
    Pause
}

function Get-SSHInfo {
    $sshDir = "$env:USERPROFILE\.ssh"
    if (Test-Path $sshDir) {
        Write-Host "Checking $sshDir..." -ForegroundColor Green
        $keys = Get-ChildItem -Path $sshDir -Filter "*.pub"
        if ($keys) {
            foreach ($key in $keys) {
                Write-Host "`nPublic Key File: $($key.Name)" -ForegroundColor Yellow
                if (Get-Command ssh-keygen -ErrorAction SilentlyContinue) {
                    ssh-keygen -lf $key.FullName
                } else {
                    Get-Content $key.FullName
                }
            }
        } else { Write-Host "No public keys found." }
    } else { Write-Host "SSH Directory ($sshDir) does not exist." -ForegroundColor Red }
    Pause
}

function Remove-SSHKey {
    $sshDir = "$env:USERPROFILE\.ssh"
    Write-Host "--- Files in $sshDir ---" -ForegroundColor Yellow

    if (Test-Path $sshDir) {
        $files = Get-ChildItem $sshDir
        if ($files) {
            # Pipe to Out-Host to ensure it prints before Read-Host pauses execution
            $files | Select-Object Name | Format-Table -HideTableHeaders | Out-Host
        } else {
            Write-Host "No files found in this directory." -ForegroundColor DarkGray
            Pause
            return
        }
    } else {
         Write-Host "Directory not found." -ForegroundColor Red
         Pause
         return
    }

    $fileName = Read-Host "`nEnter the filename to delete (without extension, e.g., id_ed25519)"
    $privPath = Join-Path $sshDir $fileName
    $pubPath = Join-Path $sshDir "$fileName.pub"

    if (Test-Path $privPath) {
        $confirm = Read-Host "Are you sure you want to delete $fileName AND $fileName.pub? (y/N)"
        if ($confirm -match "[yY]") {
            Remove-Item $privPath -Force
            if (Test-Path $pubPath) { Remove-Item $pubPath -Force }
            Write-Host "Keys deleted successfully." -ForegroundColor Green
        }
    } else { Write-Host "File not found: $privPath" -ForegroundColor Red }
    Pause
}

function Show-SSHMenu {
    do {
        Show-Header "SSH Key Management"
        Write-Host "1. Generate SSH Key"
        Write-Host "2. View SSH Keys"
        Write-Host "3. Delete SSH Key"
        Write-Host "-----------------------"
        Write-Host "0. Back to Main Menu"

        $selection = Read-Host "`nSelect an option"

        switch ($selection) {
            "1" { New-SSHKey }
            "2" { Get-SSHInfo }
            "3" { Remove-SSHKey }
            "0" { return }
            Default { Write-Host "Invalid option." -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } until ($false)
}

# --- GPG Functions ---

function New-GPGKey {
    if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) { Write-Warning "gpg not found"; Pause; return }
    Write-Host "Generating GPG Key..." -ForegroundColor Green
    gpg --full-generate-key
    Pause
}

function Get-GPGInfo {
    if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) { Write-Warning "gpg not found"; Pause; return }
    Write-Host "--- Public Keys ---" -ForegroundColor Green
    gpg --list-keys
    Write-Host "`n--- Secret Keys ---" -ForegroundColor Green
    gpg --list-secret-keys
    Pause
}

function Remove-GPGKey {
    if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) { Write-Warning "gpg not found"; Pause; return }
    Write-Host "--- Available Keys ---"
    gpg --list-keys --keyid-format LONG
    $keyId = Read-Host "`nEnter the Key ID (Long format) to delete"

    if (-not [string]::IsNullOrWhiteSpace($keyId)) {
        Write-Host "IMPORTANT: GPG requires deleting the Secret key first, then the Public key." -ForegroundColor Red
        $confirm = Read-Host "Proceed? (y/N)"
        if ($confirm -match "[yY]") {
            Write-Host "Attempting to delete SECRET key..."
            gpg --delete-secret-key $keyId
            Write-Host "Attempting to delete PUBLIC key..."
            gpg --delete-key $keyId
        }
    }
    Pause
}

function Show-GPGMenu {
    do {
        Show-Header "GPG Key Management"
        Write-Host "1. Generate GPG Key"
        Write-Host "2. View GPG Keys"
        Write-Host "3. Delete GPG Key"
        Write-Host "-----------------------"
        Write-Host "0. Back to Main Menu"

        $selection = Read-Host "`nSelect an option"

        switch ($selection) {
            "1" { New-GPGKey }
            "2" { Get-GPGInfo }
            "3" { Remove-GPGKey }
            "0" { return }
            Default { Write-Host "Invalid option." -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } until ($false)
}

# --- Main Execution ---

Check-Prerequisites

do {
    Show-Header "GPG & SSH Key Manager"
    Write-Host "1. Manage SSH Keys"
    Write-Host "2. Manage GPG Keys"
    Write-Host "-----------------------"
    Write-Host "0. Exit"

    $selection = Read-Host "`nSelect what to manage"

    switch ($selection) {
        "1" { Show-SSHMenu }
        "2" { Show-GPGMenu }
        "0" { exit }
        Default { Write-Host "Invalid option." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
} until ($selection -eq "0")
