#!/bin/bash

# Script to configure Git settings including user info and commit signing with GPG or SSH

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check tools
check_tools() {
    log_info "Checking installed tools..."
    tools=("git" "gpg" "ssh-keygen")
    installed=()
    not_installed=()
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            installed+=("$tool")
        else
            not_installed+=("$tool")
        fi
    done
    if [ ${#installed[@]} -gt 0 ]; then
        log_success "Installed tools: ${installed[*]}"
    fi
    if [ ${#not_installed[@]} -gt 0 ]; then
        log_warning "Not installed tools: ${not_installed[*]}"
    fi
}

# Check for undo command
if [ "$1" = "--undo" ]; then
    log_info "Reverting Git configuration..."
    # Check for backup
    if [ -f ".bkp/git_config_backup.txt" ]; then
        log_info "Restoring from backup..."
        # Restore original values
        while IFS='=' read -r key value; do
            case $key in
                user.name|user.email|user.signingkey|commit.gpgsign|core.editor|merge.tool|diff.tool)
                    if [ -n "$value" ]; then
                        git config --global "$key" "$value"
                    else
                        git config --global --unset "$key" 2>/dev/null
                    fi
                    ;;
            esac
        done < ".bkp/git_config_backup.txt"
        log_success "Configuration restored from backup."
    else
        # Default undo behavior
        git config --global --unset user.signingkey 2>/dev/null
        git config --global commit.gpgsign false
        log_success "Git commit signing has been disabled."
    fi
    exit 0
fi

# Check tools
check_tools

# Create backup directory if it doesn't exist
mkdir -p .bkp

# Backup current Git config values
log_info "Creating backup of current Git configuration..."
backup_file=".bkp/git_config_backup.txt"
echo "# Git config backup created on $(date)" > "$backup_file"
echo "user.name=$(git config --global user.name 2>/dev/null || echo '')" >> "$backup_file"
echo "user.email=$(git config --global user.email 2>/dev/null || echo '')" >> "$backup_file"
echo "user.signingkey=$(git config --global user.signingkey 2>/dev/null || echo '')" >> "$backup_file"
echo "commit.gpgsign=$(git config --global commit.gpgsign 2>/dev/null || echo 'false')" >> "$backup_file"
echo "gpg.format=$(git config --global gpg.format 2>/dev/null || echo '')" >> "$backup_file"
echo "core.editor=$(git config --global core.editor 2>/dev/null || echo '')" >> "$backup_file"
echo "merge.tool=$(git config --global merge.tool 2>/dev/null || echo '')" >> "$backup_file"
echo "diff.tool=$(git config --global diff.tool 2>/dev/null || echo '')" >> "$backup_file"
log_success "Backup created at $backup_file"

# Check if required tools are installed
if command -v git &> /dev/null; then
    log_success "Git is installed"
else
    log_error "Git is not installed. Please install Git first."
    exit 1
fi

# Configure basic Git settings
log_info "Configuring basic Git settings..."

total_questions=8
current_question=1

# Function to show progress
show_progress() {
    local progress=$((current_question * 100 / total_questions))
    local bar_length=20
    local filled=$((progress * bar_length / 100))
    local empty=$((bar_length - filled))
    printf "\rProgress: [%-${bar_length}s] %d%% (%d/%d)" "$(printf '#%.0s' $(seq 1 $filled))" "$progress" "$current_question" "$total_questions"
    echo
}

# Get user name
show_progress
current_name=$(git config --global user.name 2>/dev/null || echo '')
if [ -n "$current_name" ]; then
    echo "Current user.name: $current_name"
    echo "Enter new user.name (or press Enter to keep current, '/skip' to skip):"
else
    echo "Enter user.name (or press Enter to skip):"
fi
read -r user_name
if [ -n "$user_name" ] && [ "$user_name" != "/skip" ]; then
    git config --global user.name "$user_name"
    log_success "Set user.name to: $user_name"
elif [ -n "$current_name" ]; then
    log_info "Kept existing user.name: $current_name"
else
    log_info "Skipped user.name configuration"
fi
((current_question++))

# Get user email
show_progress
current_email=$(git config --global user.email 2>/dev/null || echo '')
if [ -n "$current_email" ]; then
    echo "Current user.email: $current_email"
    echo "Enter new user.email (or press Enter to keep current, '/skip' to skip):"
else
    echo "Enter user.email (or press Enter to skip):"
fi
read -r user_email
if [ -n "$user_email" ] && [ "$user_email" != "/skip" ]; then
    git config --global user.email "$user_email"
    log_success "Set user.email to: $user_email"
elif [ -n "$current_email" ]; then
    log_info "Kept existing user.email: $current_email"
else
    log_info "Skipped user.email configuration"
fi
((current_question++))

# Optional: Configure editor
show_progress
current_editor=$(git config --global core.editor 2>/dev/null || echo '')
echo "Configure Git editor (optional):"
echo "Current core.editor: ${current_editor:-none}"
echo "Enter editor command (e.g., nano, vim, code --wait) or press Enter to skip:"
read -r editor
if [ -n "$editor" ] && [ "$editor" != "/skip" ]; then
    git config --global core.editor "$editor"
    log_success "Set core.editor to: $editor"
else
    log_info "Skipped core.editor configuration"
fi
((current_question++))

# Optional: Configure merge tool
show_progress
current_merge=$(git config --global merge.tool 2>/dev/null || echo '')
echo "Configure Git merge tool (optional):"
echo "Current merge.tool: ${current_merge:-none}"
echo "Enter merge tool (e.g., vimdiff, meld) or press Enter to skip:"
read -r merge_tool
if [ -n "$merge_tool" ] && [ "$merge_tool" != "/skip" ]; then
    git config --global merge.tool "$merge_tool"
    log_success "Set merge.tool to: $merge_tool"
else
    log_info "Skipped merge.tool configuration"
fi
((current_question++))

# Optional: Configure diff tool
show_progress
current_diff=$(git config --global diff.tool 2>/dev/null || echo '')
echo "Configure Git diff tool (optional):"
echo "Current diff.tool: ${current_diff:-none}"
echo "Enter diff tool (e.g., vimdiff, meld) or press Enter to skip:"
read -r diff_tool
if [ -n "$diff_tool" ] && [ "$diff_tool" != "/skip" ]; then
    git config --global diff.tool "$diff_tool"
    log_success "Set diff.tool to: $diff_tool"
else
    log_info "Skipped diff.tool configuration"
fi
((current_question++))

# Ask user to choose between SSH or GPG signing
show_progress
echo "Choose commit signing method:"
echo "1) GPG signing"
echo "2) SSH signing"
echo "3) No signing"
echo "Select an option (1-3, or press Enter to skip):"
read -r signing_choice
((current_question++))

if [ -z "$signing_choice" ] || [ "$signing_choice" = "/skip" ]; then
    log_info "Skipped commit signing configuration."
    git config --global commit.gpgsign false
    git config --global --unset gpg.format 2>/dev/null
    log_success "Git configuration completed."
    exit 0
elif [ "$signing_choice" = "3" ]; then
    log_info "Disabling commit signing."
    git config --global commit.gpgsign false
    git config --global --unset gpg.format 2>/dev/null
    log_success "Git configuration completed."
    exit 0
elif [ "$signing_choice" = "2" ]; then
    # SSH signing configuration
    log_info "Configuring SSH signing..."
    
    # Check for SSH keys
    ssh_dir="$HOME/.ssh"
    if [ ! -d "$ssh_dir" ]; then
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
    fi
    
    # List existing SSH keys
    ssh_keys=()
    if [ -d "$ssh_dir" ]; then
        while IFS= read -r -d '' key_file; do
            # Check if it's a public key and has a corresponding private key
            private_key="${key_file%.pub}"
            if [ -f "$private_key" ] && [ "$key_file" != "$private_key" ]; then
                ssh_keys+=("$key_file")
            fi
        done < <(find "$ssh_dir" -maxdepth 1 -name "*.pub" -print0 2>/dev/null)
    fi
    
    if [ ${#ssh_keys[@]} -eq 0 ]; then
        show_progress
        log_warning "No existing SSH keys found"
        echo "Would you like to generate a new SSH key? (y/n, or press Enter to skip)"
        read -r generate_ssh_key
        if [[ $generate_ssh_key =~ ^[Yy]$ ]]; then
            log_info "Generating a new SSH key..."
            
            git_email=$(git config --global user.email 2>/dev/null || echo '')
            echo "Enter email for SSH key (default: $git_email):"
            read -r ssh_email
            ssh_email=${ssh_email:-$git_email}
            
            echo "Enter filename for SSH key (default: id_ed25519):"
            read -r ssh_filename
            ssh_filename=${ssh_filename:-id_ed25519}
            
            ssh-keygen -t ed25519 -C "$ssh_email" -f "$ssh_dir/$ssh_filename"
            
            if [ -f "$ssh_dir/${ssh_filename}.pub" ]; then
                ssh_keys+=("$ssh_dir/${ssh_filename}.pub")
                log_success "SSH key generated successfully"
            else
                log_error "Failed to generate SSH key"
                exit 1
            fi
        else
            log_info "Skipping SSH signing configuration."
            git config --global commit.gpgsign false
            log_success "Git configuration completed."
            exit 0
        fi
        ((current_question++))
    fi
    
    show_progress
    log_info "Available SSH keys:"
    index=1
    for key_file in "${ssh_keys[@]}"; do
        key_content=$(cat "$key_file" 2>/dev/null)
        echo "$index) $(basename "$key_file") - $key_content"
        ((index++))
    done
    
    echo "$index) Create a new SSH key"
    ((index++))
    echo "$index) Cancel SSH signing"
    
    echo "Select an option (enter number):"
    read -r ssh_choice
    
    if [ -z "$ssh_choice" ] || [ "$ssh_choice" = "/skip" ]; then
        log_info "Skipped SSH signing configuration."
        git config --global commit.gpgsign false
    elif [ "$ssh_choice" -ge 1 ] && [ "$ssh_choice" -le ${#ssh_keys[@]} ]; then
        selected_ssh_key="${ssh_keys[$((ssh_choice-1))]}"
        private_ssh_key="${selected_ssh_key%.pub}"
        log_info "Configuring Git to sign commits with SSH key: $(basename "$selected_ssh_key")"
        git config --global gpg.format ssh
        git config --global user.signingkey "$selected_ssh_key"
        git config --global commit.gpgsign true
        log_success "Git commit signing has been configured with SSH."
        echo ""
        log_info "SSH Key Paths:"
        echo "  Private key: $private_ssh_key"
        echo "  Public key:  $selected_ssh_key"
        echo ""
        echo "Copy the following public key and add it to your GitHub account (Settings > SSH and GPG keys > New SSH key > Signing Key):"
        echo ""
        cat "$selected_ssh_key"
        echo ""
    elif [ "$ssh_choice" -eq $((index-1)) ]; then
        # Create new SSH key
        log_info "Creating a new SSH key..."
        
        git_email=$(git config --global user.email 2>/dev/null || echo '')
        echo "Enter email for SSH key (default: $git_email):"
        read -r ssh_email
        ssh_email=${ssh_email:-$git_email}
        
        echo "Enter filename for SSH key (default: id_ed25519):"
        read -r ssh_filename
        ssh_filename=${ssh_filename:-id_ed25519}
        
        ssh-keygen -t ed25519 -C "$ssh_email" -f "$ssh_dir/$ssh_filename"
        
        if [ -f "$ssh_dir/${ssh_filename}.pub" ]; then
            log_success "SSH key created successfully"
            log_info "Configuring Git to sign commits with the new SSH key..."
            git config --global gpg.format ssh
            git config --global user.signingkey "$ssh_dir/${ssh_filename}.pub"
            git config --global commit.gpgsign true
            log_success "Git commit signing has been configured with SSH."
            echo ""
            log_info "SSH Key Paths:"
            echo "  Private key: $ssh_dir/$ssh_filename"
            echo "  Public key:  $ssh_dir/${ssh_filename}.pub"
            echo ""
            echo "Copy the following public key and add it to your GitHub account (Settings > SSH and GPG keys > New SSH key > Signing Key):"
            echo ""
            cat "$ssh_dir/${ssh_filename}.pub"
            echo ""
        else
            log_error "Failed to create SSH key"
            exit 1
        fi
    else
        log_info "Cancelled SSH signing configuration."
        git config --global commit.gpgsign false
    fi
    
    log_success "Git configuration completed."
    exit 0
elif [ "$signing_choice" = "1" ]; then
    # GPG signing configuration (existing code)
    # Now proceed with GPG signing configuration
    if command -v gpg &> /dev/null; then
        log_success "GPG is installed"
    else
        log_warning "GPG is not installed. Skipping commit signing configuration."
        log_success "Basic Git configuration completed."
        exit 0
    fi

    log_info "Checking for existing GPG keys..."

    # Check if user has GPG secret keys
    gpg_keys=$(gpg --list-secret-keys --keyid-format LONG 2>/dev/null | grep -E "^sec" | awk '{print $2}' | cut -d'/' -f2)

    if [ -z "$gpg_keys" ]; then
        show_progress
        log_warning "No existing keys found"
        echo "Would you like to generate a new GPG key? (y/n, or press Enter to skip)"
        read -r generate_key
        if [[ $generate_key =~ ^[Yy]$ ]]; then
            log_info "Generating a new GPG key..."
            gpg --full-generate-key
            # Re-check for keys after generation
            gpg_keys=$(gpg --list-secret-keys --keyid-format LONG 2>/dev/null | grep -E "^sec" | awk '{print $2}' | cut -d'/' -f2)
            if [ -z "$gpg_keys" ]; then
                log_error "Failed to generate GPG key. Exiting."
                exit 1
            fi
        else
            log_info "Skipping GPG key generation."
            git config --global commit.gpgsign false
            log_success "Git commit signing has been disabled."
            exit 0
        fi
        ((current_question++))
    fi

    show_progress
    log_info "Available GPG keys:"
    key_array=()
    index=1
    for key in $gpg_keys; do
        key_info=$(gpg --list-secret-keys --keyid-format LONG $key 2>/dev/null | grep -E "^uid" | head -1 | sed 's/uid *//')
        echo "$index) $key - $key_info"
        key_array+=("$key")
        ((index++))
    done

    echo "$index) Create a new GPG key"
    ((index++))
    echo "$index) Do not use GPG signing"

    echo "Select an option (enter number, or press Enter to skip):"
    read -r choice

    if [ -z "$choice" ] || [ "$choice" = "/skip" ]; then
        log_info "Skipped GPG signing configuration."
        git config --global commit.gpgsign false
        log_success "Git commit signing has been disabled."
    elif [ "$choice" -ge 1 ] && [ "$choice" -lt $((index-1)) ]; then
        selected_key="${key_array[$((choice-1))]}"
        log_info "Configuring Git to sign commits with key: $selected_key"
        git config --global user.signingkey "$selected_key"
        git config --global commit.gpgsign true
        log_success "Git commit signing has been configured."
        echo "Copy the following public key and add it to your GitHub account (Settings > SSH and GPG keys > New GPG key):"
        echo
        gpg --armor --export "$selected_key"
        echo
    elif [ "$choice" -eq $((index-1)) ]; then
        # Create new GPG key
        log_info "Creating a new GPG key..."
        
        # Get git user name and email as defaults
        git_name=$(git config --global user.name 2>/dev/null || echo '')
        git_email=$(git config --global user.email 2>/dev/null || echo '')
        
        echo "GPG Key Name (default: $git_name, or '/skip' to skip creation):"
        read -r gpg_name
        if [ "$gpg_name" = "/skip" ]; then
            log_info "Skipped GPG key creation."
            git config --global commit.gpgsign false
            log_success "Git commit signing has been disabled."
            return
        fi
        gpg_name=${gpg_name:-$git_name}
        
        echo "GPG Key Email (default: $git_email, or '/skip' to skip creation):"
        read -r gpg_email
        if [ "$gpg_email" = "/skip" ]; then
            log_info "Skipped GPG key creation."
            git config --global commit.gpgsign false
            log_success "Git commit signing has been disabled."
            return
        fi
        gpg_email=${gpg_email:-$git_email}
        
        echo "GPG Key Passphrase (leave blank for no passphrase):"
        read -r -s gpg_passphrase
        echo
        
        # Create batch file for gpg
        batch_file=$(mktemp)
        cat > "$batch_file" << EOF
%echo Generating GPG key...
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: $gpg_name
Name-Email: $gpg_email
Expire-Date: 0
EOF
        if [ -n "$gpg_passphrase" ]; then
            echo "Passphrase: $gpg_passphrase" >> "$batch_file"
        fi
        echo "%commit" >> "$batch_file"
        echo "%echo GPG key generated successfully." >> "$batch_file"
        
        # Generate the key
        gpg --batch --generate-key "$batch_file"
        rm "$batch_file"
        
        # Get the new key ID
        new_key=$(gpg --list-secret-keys --keyid-format LONG 2>/dev/null | grep -E "^sec" | tail -1 | awk '{print $2}' | cut -d'/' -f2)
        
        if [ -n "$new_key" ]; then
            log_success "New GPG key created: $new_key"
            log_info "Configuring Git to sign commits with the new key..."
            git config --global user.signingkey "$new_key"
            git config --global commit.gpgsign true
            log_success "Git commit signing has been configured with the new key."
            echo "Copy the following public key and add it to your GitHub account (Settings > SSH and GPG keys > New GPG key):"
            echo
            gpg --armor --export "$new_key"
            echo
        else
            log_error "Failed to create GPG key."
            exit 1
        fi
    elif [ "$choice" -eq "$index" ]; then
        log_info "Disabling Git commit signing."
        git config --global commit.gpgsign false
        log_success "Git commit signing has been disabled."
    else
        log_error "Invalid choice. Exiting."
        exit 1
    fi

    log_success "Git configuration completed."
else
    log_error "Invalid choice. Exiting."
    exit 1
fi