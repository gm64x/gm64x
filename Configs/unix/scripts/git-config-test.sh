#!/bin/bash

# Test version of script to configure Git settings including user info and commit signing with GPG
# This version simulates actions without making actual changes

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

log_test() {
    echo -e "${CYAN}[TEST MODE]${NC} $1"
}

# Check for undo command
if [ "$1" = "--undo" ]; then
    log_info "Reverting Git configuration..."
    # Check for backup
    if [ -f ".bkp/git_config_backup.txt" ]; then
        log_test "Would restore from backup at .bkp/git_config_backup.txt"
        log_success "Configuration restored from backup (simulated)."
    else
        log_test "Would run: git config --global --unset user.signingkey"
        log_test "Would run: git config --global commit.gpgsign false"
        log_success "Git commit signing has been disabled (simulated)."
    fi
    exit 0
fi

# Create backup directory if it doesn't exist
log_test "Would create backup directory: mkdir -p .bkp"

# Backup current Git config values
log_info "Creating backup of current Git configuration..."
log_test "Would create backup file: .bkp/git_config_backup.txt"
log_test "Would backup: user.name, user.email, user.signingkey, commit.gpgsign, core.editor, merge.tool, diff.tool"
log_success "Backup created at .bkp/git_config_backup.txt (simulated)"

# Check if required tools are installed
if command -v git &> /dev/null; then
    log_success "Git is installed"
else
    log_error "Git is not installed. Please install Git first."
    exit 1
fi

# Configure basic Git settings
log_info "Configuring basic Git settings..."

total_questions=7
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
    log_test "Would run: git config --global user.name \"$user_name\""
    log_success "Set user.name to: $user_name (simulated)"
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
    log_test "Would run: git config --global user.email \"$user_email\""
    log_success "Set user.email to: $user_email (simulated)"
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
    log_test "Would run: git config --global core.editor \"$editor\""
    log_success "Set core.editor to: $editor (simulated)"
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
    log_test "Would run: git config --global merge.tool \"$merge_tool\""
    log_success "Set merge.tool to: $merge_tool (simulated)"
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
    log_test "Would run: git config --global diff.tool \"$diff_tool\""
    log_success "Set diff.tool to: $diff_tool (simulated)"
else
    log_info "Skipped diff.tool configuration"
fi
((current_question++))

# Now proceed with GPG signing configuration
if command -v gpg &> /dev/null; then
    log_success "GPG is installed"
else
    log_warning "GPG is not installed. Skipping commit signing configuration."
    log_success "Basic Git configuration completed (simulated)."
    exit 0
fi

log_info "Checking for existing GPG keys..."

# Check if user has GPG secret keys
gpg_keys=$(gpg --list-secret-keys --keyid-format LONG 2>/dev/null | grep -E "^sec" | awk '{print $2}' | cut -d'/' -f2)

if [ -z "$gpg_keys" ]; then
    log_warning "No existing keys found"
    echo "Would you like to generate a new GPG key? (y/n)"
    read -r generate_key
    if [[ $generate_key =~ ^[Yy]$ ]]; then
        log_test "Would generate a new GPG key with: gpg --full-generate-key"
        # Simulate successful generation
        log_test "Assuming key generation succeeded."
        gpg_keys="SIMULATED_KEY_ID"
    else
        log_test "Would disable Git commit signing with: git config --global commit.gpgsign false"
        log_success "Git commit signing has been disabled (simulated)."
        exit 0
    fi
fi

show_progress
log_info "Available GPG keys:"
key_array=()
index=1
for key in $gpg_keys; do
    if [ "$key" = "SIMULATED_KEY_ID" ]; then
        key_info="Simulated User <simulated@example.com>"
    else
        key_info=$(gpg --list-secret-keys --keyid-format LONG $key 2>/dev/null | grep -E "^uid" | head -1 | sed 's/uid *//')
    fi
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
    log_test "Would disable Git commit signing with: git config --global commit.gpgsign false"
    log_success "Git commit signing has been disabled (simulated)."
elif [ "$choice" -ge 1 ] && [ "$choice" -lt $((index-1)) ]; then
    selected_key="${key_array[$((choice-1))]}"
    log_test "Would configure Git to sign commits with key: $selected_key"
    log_test "Would run: git config --global user.signingkey \"$selected_key\""
    log_test "Would run: git config --global commit.gpgsign true"
    log_success "Git commit signing has been configured (simulated)."
elif [ "$choice" -eq $((index-1)) ]; then
    # Simulate creating new GPG key
    log_info "Creating a new GPG key..."
    
    # Get git user name and email as defaults
    git_name=$(git config --global user.name 2>/dev/null || echo '')
    git_email=$(git config --global user.email 2>/dev/null || echo '')
    
    echo "GPG Key Name (default: $git_name, or '/skip' to skip creation):"
    read -r gpg_name
    if [ "$gpg_name" = "/skip" ]; then
        log_info "Skipped GPG key creation."
        log_test "Would disable Git commit signing with: git config --global commit.gpgsign false"
        log_success "Git commit signing has been disabled (simulated)."
        return
    fi
    gpg_name=${gpg_name:-$git_name}
    
    echo "GPG Key Email (default: $git_email, or '/skip' to skip creation):"
    read -r gpg_email
    if [ "$gpg_email" = "/skip" ]; then
        log_info "Skipped GPG key creation."
        log_test "Would disable Git commit signing with: git config --global commit.gpgsign false"
        log_success "Git commit signing has been disabled (simulated)."
        return
    fi
    gpg_email=${gpg_email:-$git_email}
    
    echo "GPG Key Passphrase (leave blank for no passphrase):"
    read -r -s gpg_passphrase
    echo
    
    log_test "Would create GPG key with name: $gpg_name, email: $gpg_email"
    if [ -n "$gpg_passphrase" ]; then
        log_test "Would set passphrase (hidden)"
    else
        log_test "Would create key without passphrase"
    fi
    log_test "Would run: gpg --batch --generate-key <batch_file>"
    
    # Simulate new key
    new_key="SIMULATED_NEW_KEY_ID"
    log_success "New GPG key created (simulated): $new_key"
    log_info "Configuring Git to sign commits with the new key..."
    log_test "Would run: git config --global user.signingkey \"$new_key\""
    log_test "Would run: git config --global commit.gpgsign true"
    log_success "Git commit signing has been configured with the new key (simulated)."
elif [ "$choice" -eq "$index" ]; then
    log_test "Would disable Git commit signing with: git config --global commit.gpgsign false"
    log_success "Git commit signing has been disabled (simulated)."
else
    log_error "Invalid choice. Exiting."
    exit 1
fi

log_success "Git configuration completed (simulated)."