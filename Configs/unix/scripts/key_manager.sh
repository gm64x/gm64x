#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SSH_DIR="$HOME/.ssh"

# --- DEPENDENCY MANAGEMENT ---

function detect_manager_and_install() {
    local pkg_name=$1
    local display_name=$2

    if [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew &> /dev/null; then
            brew install "$pkg_name"
        else
            echo -e "${RED}Homebrew not found. Cannot auto-install on macOS.${NC}"
        fi
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        case $ID in
            debian|ubuntu|kali|mint)
                sudo apt-get update && sudo apt-get install -y "$pkg_name"
                ;;
            fedora|rhel|centos)
                sudo dnf install -y "$pkg_name"
                ;;
            arch|manjaro)
                sudo pacman -S --noconfirm "$pkg_name"
                ;;
            opensuse*|sles)
                sudo zypper install -y "$pkg_name"
                ;;
            *)
                echo -e "${RED}Unsupported distribution: $ID. Please install $display_name manually.${NC}"
                ;;
        esac
    else
        echo -e "${RED}Cannot detect OS. Please install $display_name manually.${NC}"
    fi
}

function check_dependency() {
    local cmd=$1
    local pkg=$2
    local nice_name=$3

    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${YELLOW}Warning: '$nice_name' ($cmd) is not installed.${NC}"
        read -p "Do you want to attempt to install it now? (y/N): " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Attempting installation of $pkg...${NC}"
            detect_manager_and_install "$pkg" "$nice_name"
        else
            echo -e "${YELLOW}Skipping installation. Some features may not work.${NC}"
        fi
    fi
}

# --- SSH FUNCTIONS ---

function generate_ssh() {
    if ! command -v ssh-keygen &> /dev/null; then echo -e "${RED}Error: ssh-keygen missing.${NC}"; read -p "Enter..."; return; fi
    echo -e "${GREEN}Generating New SSH Key${NC}"
    read -p "Enter comment (e.g., email address): " email
    echo "1) Ed25519 (Recommended)"
    echo "2) RSA (4096 bit)"
    read -p "Choice: " algo_choice

    if [ "$algo_choice" == "1" ]; then
        ssh-keygen -t ed25519 -C "$email"
    elif [ "$algo_choice" == "2" ]; then
        ssh-keygen -t rsa -b 4096 -C "$email"
    else
        echo -e "${RED}Invalid choice.${NC}"
    fi
    read -p "Press Enter..."
}

function view_ssh() {
    echo -e "${GREEN}Existing SSH Public Keys:${NC}"
    ls -l "$SSH_DIR"/*.pub 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "No public keys found in $SSH_DIR"
    else
        echo ""
        for key in "$SSH_DIR"/*.pub; do
            echo -e "${GREEN}Key: $(basename "$key")${NC}"
            if command -v ssh-keygen &> /dev/null; then
                ssh-keygen -lf "$key"
            else
                cat "$key"
            fi
        done
    fi
    read -p "Press Enter to continue..."
}

function delete_ssh() {
    echo -e "${RED}--- DELETE SSH KEY ---${NC}"

    # Check if dir exists and is not empty
    if [ -d "$SSH_DIR" ] && [ "$(ls -A "$SSH_DIR")" ]; then
        ls "$SSH_DIR"
    else
        echo "No SSH keys found to delete."
        read -p "Press Enter to continue..."
        return
    fi

    read -p "Enter the filename to delete (e.g., id_ed25519): " filename

    if [ -f "$SSH_DIR/$filename" ]; then
        read -p "Are you sure you want to delete $filename and $filename.pub? (y/N): " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm "$SSH_DIR/$filename"
            rm "$SSH_DIR/$filename.pub" 2>/dev/null
            echo -e "${GREEN}Keys deleted.${NC}"
        fi
    else
        echo -e "${RED}File not found.${NC}"
    fi
    read -p "Press Enter to continue..."
}

function menu_ssh() {
    while true; do
        clear
        echo -e "${BLUE}=========================================${NC}"
        echo -e "${BLUE}          SSH Key Management             ${NC}"
        echo -e "${BLUE}=========================================${NC}"
        echo "1. Generate SSH Key"
        echo "2. View SSH Keys"
        echo "3. Delete SSH Key"
        echo "-----------------------"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select an option: " choice

        case $choice in
            1) generate_ssh ;;
            2) view_ssh ;;
            3) delete_ssh ;;
            0) return ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
    done
}

# --- GPG FUNCTIONS ---

function generate_gpg() {
    if ! command -v gpg &> /dev/null; then echo -e "${RED}Error: gpg missing.${NC}"; read -p "Enter..."; return; fi
    echo -e "${GREEN}Generating GPG Key (Full Gen)${NC}"
    gpg --full-generate-key
    read -p "Press Enter to continue..."
}

function view_gpg() {
    if ! command -v gpg &> /dev/null; then echo -e "${RED}Error: gpg missing.${NC}"; read -p "Enter..."; return; fi
    echo -e "${GREEN}--- Public Keys ---${NC}"
    gpg --list-keys
    echo -e "${GREEN}--- Secret Keys ---${NC}"
    gpg --list-secret-keys
    read -p "Press Enter to continue..."
}

function delete_gpg() {
    if ! command -v gpg &> /dev/null; then echo -e "${RED}Error: gpg missing.${NC}"; read -p "Enter..."; return; fi
    echo -e "${RED}--- DELETE GPG KEY ---${NC}"
    gpg --list-keys --keyid-format LONG
    echo ""
    read -p "Enter the Key ID (Long format) to delete: " keyid

    if [ -z "$keyid" ]; then return; fi

    echo -e "${RED}WARNING: You must delete the secret key first, then the public key.${NC}"
    read -p "Proceed? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo "Deleting Secret Key..."
        gpg --delete-secret-key "$keyid"
        echo "Deleting Public Key..."
        gpg --delete-key "$keyid"
    fi
    read -p "Press Enter to continue..."
}

function menu_gpg() {
    while true; do
        clear
        echo -e "${BLUE}=========================================${NC}"
        echo -e "${BLUE}          GPG Key Management             ${NC}"
        echo -e "${BLUE}=========================================${NC}"
        echo "1. Generate GPG Key"
        echo "2. View GPG Keys"
        echo "3. Delete GPG Key"
        echo "-----------------------"
        echo "0. Back to Main Menu"
        echo ""
        read -p "Select an option: " choice

        case $choice in
            1) generate_gpg ;;
            2) view_gpg ;;
            3) delete_gpg ;;
            0) return ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
    done
}

# --- INITIAL CHECKS ---
check_dependency "gpg" "gnupg" "GPG"
check_dependency "ssh-keygen" "openssh" "OpenSSH"

# --- MAIN LOOP ---
while true; do
    clear
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}    GPG & SSH Key Management System      ${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo "1. Manage SSH Keys"
    echo "2. Manage GPG Keys"
    echo "-----------------------"
    echo "0. Exit"
    echo ""
    read -p "Select what to manage: " choice

    case $choice in
        1) menu_ssh ;;
        2) menu_gpg ;;
        0) echo "Exiting..."; exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
    esac
done
