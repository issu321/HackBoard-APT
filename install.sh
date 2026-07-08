#!/bin/sh

# ══════════════════════════════════════════════════════════════════════════════
#  HACKBOARD — Advanced Linux Installer
#  Version: 1.0.0
#  Author: issu321
#  GitHub: https://github.com/issu321/hackboard
# ══════════════════════════════════════════════════════════════════════════════

set -e

# =========================
# COLORS
# =========================
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# =========================
# UTILITIES
# =========================

print_banner() {
    clear 2>/dev/null || true
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                      ║${NC}"
    echo -e "${CYAN}║     ██╗  ██╗ █████╗  ██████╗██╗  ██╗██████╗  ██████╗  █████╗ ██████╗  ║${NC}"
    echo -e "${CYAN}║     ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗██╔══██╗██╔══██╗ ║${NC}"
    echo -e "${CYAN}║     ███████║███████║██║     █████╔╝ ██████╔╝██║   ██║███████║██║  ██║ ║${NC}"
    echo -e "${CYAN}║     ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══██╗██║   ██║██╔══██║██║  ██║ ║${NC}"
    echo -e "${CYAN}║     ██║  ██║██║  ██║╚██████╗██║  ██╗██████╔╝╚██████╔╝██║  ██║██████╔╝ ║${NC}"
    echo -e "${CYAN}║     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝  ║${NC}"
    echo -e "${CYAN}║                                                                      ║${NC}"
    echo -e "${CYAN}║              CYBERSECURITY INTELLIGENCE PLATFORM                      ║${NC}"
    echo -e "${CYAN}║                                                                      ║${NC}"
    echo -e "${CYAN}║                  Version 1.0.0  |  Developed by issu321               ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${MAGENTA}[INFO]${NC} $1"
}

# =========================
# PYTHON DETECTION
# =========================

detect_python() {
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_CMD="python3"
    elif command -v python >/dev/null 2>&1; then
        PYTHON_CMD="python"
    else
        print_error "Python 3 is not installed."
        echo "Install Python 3.9+ and run the installer again."
        exit 1
    fi

    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    print_ok "Python detected: $PYTHON_VERSION ($PYTHON_CMD)"

    # Check minimum version (3.9+)
    PYTHON_MAJOR=$($PYTHON_CMD -c "import sys; print(sys.version_info.major)")
    PYTHON_MINOR=$($PYTHON_CMD -c "import sys; print(sys.version_info.minor)")
    if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]; }; then
        print_error "Python 3.9+ is required. Found: $PYTHON_VERSION"
        exit 1
    fi
}

# =========================
# PIP DETECTION
# =========================

detect_pip() {
    if command -v pip3 >/dev/null 2>&1; then
        PIP_CMD="pip3"
    elif command -v pip >/dev/null 2>&1; then
        PIP_CMD="pip"
    else
        print_error "pip is not installed."
        echo "Install pip and run the installer again."
        exit 1
    fi
    print_ok "pip detected: $PIP_CMD"
}

# =========================
# VIRTUAL ENVIRONMENT CHECK
# =========================

check_venv() {
    if [ -n "${VIRTUAL_ENV}" ]; then
        print_ok "Virtual environment active: $VIRTUAL_ENV"
        return 0
    fi

    print_warn "No virtual environment detected."
    echo ""
    echo -e "${YELLOW}IMPORTANT:${NC} A virtual environment is REQUIRED for isolation."
    echo ""
    echo -e "${GREEN}Recommended commands:${NC}"
    echo "  $PYTHON_CMD -m venv venv"
    echo "  source venv/bin/activate"
    echo "  bash install.sh"
    echo ""
    echo -e "Type ${GREEN}yes${NC}  -> Continue without venv (not recommended)"
    echo -e "Type ${RED}exit${NC} -> Stop installer"
    echo ""
    printf "Enter choice (yes/exit): "
    read -r USER_INPUT

    if [ "$USER_INPUT" = "exit" ]; then
        echo ""
        print_error "Installation terminated by user."
        exit 1
    fi

    if [ "$USER_INPUT" != "yes" ]; then
        echo ""
        print_error "Invalid input. Run installer again and type: yes or exit"
        exit 1
    fi

    print_warn "Continuing without virtual environment."
}

# =========================
# CONFIG DIRECTORIES
# =========================

create_config_dirs() {
    print_step "Creating HackBoard configuration directories..."
    CONFIG_DIR="$HOME/.config/hackboard"
    for subdir in logs reports history settings; do
        mkdir -p "$CONFIG_DIR/$subdir"
    done
    print_ok "Config directories created: $CONFIG_DIR"
}

# =========================
# DEPENDENCY INSTALLATION
# =========================

install_deps() {
    print_step "Upgrading pip..."
    $PIP_CMD install --upgrade pip -q

    print_step "Installing HackBoard dependencies..."
    if [ -f requirements.txt ]; then
        $PIP_CMD install -r requirements.txt -q
    else
        $PIP_CMD install hackboard -q
    fi
    print_ok "Dependencies installed successfully"
}

# =========================
# HACKBOARD INSTALL
# =========================

install_hackboard() {
    print_step "Installing HackBoard package..."
    if [ -f pyproject.toml ]; then
        $PIP_CMD install -e . -q
    else
        $PIP_CMD install hackboard -q
    fi
    print_ok "HackBoard installed"
}

# =========================
# VERIFY INSTALLATION
# =========================

verify_install() {
    print_step "Verifying installation..."
    if command -v hackboard >/dev/null 2>&1; then
        print_ok "hackboard command is available"
    else
        print_warn "hackboard command not found in PATH"
        print_info "You may need to restart your shell or run: source ~/.bashrc"
    fi
}

# =========================
# LAUNCH
# =========================

launch_hackboard() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║               ✅ INSTALLATION COMPLETE ✅                           ║${NC}"
    echo -e "${GREEN}║                                                                      ║${NC}"
    echo -e "${GREEN}║          HACKBOARD IS READY                                          ║${NC}"
    echo -e "${GREEN}║                                                                      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    print_ok "HackBoard v1.0.0 installed successfully"
    print_ok "Config directory: $HOME/.config/hackboard"
    print_ok "Launch with: hackboard"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${MAGENTA}🚀 Launching HackBoard Dashboard...${NC}"
    echo ""
    hackboard
}

# =========================
# MAIN
# =========================

main() {
    print_banner
    detect_python
    detect_pip
    check_venv
    create_config_dirs
    install_deps
    install_hackboard
    verify_install
    launch_hackboard
}

main "$@"
