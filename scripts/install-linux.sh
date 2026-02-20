#!/usr/bin/env bash
# Espengler - Linux auto-installer for Debian-based distros (Parrot, Kali, Ubuntu, Debian).
# Run from project root or from scripts/ directory.
set -e

WITH_CHROMIUM=false
WITH_NODE=false
CREATE_SUPERUSER=false

rm -rf $INSTALL_DIR/venv

for arg in "$@"; do
    case "$arg" in
        --with-chromium) WITH_CHROMIUM=true ;;
        --with-node)     WITH_NODE=true ;;
        --create-superuser) CREATE_SUPERUSER=true ;;
        -h|--help)
            echo "Usage: $0 [--with-chromium] [--with-node] [--create-superuser]"
            echo "  --with-chromium   Install Chromium for report generation"
            echo "  --with-node       Install Node.js for GraphMap PNG script"
            echo "  --create-superuser Run createsuperuser at the end"
            exit 0
            ;;
    esac
done

# Resolve INSTALL_DIR (project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/../manage.py" ] && [ -f "$SCRIPT_DIR/../requirements.txt" ]; then
    INSTALL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    INSTALL_DIR="$(pwd)"
fi

if [ ! -f "$INSTALL_DIR/manage.py" ] || [ ! -f "$INSTALL_DIR/requirements.txt" ]; then
    echo "Error: Run this script from the Espengler project root (where manage.py and requirements.txt are), or from the scripts/ directory."
    exit 1
fi

if echo "$INSTALL_DIR" | grep -q -i Trash; then
    echo "Error: The project is inside the Trash ($INSTALL_DIR)."
    echo "Move or copy Espengler to a permanent location (e.g. ~/Desktop or ~/Projects) and run this script again."
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    echo "Error: Do not run this script as root. It configures a user-level service and shortcuts."
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "Error: This installer requires a Debian-based distribution (apt-get)."
    echo "Supported: Parrot OS, Kali, Ubuntu, Debian."
    exit 1
fi

if [ ! -f /etc/debian_version ]; then
    echo "Warning: /etc/debian_version not found. Continuing anyway if apt-get is available."
fi

echo "Installing Espengler to: $INSTALL_DIR"
echo ""

# System packages
echo "Installing system dependencies..."
sudo apt-get update || { echo "Warning: apt-get update had errors (e.g. third-party repo signatures). Continuing with available packages..."; }
# libgdk-pixbuf-2.0-dev is the correct package name on Debian/Kali/Ubuntu (hyphen before 2.0)
PKGS="python3 python3-venv python3-pip libjpeg-dev zlib1g-dev libpng-dev libcairo2-dev libpango1.0-dev libgdk-pixbuf-2.0-dev libffi-dev"
if $WITH_CHROMIUM; then
    if apt-cache show chromium >/dev/null 2>&1; then
        PKGS="$PKGS chromium"
    elif apt-cache show chromium-browser >/dev/null 2>&1; then
        PKGS="$PKGS chromium-browser"
    else
        echo "Warning: Chromium package not found in repos; skipping."
    fi
fi
if ! sudo apt-get install -y $PKGS; then
    echo "Warning: Some packages failed (e.g. libgdk-pixbuf-2.0-dev). Retrying without optional pixbuf dev package..."
    PKGS_FALLBACK="python3 python3-venv python3-pip libjpeg-dev zlib1g-dev libpng-dev libcairo2-dev libpango1.0-dev libffi-dev"
    if $WITH_CHROMIUM; then
        apt-cache show chromium >/dev/null 2>&1 && PKGS_FALLBACK="$PKGS_FALLBACK chromium" || \
        apt-cache show chromium-browser >/dev/null 2>&1 && PKGS_FALLBACK="$PKGS_FALLBACK chromium-browser" || true
    fi
    sudo apt-get install -y $PKGS_FALLBACK || { echo "Error: Could not install system dependencies."; exit 1; }
fi

if $WITH_NODE; then
    echo "Installing Node.js..."
    if ! command -v node >/dev/null 2>&1; then
        curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
        sudo apt-get install -y nodejs
    else
        echo "Node.js already installed."
    fi
fi

# Virtual environment and Django (use venv bin paths explicitly to avoid PEP 668 "externally-managed" on Kali/Debian)
echo "Setting up Python virtual environment..."
if [ -d "$INSTALL_DIR/venv" ]; then
    if ! "$INSTALL_DIR/venv/bin/python" --version >/dev/null 2>&1; then
        echo "Removing broken or moved venv (interpreter path changed)..."
        rm -rf "$INSTALL_DIR/venv"
    fi
fi
if [ ! -d "$INSTALL_DIR/venv" ]; then
    python3 -m venv "$INSTALL_DIR/venv"
fi
VENV_PIP="$INSTALL_DIR/venv/bin/pip"
VENV_PYTHON="$INSTALL_DIR/venv/bin/python"
"$VENV_PIP" install --upgrade pip
"$VENV_PIP" install -r "$INSTALL_DIR/requirements.txt"

echo "Running migrations..."
cd "$INSTALL_DIR"
"$VENV_PYTHON" manage.py migrate
# Create and apply any new migrations (e.g. ProjectManager model changes)
if "$VENV_PYTHON" manage.py makemigrations --noinput 2>/dev/null; then
    "$VENV_PYTHON" manage.py migrate
fi

echo "Collecting static files..."
"$VENV_PYTHON" manage.py collectstatic --noinput

if $CREATE_SUPERUSER; then
    echo "Create an admin user:"
    "$VENV_PYTHON" manage.py createsuperuser
fi

# Systemd user service
mkdir -p "$HOME/.config/systemd/user"
sed "s|@INSTALL_DIR@|$INSTALL_DIR|g" "$SCRIPT_DIR/espengler.service.in" > "$HOME/.config/systemd/user/espengler.service"
systemctl --user daemon-reload
echo "Systemd user service installed."

# Launcher and stop scripts (with INSTALL_DIR substituted).
# Use a temp file so we never read and write the same file (would truncate it to 0 bytes when installing in-place).
_launcher_tmp="$INSTALL_DIR/scripts/espengler-launcher.sh.$$"
_stop_tmp="$INSTALL_DIR/scripts/espengler-stop.sh.$$"
sed "s|@INSTALL_DIR@|$INSTALL_DIR|g" "$SCRIPT_DIR/espengler-launcher.sh" > "$_launcher_tmp"
mv "$_launcher_tmp" "$INSTALL_DIR/scripts/espengler-launcher.sh"
chmod +x "$INSTALL_DIR/scripts/espengler-launcher.sh"
sed "s|@INSTALL_DIR@|$INSTALL_DIR|g" "$SCRIPT_DIR/espengler-stop.sh.in" > "$_stop_tmp"
mv "$_stop_tmp" "$INSTALL_DIR/scripts/espengler-stop.sh"
chmod +x "$INSTALL_DIR/scripts/espengler-stop.sh"

# Desktop shortcuts
mkdir -p "$HOME/.local/share/applications"
sed "s|@INSTALL_DIR@|$INSTALL_DIR|g" "$SCRIPT_DIR/espengler-start.desktop.in" > "$HOME/.local/share/applications/espengler-start.desktop"
sed "s|@INSTALL_DIR@|$INSTALL_DIR|g" "$SCRIPT_DIR/espengler-stop.desktop.in"  > "$HOME/.local/share/applications/espengler-stop.desktop"

# Optional: use project icon if present
ICON_PATH="$INSTALL_DIR/static/admin-interface/logo/Logo.png"
if [ -f "$ICON_PATH" ]; then
    sed -i "s|^Icon=.*|Icon=$ICON_PATH|" "$HOME/.local/share/applications/espengler-start.desktop"
fi

chmod +x "$HOME/.local/share/applications/espengler-start.desktop"
chmod +x "$HOME/.local/share/applications/espengler-stop.desktop"

# Update desktop database if available
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
fi

echo ""
echo "Installation completed successfully."
echo ""
echo "To start Espengler: open your application menu and run 'Espengler - Start'."
echo "To stop Espengler: run 'Espengler - Stop' from the menu."
echo ""
echo "To create an admin user later, run:"
echo "  cd $INSTALL_DIR && source venv/bin/activate && python manage.py createsuperuser"
echo ""
