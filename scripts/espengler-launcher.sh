#!/usr/bin/env bash
# Espengler launcher: start server (systemd or fallback to background) and open browser.
# INSTALL_DIR is replaced at install time; if not, we resolve it from this script's path.
INSTALL_DIR="@INSTALL_DIR@"
if [ "$INSTALL_DIR" = "@INSTALL_DIR@" ] || [ ! -d "$INSTALL_DIR" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    INSTALL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
SERVICE="espengler"
PIDFILE="$INSTALL_DIR/.espengler.pid"
URL="http://127.0.0.1:8000/"
MAX_WAIT=30

# Ensure we have a sane environment when launched from desktop (e.g. PATH)
export PATH="/usr/local/bin:/usr/bin:$PATH"
cd "$INSTALL_DIR" || exit 1

start_via_systemd() {
    systemctl --user start "$SERVICE" 2>/dev/null
}

is_running_systemd() {
    systemctl --user is-active --quiet "$SERVICE" 2>/dev/null
}

is_server_up() {
    if command -v curl >/dev/null 2>&1; then
        code=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)
        case "$code" in 200|301|302) return 0 ;; *) return 1 ;; esac
    fi
    return 1
}

# If already responding, just open browser
if is_server_up; then
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$URL"
    elif command -v sensible-browser >/dev/null 2>&1; then
        sensible-browser "$URL"
    fi
    exit 0
fi

# Try systemd first (disable exit-on-error for fallback)
set +e
if is_running_systemd; then
    : # already running
elif start_via_systemd; then
    : # started
else
    # Fallback: start server in background when systemd --user is not available (e.g. some Kali sessions)
    if [ -f "$PIDFILE" ]; then
        oldpid=$(cat "$PIDFILE")
        if kill -0 "$oldpid" 2>/dev/null; then
            : # already running from previous fallback start
        else
            rm -f "$PIDFILE"
        fi
    fi
    if ! is_server_up && [ ! -f "$PIDFILE" ]; then
        export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-VulnerabilityManager.settings}"
        nohup "$INSTALL_DIR/venv/bin/python" manage.py runserver 0.0.0.0:8000 </dev/null >> "$INSTALL_DIR/.espengler.log" 2>&1 &
        echo $! > "$PIDFILE"
    fi
fi
set -e

# Wait until the server responds
count=0
while [ $count -lt $MAX_WAIT ]; do
    if is_server_up; then
        break
    fi
    sleep 1
    count=$((count + 1))
done

# Open browser
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL"
elif command -v sensible-browser >/dev/null 2>&1; then
    sensible-browser "$URL"
else
    echo "Open $URL in your browser."
fi
