#!/usr/bin/env bash
# =============================================================================
#  ReconTitan setup for macOS and Linux.
#
#  Everything this script does is printed before it does it, and the whole plan
#  is shown up front so nothing happens that you did not agree to. It touches
#  exactly three things: a Python virtual environment inside this folder, the
#  packages inside that environment, and a .env file. Nothing is installed
#  system-wide without asking first, and nothing outside this folder is
#  modified.
#
#  Undo it all with ./uninstall.sh
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
VENV="$ROOT/.venv"
MANIFEST="$ROOT/.recontitan-install.log"

if [ -t 1 ]; then
  B=$'\033[1m'; DIM=$'\033[2m'; OK=$'\033[32m'; WARN=$'\033[33m'
  ERR=$'\033[31m'; ACC=$'\033[38;5;208m'; N=$'\033[0m'
else
  B=""; DIM=""; OK=""; WARN=""; ERR=""; ACC=""; N=""
fi

say()  { printf '%s\n' "$*"; }
step() { printf '\n%s%s%s\n%s\n' "$B" "$*" "$N" " ---------------------------------------------------------------------------"; }
info() { printf '       %s\n' "$*"; }
good() { printf '       %s%s%s\n' "$OK" "$*" "$N"; }
warn() { printf '       %s%s%s\n' "$WARN" "$*" "$N"; }
fail() { printf '\n       %s%s%s\n\n' "$ERR" "$*" "$N"; exit 1; }

OS="unknown"
case "$(uname -s)" in
  Darwin) OS="macos" ;;
  Linux)  OS="linux" ;;
esac

# --- Banner ------------------------------------------------------------------
cat <<BANNER

 ============================================================================
${ACC}
    ____                      _______ __
   / __ \\___  _________  ____/_  __(_) /_____ _____
  / /_/ / _ \\/ ___/ __ \\/ __ \\/ / / / __/ __ \`/ __ \\
 / _, _/  __/ /__/ /_/ / / / / / / / /_/ /_/ / / / /
/_/ |_|\\___/\\___/\\____/_/ /_/_/ /_/\\__/\\__,_/_/ /_/
${N}
  External attack surface assessment
  Detected system: ${OS}

 ============================================================================

  ${B}WHAT THIS SCRIPT WILL DO${N}

    1. Check that Python 3.11 or newer is installed.
       If it is missing, it will ASK before installing anything.

    2. Create a private Python environment in this folder:
         ${VENV}
       This is a folder, not a system change. Deleting it undoes it.

    3. Install this project's Python packages INTO that folder only.
       Your system Python is not touched.

    4. Create a .env configuration file if you do not have one.

    5. Start the scanner at http://127.0.0.1:8000

  ${B}WHAT IT WILL NOT DO${N}

    - It will not modify anything outside this folder without asking.
    - It will not send your data anywhere.
    - It will not run any scan by itself.
    - It will not use sudo unless you explicitly approve a package install.

  Everything it creates is written to:
    ${MANIFEST}
  so uninstall.sh can remove exactly what was added and nothing else.

 ============================================================================

BANNER

printf '  Continue? [y/N] '
read -r AGREE
case "$AGREE" in
  y|Y) ;;
  *) say ""; say "  Cancelled. Nothing was changed."; say ""; exit 0 ;;
esac

{
  echo "# ReconTitan install manifest - what setup.sh created, for uninstall.sh"
  echo "# Created: $(date)"
} > "$MANIFEST"

# --- 1. Python ---------------------------------------------------------------
step " [1/5] Checking for Python"

PY_CMD=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' 2>/dev/null; then
      PY_CMD="$candidate"; break
    fi
  fi
done

if [ -n "$PY_CMD" ]; then
  good "Found: $("$PY_CMD" --version 2>&1)  (command: $PY_CMD)"
else
  warn "Python 3.11+ was not found on this system."
  say ""
  info "ReconTitan cannot run without it. This script can install it using"
  info "your system's own package manager. The exact command is shown before"
  info "it runs, and you can decline and install it yourself instead."
  say ""

  INSTALL_CMD=""
  if [ "$OS" = "macos" ]; then
    if command -v brew >/dev/null 2>&1; then
      INSTALL_CMD="brew install python@3.12"
    else
      fail "Homebrew is not installed. Install Python from https://www.python.org/downloads/ then run this again."
    fi
  elif command -v apt-get >/dev/null 2>&1; then
    INSTALL_CMD="sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip"
  elif command -v dnf >/dev/null 2>&1; then
    INSTALL_CMD="sudo dnf install -y python3 python3-pip"
  elif command -v pacman >/dev/null 2>&1; then
    INSTALL_CMD="sudo pacman -S --noconfirm python python-pip"
  elif command -v zypper >/dev/null 2>&1; then
    INSTALL_CMD="sudo zypper install -y python3 python3-pip"
  else
    fail "No supported package manager found. Install Python 3.11+ from https://www.python.org/downloads/ then run this again."
  fi

  info "The exact command that will run is:"
  printf '         %s%s%s\n' "$B" "$INSTALL_CMD" "$N"
  say ""
  printf '       Run it now? [y/N] '
  read -r DOINSTALL
  case "$DOINSTALL" in
    y|Y) ;;
    *) fail "Cannot continue without Python. Install it and run this again." ;;
  esac

  eval "$INSTALL_CMD" || fail "Python installation failed."
  echo "PYTHON_INSTALLED_BY_SETUP=1" >> "$MANIFEST"
  echo "PYTHON_INSTALL_CMD=$INSTALL_CMD" >> "$MANIFEST"

  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then PY_CMD="$candidate"; break; fi
  done
  [ -n "$PY_CMD" ] || fail "Python still not found after install. Open a new terminal and run this again."
  good "Installed: $("$PY_CMD" --version 2>&1)"
fi

# --- 2. Virtual environment --------------------------------------------------
step " [2/5] Creating the private Python environment"

if [ -x "$VENV/bin/python" ]; then
  info "Already exists, reusing it: .venv/"
else
  info "Creating: .venv/"
  info "A virtual environment keeps this project's packages separate from your"
  info "system Python, so nothing here can break your other projects."
  "$PY_CMD" -m venv "$VENV" || fail "Could not create the environment. On Debian/Ubuntu you may need: sudo apt-get install python3-venv"
  echo "CREATED_VENV=$VENV" >> "$MANIFEST"
  good "Done."
fi

VPY="$VENV/bin/python"

# --- 3. Packages -------------------------------------------------------------
step " [3/5] Installing Python packages into .venv"
info "These go inside .venv only. Your system Python is untouched."
info "Reading the list from: backend/requirements.txt"
say ""

"$VPY" -m pip install --upgrade pip --quiet
if ! "$VPY" -m pip install -r "$ROOT/backend/requirements.txt"; then
  say ""
  warn "Package installation failed. The most common causes:"
  info "  - No internet connection."
  info "  - A proxy blocking pypi.org."
  info "  - Missing build tools. On Debian/Ubuntu: sudo apt-get install build-essential python3-dev"
  exit 1
fi
echo "INSTALLED_PACKAGES=1" >> "$MANIFEST"
say ""
good "Packages installed."

# --- 4. Configuration --------------------------------------------------------
step " [4/5] Configuration"

if [ -f "$ROOT/.env" ]; then
  info ".env already exists, leaving it exactly as it is."
else
  info "Creating .env from .env.example"
  info "This holds your local settings. It is never committed to git."
  cp "$ROOT/.env.example" "$ROOT/.env"
  echo "CREATED_ENV=$ROOT/.env" >> "$MANIFEST"
  good "Done. The defaults work for local use."
fi

# --- 5. Run ------------------------------------------------------------------
step " [5/5] Starting ReconTitan"
cat <<RUN

       The scanner will start at:

           ${B}http://127.0.0.1:8000${N}

       Open that address in your browser.
       Press Ctrl+C in this terminal to stop it.

       ${WARN}Reminder: only scan domains you own or have written permission
       to test. Danger Mode sends real attack traffic.${N}

 ============================================================================

RUN

cd "$ROOT/backend"
"$VPY" -m uvicorn app.main:app --host 127.0.0.1 --port 8000

say ""
say "  ReconTitan has stopped."
say "  Run ./setup.sh again to restart it, or ./uninstall.sh to remove everything."
say ""
