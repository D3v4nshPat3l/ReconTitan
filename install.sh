#!/usr/bin/env bash
#
# ReconTitan — non-interactive Linux installer.
#
# setup.sh is the guided installer: it explains each step and asks before it
# acts. This one is for the case where you already know what you want — a
# fresh box, a container build, a CI job, a re-provision — and want it done
# without answering anything.
#
# The single rule it is built around: **pip is never run outside a virtual
# environment.** Modern Debian, Ubuntu, Kali and Fedora ship an
# externally-managed Python (PEP 668) and refuse a system-wide `pip install`
# outright. The usual workaround, --break-system-packages, does exactly what
# it says: it lets pip overwrite files the distro's package manager owns, and
# the breakage shows up later in something unrelated. So the environment is
# created first, and every install after that happens inside it.
#
#   ./install.sh                 create the environment and install
#   ./install.sh --run           ...then launch the CLI help
#   ./install.sh --with-tools    ...also install nmap and whois via the distro
#   ./install.sh --recreate      delete and rebuild an existing .venv
#   ./install.sh --python /usr/bin/python3.12
#
# Undo everything it did with: rm -rf .venv
#
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/.venv"
PY="$VENV/bin/python"
MIN_MINOR=11

ASSUME_YES=0
WITH_TOOLS=0
RUN_AFTER=0
RECREATE=0
PYTHON_OVERRIDE=""

# ── output ───────────────────────────────────────────────────────────────────
# Colour only when stdout is a terminal, so a log file or a CI transcript does
# not fill up with escape sequences.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'; C_BOLD=$'\033[1m'
else
  C_RESET=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_BOLD=""
fi

step()  { printf '\n%s==>%s %s%s%s\n' "$C_CYAN" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"; }
info()  { printf '    %s\n' "$1"; }
ok()    { printf '    %s✓%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
warn()  { printf '    %s!%s %s\n' "$C_YELLOW" "$C_RESET" "$1" >&2; }
die()   { printf '\n%serror:%s %s\n\n' "$C_RED" "$C_RESET" "$1" >&2; exit 1; }

# Report the line that failed rather than leaving the reader to guess which of
# a hundred commands stopped. $BASH_COMMAND is the command that tripped ERR.
trap 'die "line $LINENO failed: ${BASH_COMMAND}"' ERR

usage() {
  sed -n '3,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)       ASSUME_YES=1 ;;
    --with-tools)   WITH_TOOLS=1 ;;
    --run)          RUN_AFTER=1 ;;
    --recreate)     RECREATE=1 ;;
    --python)       shift; [ $# -gt 0 ] || die "--python needs a path"; PYTHON_OVERRIDE="$1" ;;
    -h|--help)      usage ;;
    *)              die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

cd "$ROOT"

printf '%s\n' "$C_CYAN"
cat <<'BANNER'
    ____                      _______ __
   / __ \___  _________  ____/_  __(_) /_____ _____
  / /_/ / _ \/ ___/ __ \/ __ \/ / / / __/ __ `/ __ \
 / _, _/  __/ /__/ /_/ / / / / / / / /_/ /_/ / / / /
/_/ |_|\___/\___/\____/_/ /_/_/ /_/\__/\__,_/_/ /_/
BANNER
printf '%s' "$C_RESET"
printf '  External attack surface assessment — Linux installer\n'

[ "$(uname -s)" = "Linux" ] || warn "This installer targets Linux. On macOS use ./setup.sh, on Windows setup.bat."

if [ "$(id -u)" -eq 0 ]; then
  warn "Running as root. The environment and its packages will be owned by root."
fi

# ── privilege helper ─────────────────────────────────────────────────────────
# Resolved once. Scripts that call sudo ad hoc end up prompting several times,
# or worse, prompting in the middle of a long install when nobody is watching.
SUDO=""
need_sudo() {
  [ "$(id -u)" -ne 0 ] || return 0
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
    return 0
  fi
  return 1
}

confirm() {
  [ "$ASSUME_YES" -eq 0 ] || return 0
  # No terminal means nobody can answer. Refusing is the safe default: the
  # alternative is a build that silently installs distro packages.
  [ -t 0 ] || return 1
  local reply=""
  printf '    %s [y/N] ' "$1"
  read -r reply || return 1
  case "$reply" in [yY]*) return 0 ;; *) return 1 ;; esac
}

# ── 1. find a usable interpreter ─────────────────────────────────────────────
step "1/6  Locating Python 3.${MIN_MINOR}+"

python_ok() {
  local candidate="$1"
  [ -n "$candidate" ] && command -v "$candidate" >/dev/null 2>&1 || return 1
  "$candidate" -c "import sys; sys.exit(0 if sys.version_info >= (3, ${MIN_MINOR}) else 1)" >/dev/null 2>&1
}

SYS_PY=""
if [ -n "$PYTHON_OVERRIDE" ]; then
  python_ok "$PYTHON_OVERRIDE" || die "$PYTHON_OVERRIDE is not Python 3.${MIN_MINOR} or newer."
  SYS_PY="$PYTHON_OVERRIDE"
else
  # Newest first, so a box with both 3.11 and 3.13 uses 3.13.
  for candidate in python3.14 python3.13 python3.12 python3.11 python3 python; do
    if python_ok "$candidate"; then SYS_PY="$candidate"; break; fi
  done
fi

[ -n "$SYS_PY" ] || die "No Python 3.${MIN_MINOR}+ found. Install it with your package manager, e.g.:
         sudo apt install python3 python3-venv     (Debian, Ubuntu, Kali)
         sudo dnf install python3                  (Fedora, RHEL)
         sudo pacman -S python                     (Arch)
       Then re-run this script."

PY_VERSION="$("$SYS_PY" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
PY_MM="$("$SYS_PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
ok "Python $PY_VERSION at $(command -v "$SYS_PY")"

# ── 2. make sure the venv module actually works ──────────────────────────────
step "2/6  Checking the venv module"

# Debian and its derivatives split venv out of the python3 package, so
# `python3 -m venv` exists as a module and then fails at the ensurepip step
# with a message about python3-venv. Probing for real catches that now rather
# than halfway through creating the environment.
venv_works() {
  local probe
  probe="$(mktemp -d)"
  if "$SYS_PY" -m venv "$probe/t" >/dev/null 2>&1; then
    rm -rf "$probe"; return 0
  fi
  rm -rf "$probe"; return 1
}

if venv_works; then
  ok "venv is available"
else
  warn "python3 -m venv is not usable on this system yet."
  VENV_PKG=""
  INSTALL_CMD=""
  if command -v apt-get >/dev/null 2>&1; then
    # The versioned package is the reliable one on Debian/Kali; plain
    # python3-venv is a metapackage that can lag behind the default python3.
    if apt-cache policy "python${PY_MM}-venv" 2>/dev/null | grep -q 'Candidate: [^(]'; then
      VENV_PKG="python${PY_MM}-venv"
    else
      VENV_PKG="python3-venv"
    fi
    INSTALL_CMD="apt-get update && apt-get install -y $VENV_PKG python3-pip"
  elif command -v dnf >/dev/null 2>&1; then
    VENV_PKG="python3-virtualenv"; INSTALL_CMD="dnf install -y python3-pip $VENV_PKG"
  elif command -v pacman >/dev/null 2>&1; then
    VENV_PKG="python-virtualenv"; INSTALL_CMD="pacman -S --noconfirm python-pip $VENV_PKG"
  elif command -v zypper >/dev/null 2>&1; then
    VENV_PKG="python3-virtualenv"; INSTALL_CMD="zypper install -y python3-pip $VENV_PKG"
  elif command -v apk >/dev/null 2>&1; then
    VENV_PKG="py3-virtualenv"; INSTALL_CMD="apk add --no-cache python3-dev py3-pip $VENV_PKG"
  fi

  [ -n "$INSTALL_CMD" ] || die "Could not identify your package manager.
       Install the venv module for Python $PY_MM yourself, then re-run."

  info "It needs the distro package: $VENV_PKG"
  info "Command: sudo $INSTALL_CMD"
  if ! need_sudo; then
    die "sudo is not available and this is not a root shell.
       Run as root, or install $VENV_PKG yourself and re-run."
  fi
  if ! confirm "Install $VENV_PKG now?"; then
    die "Declined. Install $VENV_PKG yourself, then re-run.
       Nothing on this system was changed."
  fi
  # shellcheck disable=SC2086 # INSTALL_CMD is an intentional command line.
  $SUDO sh -c "$INSTALL_CMD" || die "Installing $VENV_PKG failed. Read the output above."
  venv_works || die "venv is still unusable after installing $VENV_PKG."
  ok "venv is available"
fi

# ── 3. create the environment ────────────────────────────────────────────────
step "3/6  Creating the virtual environment"

if [ "$RECREATE" -eq 1 ] && [ -d "$VENV" ]; then
  info "Removing the existing .venv/ because --recreate was passed"
  rm -rf "$VENV"
fi

if [ -x "$PY" ]; then
  if "$PY" -c "import sys; sys.exit(0 if sys.version_info >= (3, ${MIN_MINOR}) else 1)" >/dev/null 2>&1; then
    ok "Reusing the existing .venv/ ($("$PY" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])'))"
  else
    die "The existing .venv/ runs a Python older than 3.${MIN_MINOR}.
       Rebuild it with:  ./install.sh --recreate
       It was not modified."
  fi
elif [ -e "$VENV" ]; then
  die "$VENV exists but has no bin/python — it is incomplete, or was built on another OS.
       Rebuild it with:  ./install.sh --recreate
       It was not modified."
else
  info "Creating $VENV"
  "$SYS_PY" -m venv "$VENV" || die "Could not create the virtual environment at $VENV"
  ok "Created .venv/"
fi

[ -x "$PY" ] || die "$PY is missing after creating the environment."

# ── 4. install dependencies, inside the environment only ─────────────────────
step "4/6  Installing dependencies into .venv/"

# Every pip call below goes through "$PY" -m pip. That is not a style choice:
# a bare `pip` resolves through PATH and can be the system one, which is
# exactly the install PEP 668 blocks and exactly the install that breaks a
# distro. Calling the venv's interpreter makes the target unambiguous.
info "Using: $PY -m pip   (the system Python is never touched)"

if ! "$PY" -m pip --version >/dev/null 2>&1; then
  warn "pip is missing inside the environment; bootstrapping it"
  "$PY" -m ensurepip --upgrade >/dev/null 2>&1 \
    || die "Could not bootstrap pip inside the environment.
       On Debian/Kali this usually means python${PY_MM}-venv is incomplete:
       sudo apt install --reinstall python${PY_MM}-venv"
fi

"$PY" -m pip install --upgrade pip setuptools wheel --quiet \
  || warn "Could not upgrade pip; continuing with the bundled version."

REQ="$ROOT/requirements.txt"
[ -f "$REQ" ] || REQ="$ROOT/backend/requirements.txt"
[ -f "$REQ" ] || die "No requirements.txt found at the repository root or in backend/."

build_deps_command() {
  # Headers for the three packages that still compile from source when no
  # wheel matches: cryptography (openssl, ffi, rust), pillow (zlib, jpeg) and
  # anything else with a C extension.
  if command -v apt-get >/dev/null 2>&1; then
    printf 'apt-get update && apt-get install -y build-essential python3-dev libffi-dev libssl-dev zlib1g-dev libjpeg-dev pkg-config'
  elif command -v dnf >/dev/null 2>&1; then
    printf 'dnf install -y gcc gcc-c++ python3-devel libffi-devel openssl-devel zlib-devel libjpeg-turbo-devel pkgconf'
  elif command -v pacman >/dev/null 2>&1; then
    printf 'pacman -S --noconfirm base-devel libffi openssl zlib libjpeg-turbo pkgconf'
  elif command -v zypper >/dev/null 2>&1; then
    printf 'zypper install -y gcc gcc-c++ python3-devel libffi-devel libopenssl-devel zlib-devel libjpeg8-devel pkg-config'
  elif command -v apk >/dev/null 2>&1; then
    printf 'apk add --no-cache build-base python3-dev libffi-dev openssl-dev zlib-dev jpeg-dev pkgconf'
  fi
}

info "Installing from $(basename "$(dirname "$REQ")")/$(basename "$REQ") — this takes a minute"

# --prefer-binary first. Without it pip will happily compile a package from
# source when the wheel it finds is a slightly older version, which turns a
# 40-second install into a toolchain problem. This matters most on a Python
# released recently enough that PyPI has not caught up: on 3.14, cryptography
# and pillow have no wheel yet for many platforms and both need C headers the
# distro does not install by default.
PIP_LOG="$(mktemp)"
if "$PY" -m pip install -r "$REQ" --prefer-binary >"$PIP_LOG" 2>&1; then
  rm -f "$PIP_LOG"
  ok "Dependencies installed"
else
  if grep -qiE "could not be found for|error: command .*(gcc|cc|clang).* failed|Microsoft Visual C|failed building wheel|RequiredDependencyException|rust" "$PIP_LOG"; then
    warn "A package had to compile from source and the build tools are missing."
    printf '\n'
    sed -n '$!{/error:/,$p}' "$PIP_LOG" | tail -12 | sed 's/^/      /'
    printf '\n'
    BUILD_CMD="$(build_deps_command)"
    if [ -n "$BUILD_CMD" ]; then
      info "The build headers this needs come from your distro:"
      info "  sudo $BUILD_CMD"
      if need_sudo && confirm "Install the build dependencies and retry?"; then
        # shellcheck disable=SC2086
        $SUDO sh -c "$BUILD_CMD" || die "Installing build dependencies failed. Read the output above."
        info "Retrying the Python dependency install"
        if "$PY" -m pip install -r "$REQ" --prefer-binary; then
          rm -f "$PIP_LOG"
          ok "Dependencies installed"
        else
          rm -f "$PIP_LOG"
          die "Still failing after installing the build dependencies. The output above has the cause."
        fi
      else
        rm -f "$PIP_LOG"
        die "Install the build dependencies above, then re-run ./install.sh

       If you are on a very new Python (3.14+), the faster fix is usually to
       build against a release PyPI has wheels for:
         ./install.sh --recreate --python /usr/bin/python3.12"
      fi
    else
      rm -f "$PIP_LOG"
      die "A package needed to compile and no supported package manager was found.
       Install a C toolchain plus the openssl, ffi, zlib and jpeg headers, then re-run."
    fi
  else
    printf '\n'
    tail -20 "$PIP_LOG" | sed 's/^/      /'
    rm -f "$PIP_LOG"
    printf '\n'
    die "Dependency installation failed. The tail of pip's output is above; reproduce it with:
       $PY -m pip install -r $REQ"
  fi
fi

# ── 5. configuration ─────────────────────────────────────────────────────────
step "5/6  Configuration"

if [ -f "$ROOT/.env" ]; then
  ok ".env already exists — left exactly as it is"
elif [ -f "$ROOT/.env.example" ]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  ok "Created .env from .env.example (defaults work for local use)"
else
  warn "No .env.example found; skipping. The defaults in code still apply."
fi

# A launcher, so nobody has to remember the path into .venv or keep a shell
# activated. Activation is one way to select an interpreter; naming it
# directly is another, and it works from cron and systemd where no shell ever
# sources an activate script.
LAUNCHER="$ROOT/recontitan"
cat > "$LAUNCHER" <<'LAUNCH'
#!/usr/bin/env bash
# ReconTitan launcher — runs the CLI inside this repository's virtual
# environment without needing it activated first.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ]; then
  printf 'error: %s is missing. Run ./install.sh first.\n' "$PY" >&2
  exit 1
fi
exec "$PY" "$ROOT/recontitan.py" "$@"
LAUNCH
chmod +x "$LAUNCHER"
ok "Wrote the ./recontitan launcher"

if [ "$WITH_TOOLS" -eq 1 ]; then
  step "5b   Optional scanner binaries"
  TOOLS_CMD=""
  if command -v apt-get >/dev/null 2>&1;  then TOOLS_CMD="apt-get install -y nmap whois"
  elif command -v dnf >/dev/null 2>&1;    then TOOLS_CMD="dnf install -y nmap whois"
  elif command -v pacman >/dev/null 2>&1; then TOOLS_CMD="pacman -S --noconfirm nmap whois"
  elif command -v apk >/dev/null 2>&1;    then TOOLS_CMD="apk add --no-cache nmap whois"
  fi
  if [ -z "$TOOLS_CMD" ]; then
    warn "Unknown package manager; skipping optional tools."
  elif ! need_sudo; then
    warn "sudo unavailable; skipping optional tools."
  elif confirm "Install nmap and whois via the distro?"; then
    # Not fatal. These widen coverage; the scanner reports their absence and
    # falls back rather than failing, so a refusal here is not an error.
    # shellcheck disable=SC2086
    $SUDO sh -c "$TOOLS_CMD" || warn "Optional tool installation failed; continuing."
  else
    info "Skipped."
  fi
fi

# ── 6. verify ────────────────────────────────────────────────────────────────
step "6/6  Verifying the installation"

"$PY" -c 'import fastapi, requests, dns.resolver' >/dev/null 2>&1 \
  || die "Core dependencies are not importable inside the environment."
ok "Core imports resolve"

if "$PY" "$ROOT/recontitan.py" --list-modules >/dev/null 2>&1; then
  ok "CLI runs"
else
  die "The CLI did not start. Reproduce the error with:
       $PY $ROOT/recontitan.py --list-modules"
fi

printf '\n%s%s  Installation complete.%s\n\n' "$C_GREEN" "$C_BOLD" "$C_RESET"

if [ "$RUN_AFTER" -eq 1 ]; then
  # Launch rather than describe. --run exists for the case where the installer
  # is the first thing someone has run and they want to see the tool work,
  # not read about it.
  step "Launching"
  exec "$LAUNCHER" --help
fi

cat <<EOF
  Run a scan
    ./recontitan example.com --profile recon
    ./recontitan --list-modules
    ./recontitan --help

  Or activate the environment and use python directly
    source .venv/bin/activate
    python recontitan.py example.com

  Start the web UI on http://127.0.0.1:8000
    ASYNC_SCANS_ENABLED=false .venv/bin/python -m uvicorn app.main:app \\
      --app-dir backend --host 127.0.0.1 --port 8000

  ${C_DIM}Only scan systems you own or have explicit written permission to test.${C_RESET}
  ${C_DIM}Remove everything this installed with:  rm -rf .venv .env recontitan${C_RESET}

EOF
