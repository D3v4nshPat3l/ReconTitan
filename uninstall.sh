#!/usr/bin/env bash
# =============================================================================
#  ReconTitan uninstall for macOS and Linux.
#
#  This asks about every item separately and defaults to KEEPING it. Nothing is
#  removed unless you type y for that specific item, and each item's exact path
#  and size is shown before the question.
#
#  It only offers to remove things setup.sh created. Your scan reports, your
#  .env secrets and the project source are handled separately and explicitly.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
VENV="$ROOT/.venv"
MANIFEST="$ROOT/.recontitan-install.log"
REMOVED=0
KEPT=0

# Same reason as setup.sh: on Windows the environment lives in .venv/Scripts,
# so this script would report "not present" for a venv that is right there.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    cat <<'WRONGSHELL'

  This is the macOS and Linux uninstaller, but it is running on Windows
  (Git Bash / MSYS). Use the Windows one instead:

      uninstall.bat

WRONGSHELL
    exit 1
    ;;
esac

if [ -t 1 ]; then
  B=$'\033[1m'; OK=$'\033[32m'; WARN=$'\033[33m'; N=$'\033[0m'
else
  B=""; OK=""; WARN=""; N=""
fi

say()  { printf '%s\n' "$*"; }
rule() { printf ' ---------------------------------------------------------------------------\n'; }
info() { printf '     %s\n' "$*"; }
good() { printf '     %s%s%s\n' "$OK" "$*" "$N"; }

human_size() {
  if [ -d "$1" ]; then du -sh "$1" 2>/dev/null | cut -f1; else echo "n/a"; fi
}

ask() {   # ask "prompt"  -> returns 0 for yes
  printf '     %s [y/N] ' "$1"
  read -r reply
  case "$reply" in y|Y) return 0 ;; *) return 1 ;; esac
}

cat <<BANNER

 ============================================================================

   ReconTitan - Uninstall

 ============================================================================

  This will go through everything setup.sh created, ${B}ONE ITEM AT A TIME${N}.

  For each item you will see:
    - exactly what it is
    - exactly where it lives
    - how much disk space it uses

  Then you choose to keep it or remove it. The default is ${B}KEEP${N}.
  Nothing is deleted unless you type "y" for that specific item.

BANNER

if [ -f "$MANIFEST" ]; then
  say "  Reading the install record from:"
  say "    $MANIFEST"
else
  say "  No install record found. That is fine - this script will still check"
  say "  for the standard items and ask about each one it finds."
fi

say ""
say " ============================================================================"
say ""
printf '  Continue? [y/N] '
read -r GO
case "$GO" in
  y|Y) ;;
  *) say ""; say "  Cancelled. Nothing was changed."; say ""; exit 0 ;;
esac

# --- 1. venv -----------------------------------------------------------------
say ""; rule
say "  ITEM 1 of 5:  Python environment (.venv)"
rule
if [ -d "$VENV" ]; then
  say ""
  info "What:  The private Python environment and every package installed"
  info "       into it (FastAPI, uvicorn, pymongo and the rest)."
  info "Where: $VENV"
  info "Size:  $(human_size "$VENV")"
  say ""
  info "Removing this frees the most space. It does NOT affect your system"
  info "Python or any other project. You can recreate it any time by"
  info "running ./setup.sh again."
  say ""
  if ask "Remove it?"; then
    info "Deleting $VENV ..."
    rm -rf "$VENV"
    good "Removed."
    REMOVED=$((REMOVED+1))
  else
    info "Kept."
    KEPT=$((KEPT+1))
  fi
else
  say ""
  info "Not present - nothing to remove."
fi

# --- 2. .env -----------------------------------------------------------------
say ""; rule
say "  ITEM 2 of 5:  Configuration file (.env)"
rule
if [ -f "$ROOT/.env" ]; then
  say ""
  info "What:  Your local settings. ${WARN}THIS MAY CONTAIN SECRETS${N} - your admin"
  info "       token, API keys and database passwords."
  info "Where: $ROOT/.env"
  say ""
  info "Keep it if you plan to run ReconTitan again and do not want to"
  info "reconfigure. Remove it if you are wiping this machine clean."
  say ""
  if ask "Remove it?"; then
    rm -f "$ROOT/.env"
    good "Removed."
    REMOVED=$((REMOVED+1))
  else
    info "Kept."
    KEPT=$((KEPT+1))
  fi
else
  say ""
  info "Not present - nothing to remove."
fi

# --- 3. caches ---------------------------------------------------------------
say ""; rule
say "  ITEM 3 of 5:  Python bytecode caches (__pycache__)"
rule
say ""
info "What:  Compiled bytecode Python generates automatically while running."
info "Where: __pycache__ directories throughout this project."
say ""
info "These are always safe to remove. Python simply regenerates them."
say ""
if ask "Remove them?"; then
  COUNT=$(find "$ROOT" -type d -name '__pycache__' 2>/dev/null | wc -l | tr -d ' ')
  find "$ROOT" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null
  good "Removed ${COUNT} cache directory(ies)."
  REMOVED=$((REMOVED+1))
else
  info "Kept."
  KEPT=$((KEPT+1))
fi

# --- 4. Python ---------------------------------------------------------------
say ""; rule
say "  ITEM 4 of 5:  Python itself"
rule
say ""
if [ -f "$MANIFEST" ] && grep -q "PYTHON_INSTALLED_BY_SETUP=1" "$MANIFEST" 2>/dev/null; then
  INSTALL_CMD="$(grep '^PYTHON_INSTALL_CMD=' "$MANIFEST" 2>/dev/null | cut -d= -f2-)"
  info "setup.sh installed Python on this machine with:"
  info "  ${INSTALL_CMD:-(command not recorded)}"
  say ""
  info "${WARN}Be careful here.${N} On Linux especially, the system itself depends on"
  info "Python - removing it can break your package manager and desktop."
  say ""
  info "This script will NOT do it for you. If you are certain you want it"
  info "gone, reverse the command above by hand, with 'remove' in place of"
  info "'install'. Read what your package manager says it will take with it."
  KEPT=$((KEPT+1))
else
  info "Python was ALREADY on this system before you ran setup.sh."
  say ""
  info "This script will NOT touch it. Other software on your machine"
  info "almost certainly depends on it."
fi

# --- 5. nmap -----------------------------------------------------------------
say ""; rule
say "  ITEM 5 of 5:  nmap"
rule
say ""
if [ -f "$MANIFEST" ] && grep -q "INSTALLED_NMAP=1" "$MANIFEST" 2>/dev/null; then
  NMAP_CMD="$(grep '^NMAP_INSTALL_CMD=' "$MANIFEST" 2>/dev/null | cut -d= -f2-)"
  info "setup.sh installed nmap with:"
  info "  ${NMAP_CMD:-(command not recorded)}"
  say ""
  info "nmap is a general-purpose tool. You may well want it independently of"
  info "this project, and other software may have started using it."
  say ""
  if ask "Remove nmap?"; then
    REMOVE_CMD="$(printf '%s' "$NMAP_CMD" | sed 's/install -y/remove -y/; s/install/uninstall/; s/-S --noconfirm/-R --noconfirm/')"
    info "Running: $REMOVE_CMD"
    eval "$REMOVE_CMD" && good "Removed." || warn "Removal failed - remove it by hand if you still want it gone."
    REMOVED=$((REMOVED+1))
  else
    info "Kept."
    KEPT=$((KEPT+1))
  fi
else
  info "nmap was not installed by setup.sh, so this script will not touch it."
fi

# --- Not touched -------------------------------------------------------------
say ""; rule
say "  NOT TOUCHED BY THIS SCRIPT"
rule
say ""
info "- The project source code in this folder. Delete the folder yourself"
info "  if you want it gone."
info "- MongoDB, Redis, Docker or Ollama, if you installed any of them."
info "  They were not installed by setup.sh, so removing them is your call."
info "- Any scan reports you exported."
say ""

# Keep the record if anything survived: it is what tells a later run whether
# setup installed Python, and deleting it would lose that.
if [ "$KEPT" -eq 0 ]; then
  rm -f "$MANIFEST" 2>/dev/null
else
  say "  Install record kept at $MANIFEST, since some items remain."
  say ""
fi

cat <<DONE
 ============================================================================

   Finished.  ${REMOVED} item(s) removed,  ${KEPT} item(s) kept.

   To reinstall at any time, run ./setup.sh

 ============================================================================

DONE
