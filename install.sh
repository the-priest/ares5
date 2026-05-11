#!/usr/bin/env bash
# Ares v5.0 installer
#
# This installer is deliberately minimal — it matches Ares' read-only
# philosophy.  It does NOT:
#   • install any system packages
#   • require sudo
#   • modify any system configuration
#   • touch ~/.bashrc unless you ask
#
# It only:
#   • verifies Python 3.10+ is available
#   • installs the optional 'groq' python package for AI summaries
#   • makes ares.py executable
#   • symlinks ~/.local/bin/ares → ares.py

set -e

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'
  CYN=$'\033[36m'; DIM=$'\033[90m'; RST=$'\033[0m'; BLD=$'\033[1m'
else
  RED=""; GRN=""; YEL=""; CYN=""; DIM=""; RST=""; BLD=""
fi

say()  { printf "%s\n" "${CYN}[ares]${RST} $*"; }
ok()   { printf "%s\n" "${GRN}  ✓${RST} $*"; }
warn() { printf "%s\n" "${YEL}  ⚠${RST} $*"; }
err()  { printf "%s\n" "${RED}  ✕${RST} $*"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARES_PY="$SCRIPT_DIR/ares.py"

if [ ! -f "$ARES_PY" ]; then
  err "ares.py not found in $SCRIPT_DIR"
  exit 1
fi

say "Ares v5.0 installer (read-only audit tool)"
say "working from: $SCRIPT_DIR"
echo

# ── Python check ──────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
  err "python3 not installed — install python3 (>= 3.10) first"
  exit 1
fi

PY_VER=$(python3 -c 'import sys; print("{}.{}".format(*sys.version_info[:2]))')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
  err "python $PY_VER detected — Ares needs Python 3.10+"
  exit 1
fi
ok "python3 $PY_VER"

# ── Python deps (only the optional groq package) ──────────────────
say "installing python deps (optional groq for AI summary)..."
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
  if pip install -r "$SCRIPT_DIR/requirements.txt" >/dev/null 2>&1; then
    ok "requirements.txt installed (pip)"
  elif pip install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages >/dev/null 2>&1; then
    ok "requirements.txt installed (--break-system-packages)"
  elif pip install -r "$SCRIPT_DIR/requirements.txt" --user >/dev/null 2>&1; then
    ok "requirements.txt installed (--user)"
  else
    warn "pip failed — Ares will still work, just without the AI summary"
    warn "  manual: pip install groq --break-system-packages"
  fi
else
  warn "requirements.txt not found — skipping python deps"
fi

# ── Make ares.py executable ───────────────────────────────────────
chmod +x "$ARES_PY"
ok "ares.py marked executable"

# ── Symlink as `ares` ─────────────────────────────────────────────
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
LINK="$BIN_DIR/ares"
ln -sf "$ARES_PY" "$LINK"
ok "symlinked $LINK → $ARES_PY"

case ":$PATH:" in
  *":$BIN_DIR:"*) ok "$BIN_DIR is on PATH" ;;
  *)
    warn "$BIN_DIR is NOT on PATH — add this to your shell rc:"
    warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    ;;
esac

# ── Groq API key check ────────────────────────────────────────────
echo
if [ -n "${GROQ_API_KEY:-}" ]; then
  ok "GROQ_API_KEY is set — AI summary paragraph will work"
else
  warn "GROQ_API_KEY not set — AI summary will be skipped (Ares still works)"
  warn "  Get a free key at: https://console.groq.com"
  warn "  Then:  export GROQ_API_KEY=gsk_..."
fi

# ── Reminder about read-only nature ───────────────────────────────
echo
say "${BLD}done.${RST}  run:  ${GRN}ares${RST}"
echo
echo "${DIM}  Ares is read-only.  It will NOT modify your system.${RST}"
echo "${DIM}  Some checks need root to see everything.  If you want a${RST}"
echo "${DIM}  complete audit, run:  ${GRN}sudo ares${RST}${DIM}  — but it is NOT required.${RST}"
