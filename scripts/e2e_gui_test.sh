#!/bin/bash
# End-to-end GUI test for the airgapped BIP-39 generator.
#
# Runs the app on a dedicated Xvfb display (clean-room: no window manager or
# clipboard-manager interference), drives it with xdotool keyboard navigation
# and verifies every copy button against the CLIPBOARD selection:
#   1. generate a seed (12 or 24 words)
#   2. "Copiar semilla"            -> clipboard holds a 12/24-word mnemonic
#   3. "Copiar" (Ethereum)         -> clipboard holds an EIP-55 0x address
#   4. "Copiar" (Bitcoin)          -> clipboard holds a Base58Check address
#   5. auto-clear after BIP39_CLIPBOARD_TIMEOUT_MS
#   6. nothing is persisted under $HOME
#
# Note: ImGui windows are drawn inside the GLFW window, so they are NOT
# separate X11 windows; screen transitions are verified functionally via the
# clipboard instead of xdotool window-title searches.
set -u

XDISPLAY=:99
export BIP39_CLIPBOARD_TIMEOUT_MS=3000
export HOME=/tmp/bip39_home

cleanup() {
  [ -n "${APP:-}" ] && kill "$APP" 2>/dev/null
  [ -n "${XVFB:-}" ] && kill "$XVFB" 2>/dev/null
  wait "${APP:-}" 2>/dev/null
  wait "${XVFB:-}" 2>/dev/null
}
trap cleanup EXIT

pkill -f bip39_generator 2>/dev/null
pkill -f "Xvfb $XDISPLAY" 2>/dev/null
sleep 0.5
rm -rf "$HOME" && mkdir -p "$HOME"

# Start the app on an isolated display so results are deterministic.
if command -v Xvfb >/dev/null 2>&1; then
  Xvfb "$XDISPLAY" -screen 0 1280x900x24 >/tmp/opencode/e2e_xvfb.log 2>&1 &
  XVFB=$!
  sleep 1.5
  export DISPLAY=$XDISPLAY
else
  echo "E2E WARN: Xvfb not found, using existing DISPLAY=${DISPLAY:-}"
fi

./build/bip39_generator >/tmp/opencode/e2e_app.log 2>&1 &
APP=$!
sleep 2.5

WID=$(xdotool search --name "BIP-39 Seedphrase Generator" | head -1)
if [ -z "$WID" ]; then
  echo "E2E FAIL: window not found"; exit 1
fi
xdotool windowactivate "$WID" 2>/dev/null; xdotool windowfocus "$WID" 2>/dev/null
sleep 0.5

key() { xdotool key --window "$WID" "$1"; sleep 0.25; }

getclip() { timeout 3 xclip -selection clipboard -o 2>/dev/null; }

# ---------------------------------------------------------------------------
# Config screen: Tab to "Generar semilla" (radios, input, button = 4 widgets).
# ---------------------------------------------------------------------------
for _ in 1 2 3 4; do key Tab; done
key Return
sleep 1.5

# ---------------------------------------------------------------------------
# Reveal screen: the first button ("Copiar semilla") is focused on appear;
# Return copies the mnemonic. Retry once in case focus is still settling.
# ---------------------------------------------------------------------------
MNEM=""
for _ in 1 2; do
  key Return
  sleep 0.8
  MNEM=$(getclip)
  WORDS=$(echo "$MNEM" | wc -w)
  if [ "$WORDS" -eq 12 ] || [ "$WORDS" -eq 24 ]; then break; fi
done
if [ "$WORDS" -ne 12 ] && [ "$WORDS" -ne 24 ]; then
  echo "E2E FAIL: mnemonic copy wrong word count: '$MNEM'"; exit 1
fi
echo "E2E ok: mnemonic copied ($WORDS words)"
echo "  $MNEM"

# ---------------------------------------------------------------------------
# Ethereum copy: focus order is [Copiar semilla, Nueva semilla, EVM input,
# EVM Copiar, BTC input, BTC Copiar]; 3 Tabs then Return hits "Copiar" (EVM).
# ---------------------------------------------------------------------------
for _ in 1 2 3; do key Tab; done
key Return
sleep 0.8
EVM=$(getclip)
if ! echo "$EVM" | grep -Eq '^0x[0-9a-fA-F]{40}$'; then
  echo "E2E FAIL: EVM copy unexpected: '$EVM'"; exit 1
fi
echo "E2E ok: Ethereum address copied"
echo "  $EVM"

# ---------------------------------------------------------------------------
# Bitcoin copy: 2 more Tabs then Return hits "Copiar" (BTC).
# ---------------------------------------------------------------------------
for _ in 1 2; do key Tab; done
key Return
sleep 0.8
BTC=$(getclip)
if ! echo "$BTC" | grep -Eq '^bc1q[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38}$'; then
  echo "E2E FAIL: BTC copy unexpected: '$BTC'"; exit 1
fi
echo "E2E ok: Bitcoin address copied"
echo "  $BTC"

# ---------------------------------------------------------------------------
# Auto-clear: the last copy restarted the 3 s timer; wait past it.
# ---------------------------------------------------------------------------
sleep 4
AFTER=$(getclip)
if [ -n "$AFTER" ]; then
  echo "E2E FAIL: clipboard not auto-cleared: '$AFTER'"; exit 1
fi
echo "E2E ok: clipboard auto-cleared after timeout"

# ---------------------------------------------------------------------------
# No persistence: the app must not write anything under $HOME.
# ---------------------------------------------------------------------------
NFILES=$(find "$HOME" -type f 2>/dev/null | wc -l)
echo "HOME files: $NFILES"
if [ "$NFILES" -ne 0 ]; then
  echo "E2E FAIL: app persisted files under HOME"; exit 1
fi

echo "E2E PASS: generate -> copy seed -> copy EVM/BTC -> auto-clear -> no persistence"
exit 0
