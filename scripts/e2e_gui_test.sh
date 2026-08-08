#!/bin/bash
# End-to-end GUI test: generate a seed via keyboard nav, copy to clipboard,
# verify content, then verify auto-clear after BIP39_CLIPBOARD_TIMEOUT_MS.
set -u
DISPLAY="${DISPLAY:-:0}"
export DISPLAY
export HOME=/tmp/bip39_home
export BIP39_CLIPBOARD_TIMEOUT_MS=3000

pkill -f bip39_generator 2>/dev/null
rm -rf /tmp/bip39_home && mkdir -p /tmp/bip39_home
./build/bip39_generator >/tmp/opencode/e2e_app.log 2>&1 &
APP=$!
sleep 2.5

WID=$(xdotool search --name "BIP-39 Seedphrase Generator" | head -1)
if [ -z "$WID" ]; then echo "E2E FAIL: window not found"; kill $APP; exit 1; fi
xdotool windowactivate "$WID" 2>/dev/null; xdotool windowfocus "$WID" 2>/dev/null
sleep 0.3

# Config screen: Tab to the "Generar semilla" button (4 widgets) and press Enter.
for _ in 1 2 3 4; do xdotool key --window "$WID" Tab; sleep 0.15; done
xdotool key --window "$WID" Return
sleep 1.2

if ! xdotool search --name "Semilla generada" >/dev/null; then
  echo "E2E FAIL: reveal screen did not appear"; kill $APP; exit 1
fi
echo "E2E ok: reveal screen shown"

# Reveal screen: first button is "Copiar al portapapeles (auto-limpieza)".
xdotool key --window "$WID" Tab; sleep 0.15
xdotool key --window "$WID" Return
sleep 0.8

CLIP=$(xclip -selection clipboard -o 2>/dev/null)
WORDS=$(echo "$CLIP" | wc -w)
echo "E2E clipboard after copy: words=$WORDS"
if [ "$WORDS" -ne 12 ] && [ "$WORDS" -ne 24 ]; then
  echo "E2E FAIL: unexpected clipboard content: '$CLIP'"; kill $APP; exit 1
fi

# Wait past the 3 s auto-clear timeout.
sleep 4
CLIP2=$(xclip -selection clipboard -o 2>/dev/null)
WORDS2=$(echo "$CLIP2" | wc -w)
echo "E2E clipboard after 4s: words=${WORDS2:-0} (empty ok)"
if [ -n "$CLIP2" ]; then
  echo "E2E FAIL: clipboard not cleared"; kill $APP; exit 1
fi
echo "E2E PASS: generate -> copy -> auto-clear verified"
echo "HOME files: $(find /tmp/bip39_home -type f | wc -l)"
kill $APP 2>/dev/null
wait $APP 2>/dev/null
exit 0
