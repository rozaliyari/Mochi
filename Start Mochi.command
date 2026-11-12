#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
fail() { echo "$1"; read -r -p 'Press Return to close… ' ignored; exit 1; }
BREW_BIN="$(command -v brew || true)"
[ -n "$BREW_BIN" ] || fail 'Homebrew is required first. Install it from https://brew.sh, then reopen this launcher.'
BREW_PREFIX="$("$BREW_BIN" --prefix)"
PYTHON_BIN="$BREW_PREFIX/opt/python@3.13/bin/python3.13"
OPENVPN_BIN="$BREW_PREFIX/sbin/openvpn"
if [ ! -x "$PYTHON_BIN" ] || ! "$PYTHON_BIN" -c 'import tkinter' >/dev/null 2>&1 || [ ! -x "$OPENVPN_BIN" ]; then
  echo 'First run: install OpenVPN and Python/Tk 3.13 using Homebrew?'
  read -r -p 'Type y to install, or Return to cancel: ' answer
  [ "$answer" = 'y' ] || exit 0
  "$BREW_BIN" install openvpn python-tk@3.13 || fail 'Dependency installation failed. Send the error output for help.'
fi
[ -x "$OPENVPN_BIN" ] || fail 'OpenVPN could not be found.'
"$PYTHON_BIN" -c 'import tkinter' || fail 'Python/Tk is not ready.'
echo 'Mochi needs administrator access to create VPN interfaces and routes.'
echo 'Enter your Mac login password below. Typing is hidden.'
/usr/bin/sudo -v || fail 'Administrator authentication was cancelled.'
"$PYTHON_BIN" launch.py "$OPENVPN_BIN" || fail 'Mochi could not start. See the error above.'
