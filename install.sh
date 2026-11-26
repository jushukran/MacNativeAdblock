#!/bin/bash
# macblock installer - run from this folder with:  sudo ./install.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo:  sudo ./install.sh"; exit 1; }
cd "$(dirname "$0")"
umask 022            # the daemon runs as nobody and must be able to read the code

DIR=/usr/local/macblock
DAEMONS=/Library/LaunchDaemons
PY=/usr/bin/python3   # Apple's python (installs with Xcode Command Line Tools)
[[ -x $PY ]] || PY=$(command -v python3)

# stop an older install first; stopping the guard restores your DNS
launchctl bootout system/com.macblock.guard 2>/dev/null || true
launchctl bootout system/com.macblock.dns 2>/dev/null || true

echo "==> Installing to $DIR"
mkdir -p "$DIR/data" /usr/local/bin
cp macblock.py guard.sh "$DIR/"
chmod 755 "$DIR" "$DIR/guard.sh"
chmod 644 "$DIR/macblock.py"
touch "$DIR/allowlist.txt" "$DIR/denylist.txt"

echo "==> Creating Python environment"
"$PY" -m venv "$DIR/venv"
"$DIR/venv/bin/pip" install --quiet --upgrade pip dnslib

cat > /usr/local/bin/macblock <<'WRAP'
#!/bin/bash
exec /usr/local/macblock/venv/bin/python /usr/local/macblock/macblock.py "$@"
WRAP
chmod 755 /usr/local/bin/macblock

echo "==> Downloading blocklists (DNS still normal at this point)"
macblock update
chown -R nobody:nobody "$DIR/data"

echo "==> Starting background service"
for label in com.macblock.dns com.macblock.guard; do
  cp "$label.plist" "$DAEMONS/"
  chown root:wheel "$DAEMONS/$label.plist"; chmod 644 "$DAEMONS/$label.plist"
done
launchctl bootstrap system "$DAEMONS/com.macblock.dns.plist"

echo "==> Checking it answers"
ok=""
for i in $(seq 1 20); do
  if [[ $(dig @127.0.0.1 health.macblock.test +short +time=2 +tries=1) == 127.0.0.1 ]] &&
     dig @127.0.0.1 apple.com +short +time=5 +tries=1 | grep -q '^[0-9]'; then ok=1; break; fi
  sleep 1
done
if [[ -z $ok ]]; then
  echo "!! macblock isn't answering - leaving your DNS unchanged. See $DIR/data/macblock.log and $DIR/crash.log"
  launchctl bootout system/com.macblock.dns 2>/dev/null || true
  exit 1
fi

echo "==> Pointing macOS DNS at macblock"
macblock dns on
launchctl bootstrap system "$DAEMONS/com.macblock.guard.plist"

echo "==> Adding the apps"
osacompile -o "/Applications/Toggle macblock.app" \
  -e 'try' \
  -e 'set out to do shell script "/usr/local/bin/macblock dns toggle 2>&1" with administrator privileges' \
  -e 'display dialog (last paragraph of out) buttons {"OK"} default button 1 giving up after 3' \
  -e 'on error msg number n' \
  -e 'if n is not -128 then display dialog msg buttons {"OK"} default button 1' \
  -e 'end try'

BAR="/Applications/Macblock Menu.app"
pkill -x MacblockMenu 2>/dev/null || true      # so the new build is what opens
if xcrun --find swiftc >/dev/null 2>&1; then
  mkdir -p "$BAR/Contents/MacOS"
  cp menubar/Info.plist "$BAR/Contents/"
  if ! xcrun swiftc -O menubar/main.swift -o "$BAR/Contents/MacOS/MacblockMenu"; then
    echo "   (menu bar app did not build - everything else works)"
    rm -rf "$BAR"
  else
    codesign --force --sign - "$BAR"
  fi
else
  echo "   (no Swift compiler - skipping the menu bar app)"
fi

echo
echo "Done. Try:  macblock status   |   macblock recent   |   sudo macblock pause"
echo "Menu bar icon: open \"Macblock Menu\" in Applications."
echo "Turn off any time:  sudo macblock dns off"
