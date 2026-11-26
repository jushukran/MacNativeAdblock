#!/bin/bash
# macblock uninstaller:  sudo ./uninstall.sh
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo:  sudo ./uninstall.sh"; exit 1; }

DIR=/usr/local/macblock
launchctl bootout system/com.macblock.guard 2>/dev/null
[[ -x $DIR/guard.sh ]] && "$DIR/guard.sh" off       # works even if Python is broken
launchctl bootout system/com.macblock.dns 2>/dev/null
pkill -x MacblockMenu 2>/dev/null
rm -f /Library/LaunchDaemons/com.macblock.{dns,guard}.plist /usr/local/bin/macblock
rm -rf "$DIR" "/Applications/Toggle macblock.app" "/Applications/Macblock Menu.app"
dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null
echo "macblock removed and DNS restored."
