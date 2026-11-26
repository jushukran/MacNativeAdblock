#!/bin/bash
# macblock guard: the only code that changes macOS DNS settings.
# Plain shell on purpose, so DNS can be restored even if Python is broken.
#
#   guard.sh on | off   point DNS at macblock / restore what was there
#   guard.sh watch      (launchd) keep DNS on macblock only while it answers
DIR="${MACBLOCK_HOME:-/usr/local/macblock}"
NS="${MACBLOCK_NETWORKSETUP:-/usr/sbin/networksetup}"
DIG="${MACBLOCK_DIG:-/usr/bin/dig}"
ADDR=127.0.0.1
PORT=53
BACKUP="$DIR/dns_backup.tsv"     # service <TAB> servers (empty = automatic)
ENABLED="$DIR/enabled"           # present = the user wants blocking on
CHANGED=0

services() { "$NS" -listallnetworkservices </dev/null | tail -n +2 | grep -v '^\*'; }

current() {                      # DNS servers of $1 on one line, empty if automatic
  local out
  out=$("$NS" -getdnsservers "$1" </dev/null) || return 1
  case "$out" in *"aren't any"*) return 0 ;; esac
  echo $out
}

saved() { [[ -f $BACKUP ]] && awk -F'\t' -v s="$1" '$1==s{print $2}' "$BACKUP"; }

save() {                         # remember original servers $2 of service $1
  { [[ -f $BACKUP ]] && awk -F'\t' -v s="$1" '$1!=s' "$BACKUP"
    printf '%s\t%s\n' "$1" "$2"; } >"$BACKUP.tmp" && mv "$BACKUP.tmp" "$BACKUP"
}

flush() {
  dscacheutil -flushcache 2>/dev/null
  killall -HUP mDNSResponder 2>/dev/null
}

point_at_us() {
  local svc cur
  CHANGED=0
  while IFS= read -r svc; do
    cur=$(current "$svc") || continue
    [[ $cur == "$ADDR" ]] && continue
    save "$svc" "$cur" || { echo "cannot write $BACKUP - not touching $svc"; return 1; }
    "$NS" -setdnsservers "$svc" "$ADDR" </dev/null && echo "$svc: DNS -> $ADDR" && CHANGED=1
  done < <(services)
  [[ $CHANGED == 1 ]] && flush
  return 0
}

restore() {                      # only touches services that point at macblock
  local svc old
  CHANGED=0
  while IFS= read -r svc; do
    [[ $(current "$svc") == "$ADDR" ]] || continue
    old=$(saved "$svc")
    "$NS" -setdnsservers "$svc" ${old:-Empty} </dev/null && echo "$svc: DNS -> ${old:-automatic}" && CHANGED=1
  done < <(services)
  [[ $CHANGED == 1 ]] && flush
  return 0
}

healthy() {                      # the daemon answers this name itself, no upstream needed
  [[ $("$DIG" @"$ADDR" -p "$PORT" health.macblock.test A +short +time=2 +tries=1 2>/dev/null) == "$ADDR" ]]
}

tick() {                         # one watchdog step; FAILS counts misses in a row
  [[ -f $ENABLED ]] || { FAILS=0; return; }
  if healthy; then
    FAILS=0
    point_at_us
  else
    FAILS=$((FAILS + 1))
    if (( FAILS >= 3 )); then
      restore
      [[ $CHANGED == 1 ]] && echo "$(date '+%F %T') macblock not answering - DNS restored"
    fi
  fi
}

watch_loop() {
  FAILS=0
  # shutdown, reboot or `launchctl bootout`: leave the Mac with working DNS
  trap 'restore; exit 0' TERM INT
  while :; do
    tick
    sleep $(( FAILS > 0 ? 3 : 10 )) &
    wait $!
  done
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  case "${1:-}" in
    on)    touch "$ENABLED" && point_at_us ;;
    off)   rm -f "$ENABLED"; restore ;;
    watch) watch_loop ;;
    *)     echo "usage: guard.sh on|off|watch"; exit 2 ;;
  esac
fi
