# macblock

A self-updating, adaptive DNS ad and tracker blocker for macOS. It blocks system-wide, in every browser and app.

## Install
```bash
sudo ./install.sh
```
You need `python3`. If it's missing, macOS will offer to install the Command Line Tools. The installer downloads the blocklists, starts the services, checks that they answer, and only then points your DNS at macblock.

## Everyday use
| Command | What it does |
|---|---|
| `macblock status` | Running or not, on/off/paused, list sizes, top blocked |
| `macblock recent` | The last 50 blocked names (start here when a page breaks) |
| `sudo macblock allow foo.com` | Unblocks foo.com |
| `sudo macblock block foo.com` | Always blocks foo.com and every subdomain |
| `sudo macblock pause 10` / `resume` | Stops blocking for a while, then turns it back on by itself |
| `sudo macblock dns off` / `on` / `toggle` | Takes macblock out of the DNS path, or puts it back |
| `macblock review` | Suspicious domains it has spotted but not blocked |
| `macblock test foo.com` | What it would do with a name, and why |
| `sudo macblock update` | Pulls the lists now (otherwise every 24h) |

**Macblock Menu** (menu bar) shows the state and blocked count, pauses, toggles, and allows recently blocked names. Opening the app also shows a small on/off panel. It is built at install time if a Swift compiler is present. To start it at login, add it under System Settings → General → Login Items. **Toggle macblock** is a double-click on/off app.

## How it stays out of the way
- **Fails open.** `guard.sh` runs as its own service in plain shell. If macblock stops answering (about 10-20 seconds), your previous DNS is restored; when it recovers, blocking resumes. If everything else is broken: `sudo /usr/local/macblock/guard.sh off`.
- **Drops root.** The DNS server binds port 53, then runs as `nobody`.
- **Encrypted upstreams.** DNS-over-HTTPS to Cloudflare and Quad9. A failed upstream is skipped for 60 seconds.
- **Network DNS fallback.** The DNS server your network hands out (unencrypted) is used for local names, for names the encrypted upstreams don't know, and when they are unreachable (captive portals). That network can therefore see those lookups. Set `"network_fallback": false` to turn this off.

## How it adapts
1. **List updates:** StevenBlack, HaGeZi Pro and the AdGuard DNS filter are merged daily and hot-reloaded.
2. **CNAME uncloaking:** a name that is a CNAME for a listed tracker is blocked and remembered for 30 days (`learned_days`), then re-checked.
3. **Heuristic scoring:** names that look like trackers go into a review queue. It is a hint, not a verdict; `auto_block` is off by default.

## Files
Settings: `/usr/local/macblock/config.json` (restart with `sudo launchctl kickstart -k system/com.macblock.dns`). Log: `/usr/local/macblock/data/macblock.log` (rotated at 1 MB). The recent and top-blocked lists in `data/` are readable by every user on the Mac.

## Limits
- Browser "Secure DNS" in Chrome, Edge and Brave bypasses system DNS; turn it off. iCloud Private Relay bypasses it for Safari.
- A VPN that pushes its own DNS bypasses macblock, and VPN-only DNS servers are not used by the fallback.
- DNS blocking can't remove YouTube or first-party ads. Keep uBlock Origin (or uBO Lite) for those.
- This is a Python service, not a Network Extension app.

## Development
```bash
python3 -m venv .venv && .venv/bin/pip install dnslib
.venv/bin/python -m unittest discover tests
```

## Uninstall
```bash
sudo ./uninstall.sh
```
This restores your previous DNS settings.
