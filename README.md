# VPN Routes: a Proton VPN split-tunnelling check for Dux Shell / DMS

This is a bar widget for [Dux Shell](https://duxlabs.dev) (formerly DankMaterialShell). It shows which apps **actually** route through the Proton VPN tunnel and which go direct. It flags split-tunnelling problems, and it can restart a misrouted app with one (confirmed) click.

Proton's Linux app only applies split tunnelling to connections an app opens *after* the app is tracked. An app that was started before the VPN came up stays in the tunnel until it's restarted, and nothing on screen tells you. This widget does.

## Install

```sh
git clone <this repo> ~/.config/dms/plugins/VpnRoutes
dms ipc call plugin-scan scan
dms ipc call plugins enable vpnRoutes
```

Then add **VPN Routes** to the bar in DMS Settings → Plugins.

Requirements: `python3`, `ss` (iproute2), `nmcli`, `systemd-run`, and the official Proton VPN app with split tunnelling (exclude or include mode). No root is needed.

## What it shows

| Bar icon | Meaning |
|---|---|
| Blue lock | Everything is routed as configured |
| Amber warning + "N apps" | Excluded apps still have connections inside the VPN, so they need a restart |
| Red shield | An app that should use the VPN is going direct (a leak) |
| Grey "VPN off" | The VPN is disconnected |

Click the icon to see each app with internet connections, whether it goes through the VPN or direct, and how many connections it has.

## How it decides

`vpn-routes.py` runs `ss -tunpH state established`. For every connection to a public address, the local (source) address shows the route the kernel actually picked when the socket was created: the tunnel IP on `proton0` means VPN, and the LAN IP means direct. That result is compared with the split-tunnel config in `~/.config/Proton/VPN/settings.json`. The script resolves each process's exe and walks up its parent processes, the same way Proton does.

LAN, loopback and CGNAT/Tailscale peers are ignored, because they never use the tunnel.

## How Proton split tunnelling works on Linux (daemon v0.13.x)

- The system service `proton.VPN` (Python + BCC/eBPF) watches `execve` with a kprobe. New processes are matched by **exe path prefix** against `app_paths`, and forked children inherit the match.
- A cgroup `sock_create` eBPF hook on `user.slice` stamps sockets from tracked PIDs with the WireGuard fwmark. Those sockets skip the `not fwmark … lookup <vpn table>` rule and go out direct.
- Sockets created before tracking stay in the tunnel, so apps must be restarted after connecting.

### Gotcha: symlinked launchers

Proton matches the path **passed to execve**. It does not resolve symlinks.

Suppose a `.desktop` file runs `foo`, and `/usr/bin/foo` is a symlink to `/usr/lib/foo/foo`. An exclude entry of `/usr/lib/foo/foo` then never matches the main process. Electron/Chromium apps also start their network service via `/proc/self/exe`, so it is never matched either, and all traffic stays in the VPN.

Fix: also add the launcher path (e.g. `/usr/bin/claude-desktop`). The GUI picker resolves symlinks, so edit `settings.json` directly with the Proton app fully quit.

To debug, run `journalctl -u proton.VPN | grep "Process match"`. If the app's main PID never appears there, it was never matched.

## Restart buttons

A ⟳ button appears on misrouted rows. A setting adds it to every row. Click once to arm it ("Sure?" for 4 s), and click again to restart. The restart (`vpn-routes.py restart <key>`):

1. Re-computes the report itself; it never trusts data passed from the UI.
2. Finds the app's top process. Children of that process are left for the app to shut down itself.
3. Stops the app with SIGTERM, or with a per-app `stop` command.
4. Waits up to `timeout` s. **It never SIGKILLs**: an app that won't quit is left running and not relaunched.
5. Relaunches the app in its own `systemd-run --user --scope`, so a shell restart can't kill it.

It refuses to stop the shell, compositor, systemd, D-Bus, PipeWire and the Proton app.

### Per-app overrides: `restart.json`

Keys are the app name shown in the widget (case-insensitive) or its exclude path.

| Field | Meaning |
|---|---|
| `stop` | Command to use instead of SIGTERM |
| `launch` | Command to use instead of the app's original command line |
| `block_if` | Regex; if any running process's command line matches it, the restart is refused |
| `block_message` | Message shown when `block_if` matches |
| `timeout` | Seconds to wait for the app to quit (default 20) |
| `delay` | Seconds to wait before relaunching (default 1) |

The shipped overrides:

- **Steam:** stopped with `steam -shutdown`. Restarts are blocked while a game is running (`SteamLaunch AppId=`).
- **Spotify:** it catches SIGTERM and keeps running, so it is quit over MPRIS (`org.mpris.MediaPlayer2.Quit`) and relaunched via `spotify-launcher`.
- **Brave Origin and Vivaldi:** relaunched through their wrapper scripts, so their flags still apply.

If an app won't quit, check whether it catches SIGTERM with `grep SigCgt /proc/<pid>/status`. If bit `0x4000` is set, it does. For media players, try MPRIS `Quit`.

## Files

| File | Purpose |
|---|---|
| `plugin.json` | DMS plugin manifest (id `vpnRoutes`) |
| `VpnRoutesWidget.qml` | Bar pill + popout |
| `VpnRoutesSettings.qml` | Refresh interval, label toggle, restart-on-every-app toggle |
| `vpn-routes.py` | Report (default) and `restart <key>` backend |
| `restart.json` | Per-app restart overrides |

## Useful commands

```sh
python3 vpn-routes.py | jq                 # same data in a terminal
dms ipc call plugins reload vpnRoutes      # after editing the QML
dms ipc call plugin-scan scan              # pick up a newly added plugin
```

From a non-graphical shell, set `XDG_RUNTIME_DIR=/run/user/$(id -u)`, or `dms ipc` can't find the running shell.
