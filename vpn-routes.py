#!/usr/bin/env python3
"""Report which apps actually route through the Proton VPN tunnel.

Ground truth comes from the kernel: for every established socket owned by
the current user, the local (source) address shows which route was picked
when the socket was created -- the tunnel IP on proton0, or the LAN IP.
That is compared against the Proton split-tunnelling config to flag apps
that need a restart (should be excluded but still use the VPN) or leaks
(should use the VPN but go direct). Needs no root.

Usage:
  vpn-routes.py                 print the routing report as JSON (read-only)
  vpn-routes.py restart <key>   gracefully stop the app with that key and
                                start it again in its own systemd scope
"""
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

IFACE = os.environ.get("VPN_IFACE", "proton0")
SETTINGS = os.path.expanduser("~/.config/Proton/VPN/settings.json")
RECIPES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "restart.json")
USERS_RE = re.compile(r'\("([^"]*)",pid=(\d+),fd=\d+\)')
# Never stop these, whatever the report says.
PROTECTED = {"qs", "quickshell", "niri", "systemd", "dms", "dbus-daemon", "dbus-broker",
             "pipewire", "wireplumber", "protonvpn-app", "python", "python3"}


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""


def vpn_state():
    ips = []
    for line in run(["ip", "-o", "addr", "show", "dev", IFACE]).splitlines():
        m = re.search(r"\binet6? ([0-9a-fA-F.:]+)/", line)
        if m:
            ips.append(m.group(1))
    name = ""
    for line in run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"]).splitlines():
        conn, _, dev = line.rpartition(":")
        if dev == IFACE:
            name = conn.replace("\\:", ":")
    return {"up": bool(ips), "iface": IFACE, "ips": ips, "name": name}


def split_config():
    try:
        with open(SETTINGS) as f:
            st = json.load(f)["features"]["split_tunneling"]
        mode = st.get("mode", "exclude")
        paths = st.get("config_by_mode", {}).get(mode, {}).get("app_paths", [])
        return {"enabled": bool(st.get("enabled")), "mode": mode, "paths": [p for p in paths if p]}
    except Exception:
        return {"enabled": False, "mode": "exclude", "paths": []}


def proc_info(pid, cache):
    if pid in cache:
        return cache[pid]
    info = {"exe": "", "ppid": 0, "cmdline": [], "comm": "", "paths": []}
    try:
        info["exe"] = os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)")
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/stat") as f:
            info["ppid"] = int(f.read().rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        pass
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            info["cmdline"] = [a.decode(errors="replace") for a in f.read().split(b"\0") if a]
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/comm") as f:
            info["comm"] = f.read().strip()
    except OSError:
        pass
    info["paths"] = match_paths(info)
    cache[pid] = info
    return info


def match_paths(info):
    """Paths a process can be matched by: its resolved binary and, because Proton
    doesn't resolve symlinks, the path it was launched as (argv[0], looked up in
    PATH when it is a bare name)."""
    paths = [info["exe"]] if info["exe"] else []
    argv0 = info["cmdline"][0] if info["cmdline"] else ""
    if argv0 and "/" not in argv0:
        argv0 = shutil.which(argv0) or ""
    if argv0.startswith("/") and argv0 not in paths:
        paths.append(argv0)
    return paths


def matches(info, path):
    return any(p.startswith(path) for p in info["paths"])


def matched_path(pid, paths, cache):
    """Config path matched by the process or any ancestor (Proton does the same)."""
    seen = set()
    while pid > 1 and pid not in seen:
        seen.add(pid)
        info = proc_info(pid, cache)
        for p in paths:
            if matches(info, p):
                return p
        pid = info["ppid"]
    return None


def parse_ip(hostport):
    host = hostport.rsplit(":", 1)[0].strip("[]").split("%")[0]
    if host.startswith("::ffff:"):
        host = host[7:]
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def pretty(procs):
    name = min(procs, key=len).removesuffix("-bin")
    return " ".join(w[:1].upper() + w[1:] for w in re.split(r"[-_]", name) if w)


def build_report(cache):
    vpn = vpn_state()
    split = split_config()
    vpn_ips = {ipaddress.ip_address(i) for i in vpn["ips"]}
    apps = {}

    out = run(["ss", "-tunpH", "state", "established"])
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 6:
            continue
        local, peer = parse_ip(cols[3]), parse_ip(cols[4])
        if not local or not peer or not peer.is_global:
            continue  # LAN, loopback, Tailscale etc. never use the tunnel anyway
        route = "vpn" if local in vpn_ips else "direct"
        counted = set()  # ss lists every (pid, fd) holding the socket; count it once per app
        for comm, pid in dict.fromkeys(USERS_RE.findall(" ".join(cols[5:]))):
            pid = int(pid)
            path = matched_path(pid, split["paths"], cache) if split["enabled"] else None
            if not vpn["up"]:
                expected = "direct"
            elif not split["enabled"]:
                expected = "vpn"
            elif split["mode"] == "include":
                expected = "vpn" if path else "direct"
            else:
                expected = "direct" if path else "vpn"
            key = path or comm
            a = apps.setdefault(key, {
                "key": key, "name": "", "match": path or "",
                "expected": expected, "vpn": 0, "direct": 0,
                "pids": set(), "procs": set(),
            })
            if key not in counted:
                counted.add(key)
                a[route] += 1
            a["pids"].add(pid)
            a["procs"].add(comm)

    issues = leaks = 0
    result = []
    for a in apps.values():
        if a["expected"] == "direct" and a["vpn"]:
            a["status"] = "restart" if vpn["up"] else "ok"
        elif a["expected"] == "vpn" and a["direct"]:
            a["status"] = "leak"
        else:
            a["status"] = "ok"
        issues += a["status"] != "ok"
        leaks += a["status"] == "leak"
        a["name"] = pretty(a["procs"])
        a["pids"] = sorted(a["pids"])
        a["procs"] = sorted(a["procs"])
        result.append(a)

    order = {"leak": 0, "restart": 1, "ok": 2}
    result.sort(key=lambda a: (order[a["status"]], a["expected"], a["name"].lower()))
    return {
        "ts": int(time.time()), "vpn": vpn, "split": split,
        "issues": issues, "leaks": leaks, "apps": result,
    }


# --------------------------------------------------------------------------- restart

def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def belongs(info, app, root_exe):
    if app["match"]:
        return info["exe"].startswith(app["match"])
    return bool(info["exe"]) and info["exe"] == root_exe


def find_roots(app, cache):
    """Topmost ancestor of each socket-owning pid that still belongs to the app."""
    roots = set()
    for pid in app["pids"]:
        own_exe = proc_info(pid, cache)["exe"]
        root, cur, seen = pid, pid, set()
        while cur > 1 and cur not in seen:
            seen.add(cur)
            parent = proc_info(cur, cache)["ppid"]
            if parent <= 1 or not belongs(proc_info(parent, cache), app, own_exe):
                break
            root = cur = parent
        roots.add(root)

    # Drop roots that descend from another root (e.g. Claude's VM under its helper):
    # stopping the top process lets the app shut its own children down.
    def ancestors(pid):
        seen = set()
        while pid > 1 and pid not in seen:
            seen.add(pid)
            pid = proc_info(pid, cache)["ppid"]
        return seen - {pid}

    return sorted(r for r in roots if not (ancestors(proc_info(r, cache)["ppid"]) & roots))


def load_recipe(app):
    try:
        with open(RECIPES) as f:
            recipes = json.load(f)
    except (OSError, ValueError):
        return {}
    for k, v in recipes.items():
        if k.startswith("_"):
            continue
        if k.lower() == app["name"].lower() or (app["match"] and k == app["match"]):
            return v
    return {}


def any_cmdline_matches(pattern):
    rx = re.compile(pattern)
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/cmdline", "rb") as f:
                if rx.search(f.read().replace(b"\0", b" ").decode(errors="replace")):
                    return True
        except OSError:
            pass
    return False


def restart(key):
    cache = {}
    app = next((a for a in build_report(cache)["apps"] if a["key"] == key), None)
    if not app:
        return {"ok": False, "message": "App not found any more (no live connections)."}
    name = app["name"]
    recipe = load_recipe(app)

    if recipe.get("block_if") and any_cmdline_matches(recipe["block_if"]):
        return {"ok": False, "message": recipe.get("block_message", f"{name} is busy; not restarting.")}

    roots = find_roots(app, cache)
    for r in roots:
        info = proc_info(r, cache)
        if os.path.basename(info["exe"]) in PROTECTED or r == os.getpid():
            return {"ok": False, "message": f"Refusing to stop protected process {info['exe']}."}

    launch = recipe.get("launch") or proc_info(roots[0], cache)["cmdline"]
    if not launch:
        return {"ok": False, "message": f"Could not work out how to start {name} again."}
    launch = [os.path.expanduser(a) for a in launch]
    watch = set(roots) | set(app["pids"])

    # 1. ask the app to quit
    if recipe.get("stop"):
        subprocess.Popen([os.path.expanduser(a) for a in recipe["stop"]],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    else:
        for r in roots:
            try:
                os.kill(r, signal.SIGTERM)
            except ProcessLookupError:
                pass

    # 2. wait for it to be gone (never SIGKILL: an app that won't quit is left alone)
    deadline = time.time() + float(recipe.get("timeout", 20))
    while time.time() < deadline and any(alive(p) for p in watch):
        time.sleep(0.25)
    if any(alive(p) for p in watch):
        return {"ok": False, "message": f"{name} didn't quit within {recipe.get('timeout', 20)} s; not relaunched."}
    time.sleep(float(recipe.get("delay", 1)))

    # 3. start it again in its own scope, so it outlives a shell restart
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower() or "app"
    unit = f"app-vpnroutes-{slug}-{int(time.time())}.scope"
    subprocess.Popen(["systemd-run", "--user", "--scope", "--collect", "--quiet",
                      f"--unit={unit}", "--", *launch],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    return {"ok": True, "message": f"Restarted {name}.", "launch": launch}


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "restart":
        print(json.dumps(restart(sys.argv[2])))
    else:
        print(json.dumps(build_report({})))


if __name__ == "__main__":
    main()
