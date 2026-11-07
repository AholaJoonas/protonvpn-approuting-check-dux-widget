"""Tests for vpn-routes.py.

They never touch real processes: process trees are fake entries in the `cache`
dict that the script already threads through, and commands (ss, ip, nmcli,
kill, systemd-run) are replaced with mocks.

Run with either:
    python3 -m unittest      (no install needed)
    pytest
"""

import importlib.util
import ipaddress
import os
import re
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("vpn_routes", ROOT / "vpn-routes.py")
vr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vr)


def proc(exe, ppid=1, cmdline=None, comm=None):
    """A fake /proc entry, shaped like proc_info() output."""
    info = {
        "exe": exe,
        "ppid": ppid,
        "cmdline": [exe] if cmdline is None else cmdline,
        "comm": comm if comm is not None else os.path.basename(exe)[:15],
    }
    info["paths"] = vr.match_paths(info)
    return info


def app(pids, match="", name="Testapp"):
    return {"key": match or name.lower(), "name": name, "match": match, "pids": pids}


class ParseIpTest(unittest.TestCase):
    def test_formats_printed_by_ss(self):
        cases = {
            "192.168.1.10:443": "192.168.1.10",
            "[2a01:4f8::1]:443": "2a01:4f8::1",
            "[::ffff:1.2.3.4]:443": "1.2.3.4",
            "10.2.0.2%proton0:5000": "10.2.0.2",
            "[fe80::1]%wlan0:22": "fe80::1",
        }
        for raw, want in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(vr.parse_ip(raw), ipaddress.ip_address(want))

    def test_wildcard_is_none(self):
        self.assertIsNone(vr.parse_ip("*:*"))


class PrettyTest(unittest.TestCase):
    def test_names(self):
        self.assertEqual(vr.pretty({"vivaldi-bin"}), "Vivaldi")
        self.assertEqual(vr.pretty({"steam", "steamwebhelper"}), "Steam")
        self.assertEqual(vr.pretty({"spotify-launcher"}), "Spotify Launcher")


class MatchingTest(unittest.TestCase):
    def test_symlinked_launcher_matches_launch_path(self):
        # /usr/bin/foo -> /usr/lib/foo/foo; Proton only sees /usr/bin/foo
        cache = {10: proc("/usr/lib/foo/foo", cmdline=["/usr/bin/foo"])}
        self.assertEqual(vr.matched_path(10, ["/usr/bin/foo"], cache), "/usr/bin/foo")

    def test_bare_argv0_is_looked_up_in_path(self):
        with mock.patch.object(vr.shutil, "which", return_value="/usr/bin/foo"):
            cache = {10: proc("/usr/lib/foo/foo", cmdline=["foo"])}
        self.assertEqual(vr.matched_path(10, ["/usr/bin/foo"], cache), "/usr/bin/foo")

    def test_chromium_style_joined_argv0(self):
        cache = {10: proc("/opt/vivaldi/vivaldi-bin", cmdline=["/opt/vivaldi/vivaldi-bin --type=utility"])}
        self.assertEqual(vr.matched_path(10, ["/opt/vivaldi/vivaldi-bin"], cache), "/opt/vivaldi/vivaldi-bin")

    def test_matched_through_ancestor(self):
        cache = {
            10: proc("/usr/lib/app/app"),
            20: proc("/usr/bin/node", ppid=10),
        }
        self.assertEqual(vr.matched_path(20, ["/usr/lib/app/"], cache), "/usr/lib/app/")

    def test_no_match(self):
        cache = {10: proc("/usr/bin/curl")}
        self.assertIsNone(vr.matched_path(10, ["/usr/lib/app/"], cache))


class FindRootsTest(unittest.TestCase):
    def test_unmatched_app_climbs_same_binary(self):
        cache = {
            50: proc("/usr/bin/niri"),
            100: proc("/usr/lib/firefox/firefox", ppid=50),
            200: proc("/usr/lib/firefox/firefox", ppid=100),
        }
        self.assertEqual(vr.find_roots(app([200]), cache), [100])

    def test_matched_app_climbs_past_wrapper(self):
        cache = {
            100: proc("/usr/lib/app/app"),
            200: proc("/usr/bin/bash", ppid=100, cmdline=["sh", "-c", "npm exec x"]),
            300: proc("/usr/bin/node", ppid=200),
        }
        self.assertEqual(vr.find_roots(app([300], match="/usr/lib/app/"), cache), [100])

    def test_children_of_a_root_are_dropped(self):
        cache = {
            100: proc("/usr/lib/app/app"),
            200: proc("/usr/lib/app/app", ppid=100),
            300: proc("/usr/lib/app/helper", ppid=200),
        }
        self.assertEqual(vr.find_roots(app([200, 300], match="/usr/lib/app/"), cache), [100])

    def test_separate_instances_give_separate_roots(self):
        cache = {
            100: proc("/usr/lib/firefox/firefox"),
            200: proc("/usr/lib/firefox/firefox"),
        }
        self.assertEqual(vr.find_roots(app([100, 200]), cache), [100, 200])


class ProtectedTest(unittest.TestCase):
    def hit(self, info):
        return vr.proc_names(info) & vr.PROTECTED

    def test_proton_app_on_versioned_python(self):
        info = proc(
            "/usr/bin/python3.14",
            cmdline=["/usr/bin/python3", "/usr/bin/protonvpn-app"],
            comm="protonvpn-app",
        )
        self.assertIn("protonvpn-app", self.hit(info))

    def test_proton_app_caught_by_script_name_alone(self):
        info = proc(
            "/usr/bin/python3.14",
            cmdline=["/usr/bin/python3", "-I", "/usr/bin/protonvpn-app"],
            comm="weird-comm",
        )
        self.assertIn("protonvpn-app", self.hit(info))

    def test_shell_processes(self):
        self.assertTrue(self.hit(proc("/usr/bin/niri")))
        self.assertTrue(self.hit(proc("/usr/bin/quickshell", comm="qs")))

    def test_normal_app_is_not_protected(self):
        self.assertFalse(self.hit(proc("/usr/lib/firefox/firefox")))
        # arguments of non-interpreters are ignored, even if they look like a protected name
        self.assertFalse(
            self.hit(
                proc(
                    "/usr/lib/firefox/firefox",
                    cmdline=["/usr/lib/firefox/firefox", "https://example.com/niri"],
                )
            )
        )


class LaunchCommandsTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(vr, "flatpak_id", return_value="")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_recipe_launch_wins(self):
        cache = {100: proc("/opt/vivaldi/vivaldi-bin")}
        cmds = vr.launch_commands({"launch": ["/usr/bin/vivaldi-stable"]}, [100], cache)
        self.assertEqual(cmds, [["/usr/bin/vivaldi-stable"]])

    def test_identical_instances_launch_once(self):
        cache = {100: proc("/usr/bin/foo"), 200: proc("/usr/bin/foo")}
        self.assertEqual(vr.launch_commands({}, [100, 200], cache), [["/usr/bin/foo"]])

    def test_different_profiles_launch_each(self):
        cache = {
            100: proc("/usr/bin/firefox", cmdline=["/usr/bin/firefox", "-P", "work"]),
            200: proc("/usr/bin/firefox", cmdline=["/usr/bin/firefox", "-P", "home"]),
        }
        self.assertEqual(len(vr.launch_commands({}, [100, 200], cache)), 2)

    def test_flatpak_uses_flatpak_run(self):
        cache = {100: proc("/app/bin/foo")}
        with mock.patch.object(vr, "flatpak_id", return_value="org.example.Foo"):
            self.assertEqual(vr.launch_commands({}, [100], cache), [["flatpak", "run", "org.example.Foo"]])


def fake_run(ss_lines, vpn_up=True):
    outputs = {
        "ip": "5: proton0    inet 10.2.0.2/32 scope global proton0\n" if vpn_up else "",
        "nmcli": "ProtonVPN FI#38:proton0\n" if vpn_up else "",
        "ss": "\n".join(ss_lines) + "\n",
    }
    return lambda cmd: outputs[cmd[0]]


def ss(local, peer, *users):
    procs = ",".join(f'("{comm}",pid={pid},fd={fd})' for comm, pid, fd in users)
    return f"tcp 0 0 {local} {peer} users:({procs})"


class BuildReportTest(unittest.TestCase):
    SPLIT = {"enabled": True, "mode": "exclude", "paths": ["/usr/lib/firefox/"]}

    def report(self, ss_lines, cache, vpn_up=True):
        with (
            mock.patch.object(vr, "run", fake_run(ss_lines, vpn_up)),
            mock.patch.object(vr, "split_config", return_value=self.SPLIT),
        ):
            return vr.build_report(cache)

    def test_statuses_and_counts(self):
        cache = {
            300: proc("/usr/lib/firefox/firefox"),
            400: proc("/opt/vivaldi/vivaldi-bin"),
            500: proc("/usr/bin/curl"),
        }
        rep = self.report(
            [
                # excluded app still in the tunnel -> restart
                ss("10.2.0.2:5000", "1.1.1.1:443", ("firefox", 300, 10)),
                # one socket held by two fds -> counted once
                ss("10.2.0.2:5001", "1.1.1.1:443", ("vivaldi-bin", 400, 3), ("vivaldi-bin", 400, 7)),
                # not excluded but going direct -> leak
                ss("192.168.1.10:5002", "1.1.1.1:443", ("curl", 500, 3)),
                # LAN peer -> ignored
                ss("192.168.1.10:5003", "192.168.1.1:80", ("curl", 500, 4)),
            ],
            cache,
        )

        by_name = {a["name"]: a for a in rep["apps"]}
        self.assertEqual([a["status"] for a in rep["apps"]], ["leak", "restart", "ok"])
        self.assertEqual((rep["issues"], rep["leaks"]), (2, 1))
        self.assertEqual(by_name["Firefox"]["key"], "/usr/lib/firefox/")
        self.assertEqual((by_name["Vivaldi"]["vpn"], by_name["Vivaldi"]["direct"]), (1, 0))
        self.assertEqual(by_name["Curl"]["direct"], 1)

    def test_vpn_down_everything_ok(self):
        cache = {500: proc("/usr/bin/curl")}
        rep = self.report([ss("192.168.1.10:5002", "1.1.1.1:443", ("curl", 500, 3))], cache, vpn_up=False)
        self.assertFalse(rep["vpn"]["up"])
        self.assertEqual([a["status"] for a in rep["apps"]], ["ok"])


class RestartTest(unittest.TestCase):
    """restart() with every side effect mocked out."""

    def setUp(self):
        self.kill = self.patch(vr.os, "kill")
        self.popen = self.patch(vr.subprocess, "Popen")
        self.patch(vr, "flatpak_id", return_value="")
        self.patch(vr, "load_recipe", return_value={})

    def patch(self, target, name, **kw):
        patcher = mock.patch.object(target, name, **kw)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def run_restart(self, cache_entries, the_app, **kw):
        def fake_report(cache):
            cache.update(cache_entries)
            return {"apps": [the_app]}

        with mock.patch.object(vr, "build_report", fake_report):
            return vr.restart(the_app["key"], **kw)

    def test_dry_run_does_nothing(self):
        res = self.run_restart({100: proc("/usr/bin/foo")}, app([100]), dry_run=True)
        self.assertTrue(res["ok"])
        self.assertTrue(res["dry_run"])
        self.assertEqual(res["stop"]["sigterm"][0]["pid"], 100)
        self.assertEqual(res["launch"], [["/usr/bin/foo"]])
        self.kill.assert_not_called()
        self.popen.assert_not_called()

    def test_refuses_protected_process(self):
        proton = proc(
            "/usr/bin/python3.14",
            cmdline=["/usr/bin/python3", "/usr/bin/protonvpn-app"],
            comm="protonvpn-app",
        )
        res = self.run_restart({100: proton}, app([100], name="Protonvpn App"))
        self.assertFalse(res["ok"])
        self.assertIn("protonvpn-app", res["message"])
        self.kill.assert_not_called()

    def test_unknown_key(self):
        with mock.patch.object(vr, "build_report", return_value={"apps": []}):
            self.assertFalse(vr.restart("nope")["ok"])
        self.kill.assert_not_called()


class AnyCmdlineMatchesTest(unittest.TestCase):
    def test_own_process_is_skipped(self):
        with open("/proc/self/cmdline", "rb") as f:
            own = f.read().replace(b"\0", b" ").decode()
        self.assertFalse(vr.any_cmdline_matches("^" + re.escape(own) + "$"))


if __name__ == "__main__":
    unittest.main()
