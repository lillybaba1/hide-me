"""Tests for hideme_core. Runs on any Unix machine, no Mac or root needed.

The admin scripts are executed for real by /bin/sh, with stand-ins for the
macOS tools (networksetup, pfctl, scutil, ...) that log how they were called.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import hideme_core as core
from hideme_core import Cancelled, HideMeError

FAKE_TOOL = textwrap.dedent("""\
    #!{python} -I
    import json, os, sys
    name, args = os.path.basename(sys.argv[0]), sys.argv[1:]
    entry = [name] + args
    if args[-2:] == ["-f", "-"]:
        entry.append("stdin=" + sys.stdin.read().strip())
    with open(os.environ["FAKE_LOG"], "a") as f:
        f.write(json.dumps(entry) + "\\n")
    fail = os.environ.get("FAKE_FAIL")
    if fail and fail in " ".join(entry):
        sys.exit(1)
    if name == "pfctl" and "-E" in args:
        print("pf enabled\\nToken : 4242", file=sys.stderr)
    if name == "pfctl" and "-sn" in args and os.environ.get("FAKE_PF_LOADED"):
        print('rdr-anchor "com.apple/*" all')
""")

FAKE_TOR = textwrap.dedent("""\
    #!{python} -I
    import os, sys, time
    mode = os.environ.get("FAKE_TOR_MODE", "ok")
    def say(msg):
        print("Oct 24 12:00:00.000 " + msg, flush=True)
    say("[notice] Tor 0.4.9 (fake) starting")
    if mode == "fail":
        say("[warn] Could not bind to 127.0.0.1:9060: Address already in use. Is Tor already running?")
        say("[err] Reading config failed--see warnings above.")
        sys.exit(1)
    say("[notice] Bootstrapped 0% (starting): Starting")
    say("[notice] Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors")
    if mode == "ok":
        say("[notice] Bootstrapped 100% (done): Done")
    time.sleep(600)
""")

TOOLS = {core.NETWORKSETUP: "networksetup", core.PFCTL: "pfctl", core.SCUTIL: "scutil",
         "/usr/bin/dscacheutil": "dscacheutil", "/usr/bin/killall": "killall"}


class FakeMac:
    """A command runner that behaves like macOS for the commands Hide Me uses."""

    def __init__(self, tmp: Path, services=None):
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir()
        for name in set(TOOLS.values()):
            path = self.bin / name
            path.write_text(FAKE_TOOL.format(python=sys.executable))
            path.chmod(0o755)
        self.log = tmp / "calls.log"
        self.env = {"PATH": "/usr/bin:/bin", "FAKE_LOG": str(self.log)}
        # service name -> (socks output, dns output)
        self.services = services or {
            "Wi-Fi": ("Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n",
                      "There aren't any DNS Servers set on Wi-Fi.\n"),
            "USB 10/100/1000 LAN": ("Enabled: Yes\nServer: proxy.work\nPort: 1080\n"
                                    "Authenticated Proxy Enabled: 0\n", "1.1.1.1\n9.9.9.9\n"),
        }
        self.names = {"ComputerName": "Lilly's MacBook Pro", "LocalHostName": "Lillys-MacBook-Pro"}
        self.disabled = ["*Thunderbolt Bridge"]
        self.osa_error = None

    def __call__(self, cmd, timeout):
        if cmd[0] == core.NETWORKSETUP:
            flag, *rest = cmd[1:]
            if flag == "-listallnetworkservices":
                lines = ["An asterisk (*) denotes that a network service is disabled."]
                return "\n".join(lines + list(self.services) + self.disabled) + "\n"
            socks, dns = self.services[rest[0]]
            return socks if flag == "-getsocksfirewallproxy" else dns
        if cmd[0] == core.SCUTIL and cmd[1] == "--get":
            return self.names[cmd[2]] + "\n"
        if cmd[0] == core.OSASCRIPT:
            if self.osa_error:
                raise HideMeError(self.osa_error)
            return self.run_as_root(cmd[-2])
        raise AssertionError(f"unexpected command {cmd}")

    def run_as_root(self, script: str) -> str:
        for real, name in TOOLS.items():
            script = script.replace(real, str(self.bin / name))
        res = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True,
                             env={**os.environ, **self.env})
        if res.returncode:
            raise HideMeError(f"0:120: execution error: {res.stderr.strip()} ({res.returncode})")
        return res.stdout.replace("\n", "\r")  # do shell script returns Mac line endings

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(l) for l in self.log.read_text().splitlines()]

    def clear_calls(self):
        self.log.unlink(missing_ok=True)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class MacNetworkTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.mac = FakeMac(self.tmp)
        self.net = core.MacNetwork(self.mac)

    def test_services_skip_header_and_disabled(self):
        self.assertEqual(self.net.services(), ["Wi-Fi", "USB 10/100/1000 LAN"])

    def test_snapshot_reads_current_settings(self):
        snap = self.net.snapshot(hide_name=True, protect_dns=True)
        self.assertEqual(snap["services"]["Wi-Fi"],
                         {"socks": {"enabled": False, "server": "", "port": 0}, "dns": []})
        self.assertEqual(snap["services"]["USB 10/100/1000 LAN"],
                         {"socks": {"enabled": True, "server": "proxy.work", "port": 1080},
                          "dns": ["1.1.1.1", "9.9.9.9"]})
        self.assertEqual(snap["names"], self.mac.names)

    def test_snapshot_does_not_mistake_our_leftovers_for_user_settings(self):
        self.mac.services = {"Wi-Fi": ("Enabled: Yes\nServer: 127.0.0.1\nPort: 9060\n", "127.0.0.1\n")}
        snap = self.net.snapshot(hide_name=False, protect_dns=True)
        self.assertEqual(snap["services"]["Wi-Fi"],
                         {"socks": {"enabled": False, "server": "", "port": 0}, "dns": []})
        self.assertIsNone(snap["names"])

    def test_snapshot_without_services_fails(self):
        self.mac.services = {}
        with self.assertRaises(HideMeError):
            self.net.snapshot(hide_name=False, protect_dns=True)

    def test_apply_points_everything_at_tor(self):
        state = self.net.snapshot(hide_name=True, protect_dns=True)
        self.assertEqual(self.net.apply(state), "4242")
        calls = self.mac.calls()
        for svc in ("Wi-Fi", "USB 10/100/1000 LAN"):
            self.assertIn(["networksetup", "-setsocksfirewallproxy", svc, "127.0.0.1", "9060"], calls)
            self.assertIn(["networksetup", "-setsocksfirewallproxystate", svc, "on"], calls)
            self.assertIn(["networksetup", "-setdnsservers", svc, "127.0.0.1"], calls)
        self.assertIn(["pfctl", "-q", "-f", "/etc/pf.conf"], calls)  # main ruleset wasn't loaded
        self.assertIn(["pfctl", "-q", "-a", "com.apple/hideme", "-f", "-", "stdin=" + core.PF_RULE],
                      calls)
        self.assertIn(["scutil", "--set", "ComputerName", "MacBook"], calls)
        self.assertIn(["scutil", "--set", "LocalHostName", "MacBook"], calls)
        self.assertNotIn("Thunderbolt Bridge", json.dumps(calls))

    def test_apply_leaves_pf_conf_alone_when_already_loaded(self):
        self.mac.env["FAKE_PF_LOADED"] = "1"
        self.net.apply(self.net.snapshot(hide_name=False, protect_dns=True))
        self.assertNotIn(["pfctl", "-q", "-f", "/etc/pf.conf"], self.mac.calls())

    def test_apply_without_dns_or_name_touches_only_the_proxy(self):
        self.assertIsNone(self.net.apply(self.net.snapshot(hide_name=False, protect_dns=False)))
        tools = {c[0] for c in self.mac.calls()} - {"dscacheutil", "killall"}
        self.assertEqual(tools, {"networksetup"})
        self.assertFalse(any("-setdnsservers" in c for c in self.mac.calls()))

    def test_apply_stops_at_first_failure(self):
        self.mac.env["FAKE_FAIL"] = "-setdnsservers Wi-Fi"
        with self.assertRaises(HideMeError):
            self.net.apply(self.net.snapshot(hide_name=True, protect_dns=True))
        self.assertFalse(any(c[0] in ("pfctl", "scutil") for c in self.mac.calls()))

    def test_revert_restores_original_settings(self):
        state = self.net.snapshot(hide_name=True, protect_dns=True)
        state["pf_token"] = self.net.apply(state)
        self.mac.clear_calls()
        self.net.revert(state)
        calls = self.mac.calls()
        self.assertIn(["networksetup", "-setsocksfirewallproxystate", "Wi-Fi", "off"], calls)
        self.assertIn(["networksetup", "-setdnsservers", "Wi-Fi", "Empty"], calls)
        lan = "USB 10/100/1000 LAN"
        self.assertIn(["networksetup", "-setsocksfirewallproxy", lan, "proxy.work", "1080"], calls)
        self.assertIn(["networksetup", "-setsocksfirewallproxystate", lan, "on"], calls)
        self.assertIn(["networksetup", "-setdnsservers", lan, "1.1.1.1", "9.9.9.9"], calls)
        self.assertIn(["pfctl", "-q", "-a", "com.apple/hideme", "-F", "nat"], calls)
        self.assertIn(["pfctl", "-q", "-X", "4242"], calls)
        self.assertIn(["scutil", "--set", "ComputerName", "Lilly's MacBook Pro"], calls)
        self.assertIn(["scutil", "--set", "LocalHostName", "Lillys-MacBook-Pro"], calls)

    def test_revert_keeps_going_past_a_failure_but_reports_it(self):
        state = self.net.snapshot(hide_name=True, protect_dns=True)
        self.mac.env["FAKE_FAIL"] = "-setsocksfirewallproxystate Wi-Fi"
        with self.assertRaises(HideMeError):
            self.net.revert(state)
        self.assertIn(["scutil", "--set", "ComputerName", "Lilly's MacBook Pro"], self.mac.calls())

    def test_revert_after_reboot_ignores_missing_pf_rules(self):
        state = self.net.snapshot(hide_name=False, protect_dns=True)
        state["pf_token"] = "4242"
        self.mac.env["FAKE_FAIL"] = "pfctl"  # token and anchor are gone after a reboot
        self.net.revert(state)  # must not raise, or the restore would never finish

    def test_revert_skips_services_deleted_meanwhile(self):
        state = self.net.snapshot(hide_name=False, protect_dns=True)
        del self.mac.services["USB 10/100/1000 LAN"]
        self.net.revert(state)
        self.assertNotIn("USB 10/100/1000 LAN", json.dumps(self.mac.calls()))

    def test_awkward_service_names_reach_networksetup_intact(self):
        name = 'Bob\'s "iPhone" $(touch /tmp/pwned) `x`'
        self.mac.services = {name: ("Enabled: No\nServer: \nPort: 0\n", "8.8.8.8\n")}
        self.net.apply(self.net.snapshot(hide_name=False, protect_dns=True))
        self.assertIn(["networksetup", "-setsocksfirewallproxystate", name, "on"], self.mac.calls())

    def test_closed_password_prompt_is_a_cancel(self):
        self.mac.osa_error = "0:120: execution error: User canceled. (-128)"
        with self.assertRaises(Cancelled):
            self.net.apply(self.net.snapshot(hide_name=False, protect_dns=True))

    def test_osascript_errors_are_trimmed_for_the_user(self):
        self.mac.osa_error = "0:120: execution error: ** Error: Unable to find item. (1)"
        with self.assertRaisesRegex(HideMeError, r"^\*\* Error: Unable to find item\.$"):
            self.net.apply(self.net.snapshot(hide_name=False, protect_dns=True))

    def test_admin_call_passes_script_and_prompt_as_arguments(self):
        seen = []
        net = core.MacNetwork(lambda cmd, timeout: seen.append(cmd) or "")
        net.run_admin("echo 'hi \"there\"'", 'a "prompt"')
        self.assertEqual(seen[0][0], core.OSASCRIPT)
        self.assertEqual(seen[0][-2:], ["echo 'hi \"there\"'", 'a "prompt"'])


class FakeTor:
    def __init__(self, fail_start=None):
        self.running = False
        self.fail_start = fail_start
        self.newnym = 0

    def start(self, on_progress, timeout=0):
        if self.fail_start:
            raise self.fail_start
        on_progress(100, "Done")
        self.running = True

    def stop(self):
        self.running = False

    def new_identity(self):
        self.newnym += 1


class HideMeTest(TempDirTest):
    def make(self, tor=None):
        self.mac = getattr(self, "mac", None) or FakeMac(self.tmp)
        self.tor = tor or FakeTor()
        return core.HideMe(self.tmp / "app", core.MacNetwork(self.mac), self.tor)

    def test_on_then_off(self):
        hm = self.make()
        progress = []
        hm.turn_on(True, True, lambda p, s: progress.append(p))
        self.assertEqual(progress, [100])
        self.assertTrue(self.tor.running)
        self.assertEqual(hm.state.load()["pf_token"], "4242")
        hm.turn_off()
        self.assertFalse(self.tor.running)
        self.assertIsNone(hm.state.load())
        self.assertIn(["networksetup", "-setdnsservers", "Wi-Fi", "Empty"], self.mac.calls())

    def test_settings_are_saved_before_anything_changes(self):
        hm = self.make()
        saved = []
        real_apply = hm.network.apply
        hm.network.apply = lambda state: saved.append(hm.state.load()) or real_apply(state)
        hm.turn_on(False, True, lambda p, s: None)
        self.assertEqual(saved[0]["services"]["Wi-Fi"]["dns"], [])

    def test_cancelled_password_leaves_nothing_behind(self):
        hm = self.make()
        self.mac.osa_error = "execution error: User canceled. (-128)"
        with self.assertRaises(Cancelled):
            hm.turn_on(True, True, lambda p, s: None)
        self.assertFalse(self.tor.running)
        self.assertIsNone(hm.state.load())

    def test_failed_apply_is_rolled_back(self):
        hm = self.make()
        self.mac.env["FAKE_FAIL"] = "pfctl -q -a"
        with self.assertRaises(HideMeError):
            hm.turn_on(False, True, lambda p, s: None)
        self.assertFalse(self.tor.running)
        self.assertIsNone(hm.state.load())
        self.assertIn(["networksetup", "-setdnsservers", "Wi-Fi", "Empty"], self.mac.calls())

    def test_tor_failure_changes_no_settings(self):
        hm = self.make(FakeTor(fail_start=HideMeError("Tor stopped: boom")))
        with self.assertRaisesRegex(HideMeError, "boom"):
            hm.turn_on(True, True, lambda p, s: None)
        self.assertEqual(self.mac.calls(), [])
        self.assertIsNone(hm.state.load())

    def test_failed_switch_off_keeps_tor_running(self):
        hm = self.make()
        hm.turn_on(False, True, lambda p, s: None)
        self.mac.osa_error = "execution error: User canceled. (-128)"
        with self.assertRaises(Cancelled):
            hm.turn_off()
        self.assertTrue(self.tor.running)  # system still points at Tor, so keep it up
        self.assertIsNotNone(hm.state.load())

    def test_crash_while_on_is_recovered_next_launch(self):
        hm = self.make()
        hm.turn_on(True, True, lambda p, s: None)
        self.mac.clear_calls()
        relaunched = self.make(FakeTor())  # new process: Tor isn't running any more
        self.assertTrue(relaunched.needs_recovery())
        self.assertTrue(relaunched.recover())
        self.assertFalse(relaunched.needs_recovery())
        self.assertIn(["scutil", "--set", "ComputerName", "Lilly's MacBook Pro"], self.mac.calls())

    def test_switching_on_with_leftovers_restores_them_first(self):
        hm = self.make()
        hm.state.save({"services": {"Wi-Fi": {"socks": {"enabled": False, "server": "", "port": 0},
                                              "dns": ["8.8.8.8"]}},
                       "names": None, "protect_dns": True, "pf_token": None})
        hm.turn_on(False, True, lambda p, s: None)
        calls = self.mac.calls()
        restore = calls.index(["networksetup", "-setdnsservers", "Wi-Fi", "8.8.8.8"])
        self.assertLess(restore, calls.index(["networksetup", "-setdnsservers", "Wi-Fi", "127.0.0.1"]))
        # The saved originals are the real ones, not the leftover Tor settings.
        self.assertEqual(hm.state.load()["services"]["Wi-Fi"]["dns"], [])

    def test_only_one_copy_can_run(self):
        first, second = self.make(), self.make()
        self.assertTrue(first.acquire_lock())
        self.assertFalse(second.acquire_lock())

    def test_missing_tor_gives_install_hint(self):
        hm = core.HideMe(self.tmp / "app", core.MacNetwork(FakeMac(self.tmp)))
        with mock.patch.object(core, "find_tor", return_value=None):
            with self.assertRaisesRegex(HideMeError, "brew install tor"):
                hm.turn_on(False, False, lambda p, s: None)


class TorTest(TempDirTest):
    def setUp(self):
        super().setUp()
        exe = self.tmp / "tor"
        exe.write_text(FAKE_TOR.format(python=sys.executable))
        exe.chmod(0o755)
        self.tor = core.Tor(str(exe), self.tmp / "app" / "tor-data")
        self.addCleanup(self.tor.stop)

    def start(self, mode, **kw):
        with mock.patch.dict(os.environ, {"FAKE_TOR_MODE": mode}):
            progress = []
            try:
                self.tor.start(lambda pct, msg: progress.append((pct, msg)), **kw)
            finally:
                self.progress = progress

    def test_waits_for_full_bootstrap(self):
        self.start("ok")
        self.assertTrue(self.tor.running)
        self.assertEqual(self.progress, [(0, "Starting"), (45, "Asking for relay descriptors"),
                                         (100, "Done")])
        self.assertEqual(oct((self.tmp / "app" / "tor-data").stat().st_mode & 0o777), "0o700")
        self.tor.stop()
        self.assertFalse(self.tor.running)

    def test_reports_why_tor_exited(self):
        with self.assertRaisesRegex(HideMeError, "Address already in use"):
            self.start("fail")

    def test_gives_up_after_timeout(self):
        with self.assertRaisesRegex(HideMeError, "blocking Tor"):
            self.start("stuck", timeout=1)
        self.assertFalse(self.tor.running)

    def test_stop_while_connecting_is_a_cancel(self):
        threading.Timer(0.5, self.tor.stop).start()
        with self.assertRaises(Cancelled):
            self.start("stuck")

    def test_new_identity_speaks_the_control_protocol(self):
        data_dir = self.tmp / "app" / "tor-data"
        data_dir.mkdir(parents=True)
        (data_dir / "control_auth_cookie").write_bytes(b"\x01\xab" * 16)
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        received = []

        def serve():
            conn, _ = server.accept()
            with conn, conn.makefile("rwb") as f:
                for _ in range(3):
                    received.append(f.readline().decode().strip())
                    f.write(b"250 OK\r\n")
                    f.flush()
        t = threading.Thread(target=serve)
        t.start()
        with mock.patch.object(core, "CONTROL_PORT", server.getsockname()[1]):
            self.tor.new_identity()
        t.join(5)
        server.close()
        self.assertEqual(received, ["AUTHENTICATE " + "01ab" * 16, "SIGNAL NEWNYM", "QUIT"])

    def test_new_identity_without_tor_is_a_clear_error(self):
        with self.assertRaisesRegex(HideMeError, "Couldn't talk to Tor"):
            self.tor.new_identity()

    @unittest.skipUnless(shutil.which("tor"), "real tor not installed")
    def test_real_tor_accepts_our_options(self):
        tor = core.Tor(shutil.which("tor"), self.tmp / "app with space" / "tor-data")
        tor.data_dir.mkdir(parents=True)
        (tor.data_dir.parent / "torrc").touch()
        res = subprocess.run(tor.command() + ["--verify-config"], capture_output=True, text=True)
        self.assertIn("Configuration was valid", res.stdout, res.stdout + res.stderr)


class CheckIpTest(unittest.TestCase):
    def test_via_tor_uses_socks_with_remote_dns(self):
        seen = []
        runner = lambda cmd, t: seen.append(cmd) or '{"IsTor":true,"IP":"185.220.101.4"}'
        self.assertEqual(core.check_ip(True, runner), ("185.220.101.4", True))
        self.assertIn("--socks5-hostname", seen[0])

    def test_direct_check(self):
        seen = []
        runner = lambda cmd, t: seen.append(cmd) or '{"IsTor":false,"IP":"81.2.3.4"}'
        self.assertEqual(core.check_ip(False, runner), ("81.2.3.4", False))
        self.assertNotIn("--socks5-hostname", seen[0])

    def test_unreachable(self):
        for out in ("<html>", HideMeError("curl failed")):
            def runner(cmd, t, out=out):
                if isinstance(out, Exception):
                    raise out
                return out
            with self.assertRaisesRegex(HideMeError, "Couldn't reach"):
                core.check_ip(True, runner)


if __name__ == "__main__":
    unittest.main()
