"""Hide Me core: runs Tor and points this Mac's network settings at it.

Nothing in here touches the GUI. Every system command goes through a
replaceable runner, so the logic can be tested on any machine.

How hiding works when switched ON:
  * Tor runs as your user and listens only on 127.0.0.1.
  * Every enabled network service (Wi-Fi, Ethernet, ...) gets a SOCKS proxy
    pointing at Tor, so apps that follow the system proxy go through Tor.
  * Optionally, DNS is pointed at 127.0.0.1 and a pf rule forwards it to
    Tor's DNS port, so the sites you look up don't leak to your ISP.
  * Optionally, the Mac's network name is replaced with a generic one.

Your original settings are saved to disk *before* anything changes, so they
can always be put back, even after a crash or a power cut.
"""
from __future__ import annotations

import collections
import fcntl
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

SOCKS_PORT = 9060
CONTROL_PORT = 9061
DNS_PORT = 9053
GENERIC_NAME = "MacBook"
NAME_KEYS = ("ComputerName", "LocalHostName")
PF_ANCHOR = "com.apple/hideme"
PF_RULE = (f"rdr pass on lo0 inet proto udp from any to 127.0.0.1 port 53 "
           f"-> 127.0.0.1 port {DNS_PORT}")
CHECK_URL = "https://check.torproject.org/api/ip"
DEFAULT_APP_DIR = Path.home() / "Library" / "Application Support" / "HideMe"
TOR_SEARCH_PATHS = ("/opt/homebrew/bin/tor", "/usr/local/bin/tor")
TOR_TIMEOUT = 180

NETWORKSETUP = "/usr/sbin/networksetup"
SCUTIL = "/usr/sbin/scutil"
PFCTL = "/sbin/pfctl"
OSASCRIPT = "/usr/bin/osascript"
CURL = "/usr/bin/curl"
FLUSH_DNS = ("/usr/bin/dscacheutil -flushcache || true\n"
             "/usr/bin/killall -HUP mDNSResponder || true")

PROMPT_CHANGE = "Hide Me needs your password to change your network settings."
PROMPT_RESTORE = ("Hide Me was still on when it last closed. Enter your password "
                  "to restore your normal internet settings.")

BOOTSTRAP_RE = re.compile(r"Bootstrapped (\d+)%[^:]*:\s*(.*)")
# Tor ends a failed start with lines like these; the real reason comes before them.
TOR_GENERIC_RE = re.compile(r"see warnings above|Failed to parse/validate config")
PF_TOKEN_RE = re.compile(r"Token\s*:\s*(\d+)")
OSA_ERROR_RE = re.compile(r"execution error:\s*(.*?)\s*\(-?\d+\)\s*$", re.S)

ProgressFn = Callable[[int, str], None]
Runner = Callable[[List[str], float], str]


class HideMeError(Exception):
    """A failure whose message can be shown to the user as-is."""


class Cancelled(HideMeError):
    """The user backed out (closed the password prompt or stopped Tor)."""


def run_command(cmd: List[str], timeout: float = 30.0) -> str:
    """Run a command and return its stdout, raising HideMeError on failure."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise HideMeError(f"{os.path.basename(cmd[0])} is not available on this computer.")
    except subprocess.TimeoutExpired:
        raise HideMeError(f"{os.path.basename(cmd[0])} took too long to respond.")
    if res.returncode != 0:
        msg = (res.stderr or res.stdout).strip()
        raise HideMeError(msg or f"{os.path.basename(cmd[0])} failed (code {res.returncode}).")
    return res.stdout


def sh(*args: str) -> str:
    return " ".join(shlex.quote(a) for a in args)


def find_tor() -> Optional[str]:
    # Apps opened from Finder don't get Homebrew's PATH, so check its usual homes too.
    found = shutil.which("tor")
    if found:
        return found
    return next((p for p in TOR_SEARCH_PATHS if os.access(p, os.X_OK)), None)


def check_ip(via_tor: bool, runner: Runner = run_command) -> tuple:
    """Return (ip, is_tor) as seen by check.torproject.org.

    Only call with via_tor=False while Hide Me is OFF: a direct request while
    ON would show the check service your real address.
    """
    cmd = [CURL, "-s", "--max-time", "20"]
    if via_tor:
        cmd += ["--socks5-hostname", f"127.0.0.1:{SOCKS_PORT}"]
    try:
        data = json.loads(runner(cmd + [CHECK_URL], 25))
    except (HideMeError, ValueError):
        raise HideMeError("Couldn't reach the IP check service.")
    return data.get("IP", "unknown"), bool(data.get("IsTor"))


class StateFile:
    """The settings to restore. Its existence means "Hide Me is (or was left) on"."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self) -> Optional[dict]:
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            return None
        except ValueError:
            raise HideMeError(f"{self.path} is damaged; delete it and fix network settings by hand.")

    def save(self, state: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2))
        os.replace(tmp, self.path)

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class MacNetwork:
    """Reads and changes macOS proxy, DNS, pf and computer-name settings."""

    def __init__(self, runner: Runner = run_command):
        self.run = runner

    def services(self) -> List[str]:
        out = self.run([NETWORKSETUP, "-listallnetworkservices"], 30)
        # The first line explains that "*" marks a disabled service.
        return [l.strip() for l in out.splitlines()[1:] if l.strip() and not l.startswith("*")]

    def _get_socks(self, svc: str) -> dict:
        out = self.run([NETWORKSETUP, "-getsocksfirewallproxy", svc], 30)
        fields = {}
        for line in out.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                fields[key.strip()] = value.strip()
        try:
            port = int(fields.get("Port") or 0)
        except ValueError:
            port = 0
        socks = {"enabled": fields.get("Enabled") == "Yes",
                 "server": fields.get("Server", ""), "port": port}
        if socks["server"] == "127.0.0.1" and port == SOCKS_PORT:
            # Our own leftover, not the user's setting: restore to "no proxy".
            return {"enabled": False, "server": "", "port": 0}
        return socks

    def _get_dns(self, svc: str) -> List[str]:
        out = self.run([NETWORKSETUP, "-getdnsservers", svc], 30)
        # Server lines are bare addresses; "There aren't any DNS Servers set..." isn't.
        servers = [l.strip() for l in out.splitlines() if l.strip() and " " not in l.strip()]
        return [] if servers == ["127.0.0.1"] else servers

    def snapshot(self, hide_name: bool, protect_dns: bool) -> dict:
        """Everything apply() is about to change, so revert() can put it back."""
        services = {svc: {"socks": self._get_socks(svc), "dns": self._get_dns(svc)}
                    for svc in self.services()}
        if not services:
            raise HideMeError("No active network connection found.")
        names = None
        if hide_name:
            names = {key: self.run([SCUTIL, "--get", key], 10).strip() for key in NAME_KEYS}
        return {"services": services, "names": names, "protect_dns": protect_dns, "pf_token": None}

    def apply_script(self, state: dict) -> str:
        cmds = ["set -e"]
        for svc in state["services"]:
            cmds.append(sh(NETWORKSETUP, "-setsocksfirewallproxy", svc, "127.0.0.1", str(SOCKS_PORT)))
            cmds.append(sh(NETWORKSETUP, "-setsocksfirewallproxystate", svc, "on"))
            if state["protect_dns"]:
                cmds.append(sh(NETWORKSETUP, "-setdnsservers", svc, "127.0.0.1"))
        if state["protect_dns"]:
            cmds += [
                # Our rule lives in an anchor under Apple's "com.apple/*" hook, which
                # only exists once /etc/pf.conf is loaded, so load it if it isn't.
                f"{PFCTL} -sn 2>/dev/null | grep -q 'com.apple/' || {PFCTL} -q -f /etc/pf.conf",
                f"echo {shlex.quote(PF_RULE)} | {PFCTL} -q -a {PF_ANCHOR} -f -",
                # -E enables pf with a reference count; the token releases it later.
                f"{PFCTL} -E 2>&1 | grep Token || true",
            ]
        for key in state["names"] or {}:
            cmds.append(sh(SCUTIL, "--set", key, GENERIC_NAME))
        cmds.append(FLUSH_DNS)
        return "\n".join(cmds)

    def revert_script(self, state: dict, existing: List[str]) -> str:
        # Unlike apply, keep going past failures so as much as possible is restored.
        cmds, best_effort = [], []
        for svc, orig in state["services"].items():
            if svc not in existing:
                continue  # the service was deleted meanwhile; nothing to restore
            socks = orig["socks"]
            if socks["server"]:
                cmds.append(sh(NETWORKSETUP, "-setsocksfirewallproxy", svc,
                               socks["server"], str(socks["port"])))
            cmds.append(sh(NETWORKSETUP, "-setsocksfirewallproxystate", svc,
                           "on" if socks["enabled"] else "off"))
            if state["protect_dns"]:
                cmds.append(sh(NETWORKSETUP, "-setdnsservers", svc, *(orig["dns"] or ["Empty"])))
        for key, name in (state["names"] or {}).items():
            cmds.append(sh(SCUTIL, "--set", key, name))
        if state["protect_dns"]:
            # pf rules and tokens don't survive a reboot, so these may have nothing to undo.
            best_effort.append(f"{PFCTL} -q -a {PF_ANCHOR} -F nat")
            if state.get("pf_token"):
                best_effort.append(f"{PFCTL} -q -X {int(state['pf_token'])}")
        lines = (["status=0"] + [f"{c} || status=1" for c in cmds]
                 + [f"{c} 2>/dev/null || true" for c in best_effort]
                 + [FLUSH_DNS, "exit $status"])
        return "\n".join(lines)

    def run_admin(self, script: str, prompt: str = PROMPT_CHANGE) -> str:
        """Run a shell script as root behind the standard macOS password prompt."""
        try:
            return self.run([OSASCRIPT,
                             "-e", "on run argv",
                             "-e", "do shell script (item 1 of argv) with prompt (item 2 of argv) "
                                   "with administrator privileges",
                             "-e", "end run",
                             script, prompt], 300)
        except HideMeError as e:
            msg = str(e)
            if "-128" in msg or "User canceled" in msg:
                raise Cancelled("The password prompt was closed, so nothing was changed.")
            m = OSA_ERROR_RE.search(msg)
            raise HideMeError(m.group(1) if m else msg)

    def apply(self, state: dict) -> Optional[str]:
        """Point the system at Tor. Returns the pf token to release on revert."""
        out = self.run_admin(self.apply_script(state))
        m = PF_TOKEN_RE.search(out)
        return m.group(1) if m else None

    def revert(self, state: dict, prompt: str = PROMPT_CHANGE) -> None:
        self.run_admin(self.revert_script(state, self.services()), prompt)


class Tor:
    """A private Tor process owned by this app."""

    def __init__(self, path: str, data_dir: Path):
        self.path = path
        self.data_dir = Path(data_dir)
        self.log = collections.deque(maxlen=200)
        self._proc: Optional[subprocess.Popen] = None
        self._stopping = False

    def command(self) -> List[str]:
        # An empty torrc keeps any system-wide Tor config (e.g. Homebrew's) out of it.
        torrc = self.data_dir.parent / "torrc"
        return [self.path, "-f", str(torrc), "--defaults-torrc", str(torrc),
                "--SocksPort", f"127.0.0.1:{SOCKS_PORT}",
                "--ControlPort", f"127.0.0.1:{CONTROL_PORT}",
                "--CookieAuthentication", "1",
                "--DNSPort", f"127.0.0.1:{DNS_PORT}",
                "--DataDirectory", str(self.data_dir),
                "--ClientOnly", "1",
                "--AvoidDiskWrites", "1",
                "--Log", "notice stdout",
                # Tor exits by itself if this app dies, so it is never left orphaned.
                "--__OwningControllerProcess", str(os.getpid())]

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, on_progress: ProgressFn, timeout: float = TOR_TIMEOUT) -> None:
        """Start Tor and block until it is fully connected."""
        if self.running:
            return
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        (self.data_dir.parent / "torrc").touch()
        self._stopping = False
        ready, exited, problem = threading.Event(), threading.Event(), []
        try:
            self._proc = subprocess.Popen(self.command(), stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT, text=True, bufsize=1)
        except OSError as e:
            raise HideMeError(f"Could not start Tor: {e}")
        threading.Thread(target=self._read_output, daemon=True,
                         args=(self._proc, on_progress, ready, exited, problem)).start()
        deadline = time.monotonic() + timeout
        while not ready.wait(0.2):
            if exited.is_set():
                if self._stopping:
                    raise Cancelled("Stopped before Tor finished connecting.")
                raise HideMeError(f"Tor stopped: {problem[-1] if problem else 'unknown error'}")
            if time.monotonic() > deadline:
                self.stop()
                raise HideMeError("Tor couldn't finish connecting. "
                                  "Your network may be blocking Tor.")

    def _read_output(self, proc, on_progress, ready, exited, problem) -> None:
        # Runs for Tor's whole life: the pipe must keep draining or Tor would block.
        for raw in proc.stdout:
            line = raw.strip()
            self.log.append(line)
            m = BOOTSTRAP_RE.search(line)
            if m:
                on_progress(int(m.group(1)), m.group(2))
                if m.group(1) == "100":
                    ready.set()
            elif ("[err]" in line or "[warn]" in line) and not TOR_GENERIC_RE.search(line):
                problem.append(line.split("] ", 1)[-1])
        proc.stdout.close()
        proc.wait()
        exited.set()

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        self._stopping = True
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)

    def new_identity(self) -> None:
        """Ask Tor for fresh circuits, so new connections get a new exit IP."""
        try:
            cookie = (self.data_dir / "control_auth_cookie").read_bytes().hex()
            with socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=10) as s:
                f = s.makefile("rwb")
                for cmd in (f"AUTHENTICATE {cookie}", "SIGNAL NEWNYM", "QUIT"):
                    f.write(cmd.encode() + b"\r\n")
                    f.flush()
                    reply = f.readline().decode(errors="replace").strip()
                    if not reply.startswith("250"):
                        raise HideMeError(f"Tor refused the request: {reply}")
        except OSError as e:
            raise HideMeError(f"Couldn't talk to Tor: {e}")


class HideMe:
    """Ties Tor and the network settings together into one ON/OFF switch."""

    def __init__(self, app_dir: Path = DEFAULT_APP_DIR, network: Optional[MacNetwork] = None,
                 tor: Optional[Tor] = None):
        self.app_dir = Path(app_dir)
        self.network = network or MacNetwork()
        self.state = StateFile(self.app_dir / "state.json")
        self._tor = tor
        self._lock_fd: Optional[int] = None

    def acquire_lock(self) -> bool:
        """Only one copy may run, or two would fight over the same settings."""
        self.app_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.app_dir / "app.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self._lock_fd = fd
        return True

    @property
    def tor(self) -> Tor:
        if self._tor is None:
            path = find_tor()
            if not path:
                raise HideMeError("Tor isn't installed. Open Terminal and run:  brew install tor")
            self._tor = Tor(path, self.app_dir / "tor-data")
        return self._tor

    @property
    def tor_running(self) -> bool:
        return self._tor is not None and self._tor.running

    def needs_recovery(self) -> bool:
        """True if settings still point at a Tor that isn't running (crash, reboot...)."""
        return self.state.load() is not None and not self.tor_running

    def recover(self, prompt: str = PROMPT_RESTORE) -> bool:
        state = self.state.load()
        if state is None:
            return False
        self.network.revert(state, prompt)
        self.state.clear()
        return True

    def turn_on(self, hide_name: bool, protect_dns: bool, on_progress: ProgressFn) -> None:
        if self.needs_recovery():
            self.recover()
        tor = self.tor
        # Connect first: the internet keeps working normally while Tor starts up.
        tor.start(on_progress)
        try:
            state = self.network.snapshot(hide_name, protect_dns)
            # Saved before anything changes, so a crash at any point can be undone.
            self.state.save(state)
            try:
                state["pf_token"] = self.network.apply(state)
            except Cancelled:
                self.state.clear()
                raise
            except HideMeError:
                # Part of the change may have gone through; try to put it all back.
                try:
                    self.network.revert(state)
                    self.state.clear()
                except HideMeError:
                    pass  # state stays on disk, needs_recovery() will offer it again
                raise
            self.state.save(state)
        except BaseException:
            tor.stop()
            raise

    def restart_tor(self, on_progress: ProgressFn) -> None:
        """Bring Tor back after it died while the system still points at it."""
        self.tor.start(on_progress)

    def turn_off(self) -> None:
        state = self.state.load()
        if state is not None:
            # If this fails, Tor stays up so the internet keeps working through it.
            self.network.revert(state)
            self.state.clear()
        if self._tor:
            self._tor.stop()

    def cancel(self) -> None:
        """Abort a turn_on() that is still waiting for Tor to connect."""
        if self._tor:
            self._tor.stop()

    def new_identity(self) -> None:
        self.tor.new_identity()
