"""Hide Me Linux core: routes all traffic through Tor via nftables transparent proxy.

How hiding works when switched ON:
  * Tor runs as a direct child process under the 'debian-tor' user (privilege drop
    via preexec_fn, same technique as on macOS via osascript).
  * nftables output-chain NAT redirects every TCP SYN and every DNS query from
    all other users to Tor's TransPort (9040) / DNSPort (9053).
  * A kill-switch filter table rejects every outbound packet that is not from
    debian-tor or loopback, so if Tor dies the machine goes dark instead of
    leaking your real IP.
  * Optionally the hostname is replaced with a generic one.

Requires: python3, tor (apt), nftables (apt).
Must be run as root:  sudo python3 hideme.py
"""
from __future__ import annotations

import collections
import fcntl
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

# ---------- ports & constants -----------------------------------------------

TRANS_PORT   = 9040   # Tor TransPort  (transparent TCP proxy)
SOCKS_PORT   = 9060   # Tor SocksPort  (explicit; also used by check_ip)
CONTROL_PORT = 9061
DNS_PORT     = 9053   # Tor DNSPort (avoids conflict with Avahi on 5353)
TOR_USER     = "debian-tor"

NFT_TABLE_NAT    = "hideme_nat"
NFT_TABLE_FILTER = "hideme_filter"

GENERIC_NAME = "debian"
CHECK_URL    = "https://check.torproject.org/api/ip"
TOR_TIMEOUT  = 180

TOR_SEARCH_PATHS = ("/usr/bin/tor", "/usr/sbin/tor")
NFT_BIN  = "/usr/sbin/nft"
CURL_BIN = "/usr/bin/curl"

DEFAULT_APP_DIR = Path("/var/lib/hideme")

BOOTSTRAP_RE  = re.compile(r"Bootstrapped (\d+)%[^:]*:\s*(.*)")
TOR_GENERIC_RE = re.compile(r"see warnings above|Failed to parse/validate config")

ProgressFn = Callable[[int, str], None]
Runner = Callable[[List[str], float], str]

# ---------- nftables ruleset -------------------------------------------------
# output-chain NAT: redirect TCP and DNS from non-Tor users to Tor's ports.
# inet filter (kill-switch): reject everything outbound except loopback and
# Tor itself, so a Tor crash goes dark rather than leaking the real IP.

_NFT_RULESET = """\
table ip {nat} {{
    chain output {{
        type nat hook output priority -100;
        oif lo return
        meta skuid "{tor_user}" return
        ip daddr 127.0.0.0/8 return
        udp dport 53 redirect to :{dns_port}
        tcp flags & (fin|syn|rst|ack) == syn redirect to :{trans_port}
    }}
}}
table inet {filt} {{
    chain output {{
        type filter hook output priority filter;
        oif lo accept
        meta skuid "{tor_user}" accept
        reject with icmpx type admin-prohibited
    }}
}}
"""
NFT_RULESET = _NFT_RULESET.format(
    nat=NFT_TABLE_NAT, filt=NFT_TABLE_FILTER,
    tor_user=TOR_USER, dns_port=DNS_PORT, trans_port=TRANS_PORT,
)


# ---------- errors -----------------------------------------------------------

class HideMeError(Exception):
    """A failure whose message can be shown to the user as-is."""


class Cancelled(HideMeError):
    """The user backed out."""


# ---------- helpers ----------------------------------------------------------

def run_command(cmd: List[str], timeout: float = 30.0) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise HideMeError(f"{os.path.basename(cmd[0])} is not available.")
    except subprocess.TimeoutExpired:
        raise HideMeError(f"{os.path.basename(cmd[0])} took too long.")
    if res.returncode != 0:
        msg = (res.stderr or res.stdout).strip()
        raise HideMeError(msg or f"{os.path.basename(cmd[0])} failed (exit {res.returncode}).")
    return res.stdout


def find_tor() -> Optional[str]:
    found = shutil.which("tor")
    if found:
        return found
    return next((p for p in TOR_SEARCH_PATHS if os.access(p, os.X_OK)), None)


def check_ip(via_tor: bool, runner: Runner = run_command) -> tuple:
    """Return (ip, is_tor) as seen by check.torproject.org.

    via_tor=True uses explicit SOCKS (works before the nftables rules are up).
    via_tor=False while Hide Me is ON: transparent proxy routes it through Tor.
    """
    cmd = [CURL_BIN, "-s", "--max-time", "20"]
    if via_tor:
        cmd += ["--socks5-hostname", f"127.0.0.1:{SOCKS_PORT}"]
    try:
        data = json.loads(runner(cmd + [CHECK_URL], 25))
    except (HideMeError, ValueError):
        raise HideMeError("Couldn't reach the IP check service.")
    return data.get("IP", "unknown"), bool(data.get("IsTor"))


# ---------- state file -------------------------------------------------------

class StateFile:
    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self) -> Optional[dict]:
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            return None
        except ValueError:
            raise HideMeError(f"{self.path} is damaged; delete it and fix the network by hand.")

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


# ---------- network management -----------------------------------------------

class LinuxNetwork:
    """Manages nftables transparent-proxy rules and optionally the hostname."""

    @staticmethod
    def _hostname() -> str:
        try:
            return Path("/etc/hostname").read_text().strip()
        except OSError:
            return socket.gethostname()

    def snapshot(self, hide_name: bool) -> dict:
        return {"hostname": self._hostname() if hide_name else None,
                "hide_name": hide_name}

    def apply(self, state: dict) -> None:
        # Remove any leftover rules from a previous incomplete shutdown.
        for spec in (f"ip {NFT_TABLE_NAT}", f"inet {NFT_TABLE_FILTER}"):
            try:
                run_command([NFT_BIN, "delete", "table"] + spec.split(), 10)
            except HideMeError:
                pass

        proc = subprocess.run([NFT_BIN, "-f", "/dev/stdin"],
                              input=NFT_RULESET, text=True, capture_output=True)
        if proc.returncode != 0:
            raise HideMeError(f"nftables: {proc.stderr.strip()}")

        if state.get("hide_name"):
            try:
                Path("/etc/hostname").write_text(GENERIC_NAME + "\n")
                run_command(["hostname", GENERIC_NAME], 5)
            except (OSError, HideMeError):
                pass

    def revert(self, state: dict) -> None:
        for spec in (f"ip {NFT_TABLE_NAT}", f"inet {NFT_TABLE_FILTER}"):
            try:
                run_command([NFT_BIN, "delete", "table"] + spec.split(), 10)
            except HideMeError:
                pass

        if state.get("hostname"):
            try:
                Path("/etc/hostname").write_text(state["hostname"] + "\n")
                run_command(["hostname", state["hostname"]], 5)
            except (OSError, HideMeError):
                pass


# ---------- Tor (direct subprocess, runs as debian-tor) ----------------------

class Tor:
    """A Tor process owned by this app, running as debian-tor for routing isolation."""

    def __init__(self, tor_path: str, data_dir: Path):
        self.tor_path = tor_path
        self.data_dir = Path(data_dir)
        self.log: collections.deque = collections.deque(maxlen=200)
        self._proc: Optional[subprocess.Popen] = None
        self._stopping = False

    def command(self) -> List[str]:
        # Empty torrc so no system-wide config is inherited (same trick as macOS version).
        torrc = self.data_dir.parent / "torrc"
        return [self.tor_path,
                "-f", str(torrc), "--defaults-torrc", str(torrc),
                "--SocksPort",    f"127.0.0.1:{SOCKS_PORT}",
                "--ControlPort",  f"127.0.0.1:{CONTROL_PORT}",
                "--CookieAuthentication", "1",
                "--TransPort",    f"127.0.0.1:{TRANS_PORT}",
                "--DNSPort",      f"127.0.0.1:{DNS_PORT}",
                "--DataDirectory", str(self.data_dir),
                "--ClientOnly", "1",
                "--AvoidDiskWrites", "1",
                "--Log", "notice stdout",
                "--__OwningControllerProcess", str(os.getpid())]

    def _setup(self) -> None:
        """Create data dir and empty torrc, both readable by debian-tor."""
        pw = pwd.getpwnam(TOR_USER)
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(self.data_dir, pw.pw_uid, pw.pw_gid)
        torrc = self.data_dir.parent / "torrc"
        torrc.touch(mode=0o644, exist_ok=True)

    def _demote(self) -> None:
        """Called in child process before exec: drop to debian-tor."""
        pw = pwd.getpwnam(TOR_USER)
        os.setgroups([pw.pw_gid])
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, on_progress: ProgressFn, timeout: float = TOR_TIMEOUT) -> None:
        if self.running:
            return
        self._setup()
        self._stopping = False
        ready, exited, problem = threading.Event(), threading.Event(), []
        try:
            self._proc = subprocess.Popen(
                self.command(),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                preexec_fn=self._demote)
        except OSError as e:
            raise HideMeError(f"Could not start Tor: {e}")
        threading.Thread(target=self._read_output, daemon=True,
                         args=(self._proc, on_progress, ready, exited, problem)).start()
        deadline = time.monotonic() + timeout
        while not ready.wait(0.2):
            if exited.is_set():
                if self._stopping:
                    raise Cancelled("Stopped before Tor finished connecting.")
                raise HideMeError(
                    f"Tor stopped: {problem[-1] if problem else 'unknown error'}")
            if time.monotonic() > deadline:
                self.stop()
                raise HideMeError("Tor couldn't finish connecting. "
                                  "Your network may be blocking Tor.")

    def _read_output(self, proc, on_progress, ready, exited, problem) -> None:
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
        try:
            cookie = (self.data_dir / "control_auth_cookie").read_bytes().hex()
            with socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=10) as s:
                f = s.makefile("rwb")
                for cmd in (f"AUTHENTICATE {cookie}", "SIGNAL NEWNYM", "QUIT"):
                    f.write(cmd.encode() + b"\r\n")
                    f.flush()
                    reply = f.readline().decode(errors="replace").strip()
                    if not reply.startswith("250"):
                        raise HideMeError(f"Tor refused: {reply}")
        except OSError as e:
            raise HideMeError(f"Couldn't talk to Tor: {e}")


# ---------- HideMe -----------------------------------------------------------

class HideMe:
    """Ties Tor and nftables together into one ON/OFF switch."""

    def __init__(self, app_dir: Path = DEFAULT_APP_DIR,
                 network: Optional[LinuxNetwork] = None,
                 tor: Optional[Tor] = None):
        if os.geteuid() != 0:
            raise HideMeError("Hide Me must be run as root.  Try:  sudo python3 hideme.py")
        if not Path(NFT_BIN).exists():
            raise HideMeError("nftables not found.  Run:  sudo apt-get install nftables")
        self.app_dir = Path(app_dir)
        self.network = network or LinuxNetwork()
        self.state = StateFile(self.app_dir / "state.json")
        self._tor = tor
        self._lock_fd: Optional[int] = None

    @property
    def tor(self) -> Tor:
        if self._tor is None:
            path = find_tor()
            if not path:
                raise HideMeError("Tor not found.  Run:  sudo apt-get install tor")
            self._tor = Tor(path, self.app_dir / "tor-data")
        return self._tor

    @property
    def tor_running(self) -> bool:
        return self._tor is not None and self._tor.running

    def acquire_lock(self) -> bool:
        self.app_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.app_dir / "app.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self._lock_fd = fd
        return True

    def needs_recovery(self) -> bool:
        return self.state.load() is not None and not self.tor_running

    def recover(self) -> bool:
        state = self.state.load()
        if state is None:
            return False
        self.network.revert(state)
        if self._tor:
            self._tor.stop()
        self.state.clear()
        return True

    def turn_on(self, hide_name: bool, protect_dns: bool, on_progress: ProgressFn) -> None:
        # protect_dns is always active on Linux (nftables always redirects DNS).
        if self.needs_recovery():
            self.recover()
        tor = self.tor
        tor.start(on_progress)
        try:
            state = self.network.snapshot(hide_name)
            self.state.save(state)
            try:
                self.network.apply(state)
            except (Cancelled, HideMeError):
                try:
                    self.network.revert(state)
                    self.state.clear()
                except HideMeError:
                    pass
                raise
            self.state.save(state)
        except BaseException:
            tor.stop()
            raise

    def restart_tor(self, on_progress: ProgressFn) -> None:
        self.tor.start(on_progress)

    def turn_off(self) -> None:
        state = self.state.load()
        if state is not None:
            self.network.revert(state)
            self.state.clear()
        if self._tor:
            self._tor.stop()

    def cancel(self) -> None:
        if self._tor:
            self._tor.stop()

    def new_identity(self) -> None:
        self.tor.new_identity()
