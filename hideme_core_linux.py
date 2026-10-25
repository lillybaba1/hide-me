"""Hide Me Linux core: routes all traffic through Tor via nftables transparent proxy.

How hiding works when switched ON:
  * The system 'debian-tor' user runs Tor with TransPort + DNSPort enabled.
  * nftables output-chain NAT redirects every TCP SYN and every DNS query from
    other users to Tor's TransPort / DNSPort, so the transparent proxy applies
    to every application without any per-app configuration.
  * A kill-switch filter table rejects every outbound packet that is not from
    debian-tor or loopback, so if Tor dies the machine goes dark rather than
    leaking your real IP.
  * Optionally the hostname is replaced with a generic one to blend in on the
    local network.

Requires: python3, tor (system package), nftables.
Must be run as root (e.g.  sudo python3 hideme.py).
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Callable, List, Optional

# ---------- ports & constants -----------------------------------------------

TRANS_PORT   = 9040   # Tor TransPort  (transparent TCP proxy)
SOCKS_PORT   = 9060   # Tor SocksPort  (used by check_ip for explicit check)
CONTROL_PORT = 9061
DNS_PORT     = 5353   # Tor DNSPort
TOR_USER     = "debian-tor"

NFT_TABLE_NAT    = "hideme_nat"
NFT_TABLE_FILTER = "hideme_filter"

GENERIC_NAME = "debian"
CHECK_URL    = "https://check.torproject.org/api/ip"
TOR_TIMEOUT  = 180

TORRC_PATH   = Path("/etc/tor/torrc")
TORRC_BACKUP = Path("/etc/tor/torrc.hideme-backup")
COOKIE_PATH  = Path("/var/lib/tor/control_auth_cookie")

TOR_BIN  = "/usr/bin/tor"
NFT_BIN  = "/usr/sbin/nft"
CURL_BIN = "/usr/bin/curl"

DEFAULT_APP_DIR = Path("/var/lib/hideme")

# ---------- nftables ruleset -------------------------------------------------
# output-chain NAT: redirect TCP and DNS from non-Tor users to Tor's ports.
# inet filter: block everything outbound except loopback and Tor itself
# (the kill-switch: if Tor dies nothing leaks).

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

# ---------- torrc written by Hide Me ----------------------------------------
TORRC_HIDEME = f"""\
# Written by Hide Me — restored automatically when Hide Me is switched off.
SocksPort    127.0.0.1:{SOCKS_PORT}
ControlPort  127.0.0.1:{CONTROL_PORT}
CookieAuthentication 1
TransPort    127.0.0.1:{TRANS_PORT}
DNSPort      127.0.0.1:{DNS_PORT}
ClientOnly   1
AvoidDiskWrites 1
Log notice syslog
"""

# ---------- regex ------------------------------------------------------------
BOOTSTRAP_PHASE_RE = re.compile(r"PROGRESS=(\d+).*?SUMMARY=\"([^\"]+)\"")

ProgressFn = Callable[[int, str], None]
Runner = Callable[[List[str], float], str]


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


def check_ip(via_tor: bool, runner: Runner = run_command) -> tuple:
    """Return (ip, is_tor) as seen by check.torproject.org.

    via_tor=True: explicit SOCKS connection (checks before nftables are up).
    via_tor=False while ON: the transparent proxy routes it through Tor anyway.
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
    """Persists network state so recovery works after a crash or reboot."""

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
    """Manages nftables transparent-proxy rules, torrc, and optionally the hostname."""

    @staticmethod
    def _hostname() -> str:
        try:
            return Path("/etc/hostname").read_text().strip()
        except OSError:
            return socket.gethostname()

    def snapshot(self, hide_name: bool) -> dict:
        return {"hostname": self._hostname() if hide_name else None,
                "hide_name": hide_name}

    @staticmethod
    def _tables_exist() -> bool:
        try:
            out = run_command([NFT_BIN, "list", "tables"], 10)
            return NFT_TABLE_NAT in out
        except HideMeError:
            return False

    def apply(self, state: dict) -> None:
        # Remove any leftover rules from a previous incomplete shutdown.
        for spec in (f"ip {NFT_TABLE_NAT}", f"inet {NFT_TABLE_FILTER}"):
            try:
                run_command([NFT_BIN, "delete", "table"] + spec.split(), 10)
            except HideMeError:
                pass

        # Backup and replace torrc.
        if not TORRC_BACKUP.exists() and TORRC_PATH.exists():
            TORRC_PATH.rename(TORRC_BACKUP)
        TORRC_PATH.write_text(TORRC_HIDEME)
        TORRC_PATH.chmod(0o644)

        # Apply nftables rules.
        proc = subprocess.run([NFT_BIN, "-f", "/dev/stdin"],
                              input=NFT_RULESET, text=True, capture_output=True)
        if proc.returncode != 0:
            raise HideMeError(f"nftables: {proc.stderr.strip()}")

        # Optional: change hostname to something generic.
        if state.get("hide_name"):
            try:
                Path("/etc/hostname").write_text(GENERIC_NAME + "\n")
                run_command(["hostname", GENERIC_NAME], 5)
            except (OSError, HideMeError):
                pass

    def revert(self, state: dict) -> None:
        # Remove our nftables tables (ignore errors if already gone).
        for spec in (f"ip {NFT_TABLE_NAT}", f"inet {NFT_TABLE_FILTER}"):
            try:
                run_command([NFT_BIN, "delete", "table"] + spec.split(), 10)
            except HideMeError:
                pass

        # Restore torrc.
        if TORRC_BACKUP.exists():
            TORRC_BACKUP.rename(TORRC_PATH)
        elif TORRC_PATH.exists():
            try:
                if "Written by Hide Me" in TORRC_PATH.read_text():
                    TORRC_PATH.unlink()
            except OSError:
                pass

        # Restore hostname.
        if state.get("hostname"):
            try:
                Path("/etc/hostname").write_text(state["hostname"] + "\n")
                run_command(["hostname", state["hostname"]], 5)
            except (OSError, HideMeError):
                pass


# ---------- Tor (system service) --------------------------------------------

class Tor:
    """Controls the system Tor service and polls its control port for bootstrap."""

    def __init__(self):
        self._stopping = False

    @property
    def running(self) -> bool:
        try:
            res = subprocess.run(["systemctl", "is-active", "tor"],
                                 capture_output=True, text=True, timeout=5)
            return res.stdout.strip() == "active"
        except Exception:
            return False

    def start(self, on_progress: ProgressFn, timeout: float = TOR_TIMEOUT) -> None:
        """Restart Tor with our torrc and wait for full bootstrap."""
        self._stopping = False

        res = subprocess.run(["systemctl", "restart", "tor"],
                             capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            raise HideMeError(f"Could not start Tor: {res.stderr.strip()}")

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._stopping:
                self._stop_service()
                raise Cancelled("Stopped before Tor finished connecting.")

            pct, summary = self._query_bootstrap()
            if pct is not None:
                on_progress(pct, summary)
                if pct == 100:
                    return
            elif not self.running:
                raise HideMeError("Tor stopped unexpectedly. Check logs: journalctl -u tor")

            time.sleep(0.5)

        self._stop_service()
        raise HideMeError("Tor couldn't connect within the timeout. "
                          "Your network may be blocking Tor.")

    def _query_bootstrap(self):
        """Return (pct, summary) from Tor control port, or (None, None) on failure."""
        try:
            cookie = COOKIE_PATH.read_bytes().hex()
        except OSError:
            return None, None
        try:
            with socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=2) as s:
                s.sendall(f"AUTHENTICATE {cookie}\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n"
                          .encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            m = BOOTSTRAP_PHASE_RE.search(data.decode(errors="replace"))
            if m:
                return int(m.group(1)), m.group(2)
        except OSError:
            pass
        return None, None

    def stop(self) -> None:
        self._stopping = True
        self._stop_service()

    @staticmethod
    def _stop_service() -> None:
        try:
            run_command(["systemctl", "stop", "tor"], 15)
        except HideMeError:
            pass

    def new_identity(self) -> None:
        """Ask Tor for fresh circuits so new connections get a new exit IP."""
        try:
            cookie = COOKIE_PATH.read_bytes().hex()
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
        if not Path(TOR_BIN).exists():
            raise HideMeError("Tor is not installed.  Run:  sudo apt-get install tor")
        if not Path(NFT_BIN).exists():
            raise HideMeError("nftables is not installed.  Run:  sudo apt-get install nftables")
        self.app_dir = Path(app_dir)
        self.network = network or LinuxNetwork()
        self.state = StateFile(self.app_dir / "state.json")
        self._tor = tor or Tor()
        self._lock_fd: Optional[int] = None

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

    @property
    def tor_running(self) -> bool:
        return self._tor.running

    def needs_recovery(self) -> bool:
        return self.state.load() is not None and not self.tor_running

    def recover(self) -> bool:
        state = self.state.load()
        if state is None:
            return False
        self.network.revert(state)
        self._tor.stop()
        self.state.clear()
        return True

    def turn_on(self, hide_name: bool, protect_dns: bool, on_progress: ProgressFn) -> None:
        # protect_dns is always active on Linux (nftables always redirects DNS);
        # the parameter is accepted for API compatibility with the macOS version.
        if self.needs_recovery():
            self.recover()

        # Start Tor first over the normal internet so we can bootstrap.
        self._tor.start(on_progress)
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
            self._tor.stop()
            raise

    def restart_tor(self, on_progress: ProgressFn) -> None:
        """Bring Tor back after it died while the firewall still points at it."""
        self._tor.start(on_progress)

    def turn_off(self) -> None:
        state = self.state.load()
        if state is not None:
            self.network.revert(state)
            self.state.clear()
        self._tor.stop()

    def cancel(self) -> None:
        self._tor.stop()

    def new_identity(self) -> None:
        self._tor.new_identity()
