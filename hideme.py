#!/usr/bin/env python3
"""Hide Me: one big switch that sends this Mac's traffic through Tor.

    python3 hideme.py            open the window
    python3 hideme.py --restore  put normal network settings back (no window)
"""
from __future__ import annotations

import argparse
import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox

if sys.platform == "linux":
    import hideme_core_linux as core
    _HIDE_NAME_LABEL = "Hide this computer's name on the network"
    _DNS_LABEL = "Send DNS through Tor (always on for Linux)"
else:
    import hideme_core as core
    _HIDE_NAME_LABEL = "Hide this Mac's name on the local network"
    _DNS_LABEL = "Send DNS lookups through Tor too"

BG = "#0f1216"
CARD = "#191d23"
SWITCH_OFF = "#262b33"
FG = "#e8eaed"
MUTED = "#8b929c"
DIM = "#4a505a"
GREEN = "#2fbf71"
RED = "#e5534b"
AMBER = "#e9a23b"
FONT = "Helvetica Neue"
NEWNYM_COOLDOWN_MS = 10_000  # Tor ignores repeat requests within 10 seconds
OPTIONS = {"hide_name": _HIDE_NAME_LABEL, "protect_dns": _DNS_LABEL}

MODES = {
    # mode: (ring colour, big text, small text, status, status colour, detail)
    "off": (RED, "OFF", "tap to hide", "You are visible", RED,
            "Websites and your network can see your real IP address."),
    "connecting": (AMBER, "", "tap to cancel", "Connecting to Tor…", AMBER, ""),
    "on": (GREEN, "ON", "tap to switch off", "You are hidden", GREEN,
           "Apps that follow the system proxy now go through Tor."),
    "busy": (AMBER, "…", "please wait", "", AMBER, ""),
    "restore": (AMBER, "FIX", "tap to restore", "Restore needed", AMBER,
                "Hide Me was left on last time, so your internet may not work. "
                "Tap to put your normal settings back."),
}


class App:
    def __init__(self, root: tk.Tk, hm: core.HideMe):
        self.root = root
        self.hm = hm
        self.mode = "off"
        self.active: dict | None = None  # options in effect while ON
        self.events: queue.Queue = queue.Queue()
        self.options = {"hide_name": True, "protect_dns": True}
        self._ip_seq = 0
        self._newnym_ready = True
        self._quitting = False
        self._build()
        root.after(100, self._drain)
        root.after(2000, self._watch_tor)
        if hm.needs_recovery():
            self._set_mode("restore")
        else:
            self._set_mode("off")
            self._check_ip()

    # ---- layout -----------------------------------------------------------

    def _build(self) -> None:
        r = self.root
        r.title("Hide Me")
        r.configure(bg=BG, padx=24, pady=20)
        r.resizable(False, False)

        tk.Label(r, text="Hide Me", bg=BG, fg=FG, font=(FONT, 22, "bold")).pack()
        tk.Label(r, text="Route this Mac through Tor", bg=BG, fg=MUTED,
                 font=(FONT, 12)).pack(pady=(0, 12))

        self.switch = tk.Canvas(r, width=220, height=220, bg=BG, highlightthickness=0,
                                cursor="hand2")
        self.switch.pack()
        self.switch.bind("<Button-1>", self._on_switch)

        self.status = tk.Label(r, bg=BG, font=(FONT, 18, "bold"))
        self.status.pack(pady=(12, 2))
        self.detail = tk.Label(r, bg=BG, fg=MUTED, font=(FONT, 12), wraplength=320,
                               justify="center", height=3)
        self.detail.pack()

        card = tk.Frame(r, bg=CARD, padx=16, pady=12)
        card.pack(fill="x", pady=(10, 12))
        card.columnconfigure(1, weight=1)
        self.rows = {}
        for i, label in enumerate(("Websites see", "Through Tor", "DNS lookups", "Mac name")):
            tk.Label(card, text=label, bg=CARD, fg=MUTED, font=(FONT, 12)).grid(
                row=i, column=0, sticky="w", pady=2)
            value = tk.Label(card, text="—", bg=CARD, fg=FG, font=(FONT, 12, "bold"))
            value.grid(row=i, column=1, sticky="e", pady=2)
            self.rows[label] = value

        buttons = tk.Frame(r, bg=BG)
        buttons.pack(fill="x")
        self.newnym_btn = self._button(buttons, "New identity", self._new_identity)
        self.newnym_btn.pack(side="left", expand=True, fill="x", padx=(0, 6))
        self.check_btn = self._button(buttons, "Check my IP", self._check_ip)
        self.check_btn.pack(side="left", expand=True, fill="x", padx=(6, 0))

        self.checkboxes = {}
        for key in OPTIONS:
            box = tk.Label(r, bg=BG, fg=FG, font=(FONT, 12), anchor="w", cursor="hand2")
            box.pack(fill="x", pady=(2 if self.checkboxes else 10, 0))
            box.bind("<Button-1>", lambda _e, k=key: self._toggle_option(k))
            self.checkboxes[key] = box

        tk.Label(r, text="For the strongest protection, browse with Tor Browser.",
                 bg=BG, fg=DIM, font=(FONT, 11)).pack(pady=(14, 0))

    def _button(self, parent, text, command) -> tk.Label:
        # tk.Button ignores colours on macOS, so draw buttons as labels.
        b = tk.Label(parent, text=text, bg=CARD, fg=FG, font=(FONT, 13), pady=8, cursor="hand2")
        b.bind("<Button-1>", lambda _e: b.cget("fg") == FG and command())  # dimmed = disabled
        return b

    # ---- rendering --------------------------------------------------------

    def _set_mode(self, mode: str, progress: int = 0, status: str = "", detail: str = "") -> None:
        self.mode = mode
        self._ip_seq += 1  # results of checks started in another mode no longer apply
        ring, big, small, default_status, status_fg, default_detail = MODES[mode]
        self._draw_switch(ring, big or f"{progress}%", small, progress if mode == "connecting" else None)
        self.status.config(text=status or default_status, fg=status_fg)
        self.detail.config(text=detail or default_detail, fg=MUTED)

        hidden = mode == "on" and self.active
        self.rows["Through Tor"].config(text="—", fg=FG)
        self.rows["Websites see"].config(text="—", fg=FG)
        self.rows["DNS lookups"].config(
            text="Through Tor" if hidden and self.active["protect_dns"] else "Your provider",
            fg=GREEN if hidden and self.active["protect_dns"] else FG)
        self.rows["Mac name"].config(
            text=f"Hidden ({core.GENERIC_NAME})" if hidden and self.active["hide_name"] else "Visible",
            fg=GREEN if hidden and self.active["hide_name"] else FG)

        self._enable(self.newnym_btn, mode == "on" and self._newnym_ready)
        self._enable(self.check_btn, mode in ("on", "off"))
        self._render_options()

    def _render_options(self) -> None:
        # Options only change what the next switch-on does, so lock them otherwise.
        for key, box in self.checkboxes.items():
            mark = "☑" if self.options[key] else "☐"
            box.config(text=f"{mark}  {OPTIONS[key]}", fg=FG if self.mode == "off" else DIM)

    def _draw_switch(self, ring: str, big: str, small: str, progress) -> None:
        c = self.switch
        c.delete("all")
        on = self.mode == "on"
        if progress is None:
            c.create_oval(8, 8, 212, 212, outline=ring, width=6)
        else:
            c.create_oval(8, 8, 212, 212, outline=SWITCH_OFF, width=6)
            c.create_arc(8, 8, 212, 212, start=90, extent=-3.6 * max(progress, 1),
                         style="arc", outline=ring, width=6)
        c.create_oval(26, 26, 194, 194, fill=GREEN if on else SWITCH_OFF, outline="")
        c.create_text(110, 100, text=big, fill="white" if on else ring, font=(FONT, 40, "bold"))
        c.create_text(110, 145, text=small, fill="white" if on else MUTED, font=(FONT, 12))

    @staticmethod
    def _enable(button: tk.Label, enabled: bool) -> None:
        button.config(fg=FG if enabled else DIM)

    # ---- background work ----------------------------------------------------

    def _background(self, work, done=None, failed=None) -> None:
        """Run work() off the UI thread; done/failed run back on it via the queue."""
        def run():
            try:
                result = work()
            except core.HideMeError as e:
                self.events.put((failed, e))
            except Exception as e:  # still tell the user instead of hanging
                self.events.put((failed, core.HideMeError(f"Unexpected error: {e}")))
            else:
                self.events.put((done, result))
        threading.Thread(target=run, daemon=True).start()

    def _drain(self) -> None:
        # Tk isn't thread-safe: worker threads only ever touch this queue.
        while True:
            try:
                fn, arg = self.events.get_nowait()
            except queue.Empty:
                break
            if fn:
                fn(arg)
        self.root.after(100, self._drain)

    def _progress(self, pct: int, summary: str) -> None:
        self.events.put((self._show_progress, (pct, summary)))

    def _show_progress(self, update) -> None:
        if self.mode == "connecting":
            pct, summary = update
            self._set_mode("connecting", progress=pct, detail=summary,
                           status=self.status.cget("text"))

    def _report(self, err: core.HideMeError) -> None:
        if isinstance(err, core.Cancelled):
            self.detail.config(text=str(err))
        else:
            messagebox.showerror("Hide Me", str(err), parent=self.root)

    # ---- actions --------------------------------------------------------------

    def _on_switch(self, _event=None) -> None:
        action = {"off": self._turn_on, "connecting": self._cancel,
                  "on": self._turn_off, "restore": self._restore}.get(self.mode)
        if action:
            action()

    def _toggle_option(self, key: str) -> None:
        if self.mode == "off":
            self.options[key] = not self.options[key]
            self._render_options()

    def _turn_on(self) -> None:
        opts = dict(self.options)
        self._set_mode("connecting", detail="Starting Tor…")

        def work():
            self.hm.turn_on(opts["hide_name"], opts["protect_dns"], self._progress)
            return opts
        self._background(work, self._turned_on, self._turn_on_failed)

    def _turned_on(self, opts: dict) -> None:
        self.active = opts
        self._set_mode("on")
        self._check_ip()

    def _turn_on_failed(self, err: core.HideMeError) -> None:
        self._set_mode("restore" if self.hm.needs_recovery() else "off")
        self._report(err)

    def _cancel(self) -> None:
        self._set_mode("busy", status="Stopping…")
        self._background(self.hm.cancel)  # the waiting turn_on then reports Cancelled

    def _turn_off(self) -> None:
        self._set_mode("busy", status="Switching off…", detail="Restoring your normal settings.")
        self._background(self.hm.turn_off, self._turned_off, self._turn_off_failed)

    def _turned_off(self, _result) -> None:
        self.active = None
        if self._quitting:
            self.root.destroy()
            return
        self._set_mode("off")
        self._check_ip()

    def _turn_off_failed(self, err: core.HideMeError) -> None:
        self._quitting = False
        self._set_mode("on")
        self._report(err)

    def _restore(self) -> None:
        self._set_mode("busy", status="Restoring…", detail="Putting your normal settings back.")
        self._background(self.hm.recover, self._turned_off, self._restore_failed)

    def _restore_failed(self, err: core.HideMeError) -> None:
        self._set_mode("restore")
        self._report(err)

    def _check_ip(self) -> None:
        if self.mode not in ("on", "off"):
            return
        # Never check directly while ON: that would show the check site your real IP.
        via_tor, seq = self.mode == "on", self._ip_seq
        self.rows["Websites see"].config(text="checking…", fg=MUTED)
        self._background(lambda: (seq, core.check_ip(via_tor)), self._show_ip,
                         lambda _e: self._show_ip((seq, None)))

    def _show_ip(self, result) -> None:
        seq, found = result
        if seq != self._ip_seq:
            return
        if found is None:
            self.rows["Websites see"].config(text="couldn't check", fg=MUTED)
            return
        ip, is_tor = found
        self.rows["Websites see"].config(text=ip, fg=GREEN if is_tor else FG)
        self.rows["Through Tor"].config(text="Yes" if is_tor else "No",
                                        fg=GREEN if is_tor else RED)

    def _new_identity(self) -> None:
        if self.mode != "on" or not self._newnym_ready:
            return
        self._newnym_ready = False
        self._enable(self.newnym_btn, False)
        self.detail.config(text="Asked Tor for a new identity. New connections get a new IP.")
        self._background(self.hm.new_identity, lambda _r: self.root.after(1500, self._check_ip),
                         self._report)
        self.root.after(NEWNYM_COOLDOWN_MS, self._newnym_cooled)

    def _newnym_cooled(self) -> None:
        self._newnym_ready = True
        self._enable(self.newnym_btn, self.mode == "on")

    def _watch_tor(self) -> None:
        # If Tor dies while ON, the system still points at it: reconnect at once.
        if self.mode == "on" and not self.hm.tor_running:
            self._set_mode("connecting", status="Reconnecting…",
                           detail="Tor stopped unexpectedly. Reconnecting…")
            self._background(lambda: self.hm.restart_tor(self._progress),
                             self._turned_on_again, self._restore_failed)
        self.root.after(2000, self._watch_tor)

    def _turned_on_again(self, _result) -> None:
        self._set_mode("on")
        self._check_ip()

    def on_close(self) -> None:
        if self.mode == "on":
            if messagebox.askyesno("Quit Hide Me", "Quitting switches Hide Me off and restores "
                                   "your normal settings. Quit now?", parent=self.root):
                self._quitting = True
                self._turn_off()
            return
        if self.mode == "busy":
            return  # let the current step finish
        if self.mode == "connecting":
            self.hm.cancel()
        self.root.destroy()


def restore_only(hm: core.HideMe) -> int:
    """For the login helper: undo settings left behind by a crash or shutdown."""
    if not hm.acquire_lock():
        return 0  # the app is open and takes care of it
    if not hm.needs_recovery():
        return 0
    try:
        hm.recover()
    except core.HideMeError as e:
        print(f"Hide Me: {e}", file=sys.stderr)
        return 1
    print("Hide Me: normal network settings restored.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Route this Mac through Tor with one switch.")
    parser.add_argument("--restore", action="store_true",
                        help="restore normal network settings and exit")
    args = parser.parse_args()
    hm = core.HideMe()
    if args.restore:
        return restore_only(hm)

    root = tk.Tk()
    if not hm.acquire_lock():
        root.withdraw()
        messagebox.showinfo("Hide Me", "Hide Me is already open.")
        return 0
    app = App(root, hm)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    if root.tk.call("tk", "windowingsystem") == "aqua":
        root.createcommand("::tk::mac::Quit", app.on_close)  # Cmd-Q and Dock > Quit
    root.lift()
    root.focus_force()
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
