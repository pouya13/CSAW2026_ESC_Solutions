"""
Mini serial terminal (PuTTY-style) for COM8.

Defaults: 115200 baud, 8 data bits, no parity, 1 stop bit, no flow control,
line ending CR+LF (switchable to LF). Everything you type is echoed locally
in a distinct colour so you can see your own input.

Requires: pip install pyserial
Run:      python serial_term.py [PORT]
"""

import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, ttk

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    sys.exit("pyserial is required:  pip install pyserial")

DEFAULT_PORT = sys.argv[1] if len(sys.argv) > 1 else "COM8"
BAUD = 115200
LINE_ENDINGS = {"CR+LF  (\\r\\n)": b"\r\n", "LF  (\\n)": b"\n"}

# Palette
BG = "#1e1f29"
PANEL = "#272935"
FG = "#e6e6eb"
MUTED = "#8a8fa3"
ACCENT = "#7aa2f7"
RX = "#c0caf5"
TX = "#9ece6a"
SYS = "#e0af68"
ERR = "#f7768e"
MONO = ("Cascadia Mono", 11) if sys.platform == "win32" else ("Menlo", 11)


class SerialTerminal(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Serial Terminal — {DEFAULT_PORT}")
        self.geometry("980x640")
        self.minsize(640, 400)
        self.configure(bg=BG)

        self.ser = None
        self.rx_queue = queue.Queue()
        self.reader = None
        self.stop_evt = threading.Event()
        self.history, self.hist_idx = [], 0
        self.rx_bytes = self.tx_bytes = 0
        self.at_line_start = True

        self._style()
        self._build()
        self.after(30, self._drain_rx)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._sys(f"Ready. Settings: {BAUD} 8N1, no flow control. Press Connect.")

    # ---------- UI ----------
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, fieldbackground=PANEL,
                    bordercolor=PANEL, lightcolor=PANEL, darkcolor=PANEL,
                    font=("Segoe UI", 10))
        s.configure("Panel.TFrame", background=PANEL)
        s.configure("Panel.TLabel", background=PANEL, foreground=MUTED)
        s.configure("Value.TLabel", background=PANEL, foreground=FG,
                    font=("Segoe UI Semibold", 10))
        s.configure("Status.TLabel", background=PANEL, foreground=MUTED,
                    font=("Segoe UI", 9))
        s.configure("TButton", background="#353849", foreground=FG,
                    padding=(12, 5), borderwidth=0)
        s.map("TButton", background=[("active", "#43475c"), ("disabled", PANEL)],
              foreground=[("disabled", MUTED)])
        s.configure("Accent.TButton", background=ACCENT, foreground="#11121a")
        s.map("Accent.TButton", background=[("active", "#9ab8ff")])
        s.configure("Danger.TButton", background=ERR, foreground="#11121a")
        s.map("Danger.TButton", background=[("active", "#ff99ad")])
        s.configure("TCheckbutton", background=PANEL, foreground=FG)
        s.map("TCheckbutton", background=[("active", PANEL)])
        s.configure("TCombobox", arrowcolor=FG, padding=4)
        s.map("TCombobox", fieldbackground=[("readonly", "#353849")],
              foreground=[("readonly", FG)])
        self.option_add("*TCombobox*Listbox.background", PANEL)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)

    def _build(self):
        # Top bar: port + settings + connect
        top = ttk.Frame(self, style="Panel.TFrame", padding=(14, 10))
        top.pack(fill="x")

        ttk.Label(top, text="PORT", style="Panel.TLabel").pack(side="left")
        self.port_var = tk.StringVar(value=DEFAULT_PORT)
        self.port_box = ttk.Combobox(top, textvariable=self.port_var, width=9,
                                     values=self._ports())
        self.port_box.pack(side="left", padx=(6, 4))
        self.port_box.bind("<Button-1>", lambda e: self.port_box.configure(values=self._ports()))

        for label, value in (("BAUD", str(BAUD)), ("DATA", "8"), ("PARITY", "None"),
                             ("STOP", "1"), ("FLOW", "None")):
            ttk.Label(top, text=label, style="Panel.TLabel").pack(side="left", padx=(14, 4))
            ttk.Label(top, text=value, style="Value.TLabel").pack(side="left")

        self.conn_btn = ttk.Button(top, text="Connect", style="Accent.TButton",
                                   command=self._toggle)
        self.conn_btn.pack(side="right")
        self.led = tk.Canvas(top, width=14, height=14, bg=PANEL, highlightthickness=0)
        self.led_dot = self.led.create_oval(2, 2, 12, 12, fill=ERR, outline="")
        self.led.pack(side="right", padx=10)

        # Terminal output
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=12, pady=(10, 6))
        self.out = tk.Text(body, bg=BG, fg=RX, insertbackground=FG, font=MONO,
                           wrap="char", relief="flat", padx=8, pady=6,
                           selectbackground="#3d4466", state="disabled")
        sb = ttk.Scrollbar(body, command=self.out.yview)
        self.out.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.out.pack(side="left", fill="both", expand=True)
        self.out.tag_configure("rx", foreground=RX)
        self.out.tag_configure("tx", foreground=TX, font=MONO + ("bold",))
        self.out.tag_configure("sys", foreground=SYS)
        self.out.tag_configure("err", foreground=ERR)
        self.out.tag_configure("ts", foreground=MUTED)

        # Input row
        inp = ttk.Frame(self, style="Panel.TFrame", padding=(12, 8))
        inp.pack(fill="x")
        tk.Label(inp, text="›", bg=PANEL, fg=TX, font=MONO + ("bold",)).pack(side="left")
        self.entry = tk.Entry(inp, bg="#353849", fg=TX, insertbackground=TX,
                              font=MONO, relief="flat", highlightthickness=1,
                              highlightbackground="#353849", highlightcolor=ACCENT)
        self.entry.pack(side="left", fill="x", expand=True, padx=8, ipady=5)
        self.entry.bind("<Return>", self._send_line)
        self.entry.bind("<Up>", lambda e: self._hist(-1))
        self.entry.bind("<Down>", lambda e: self._hist(1))
        self.entry.bind("<Control-c>", self._ctrl_c)
        self.entry.focus_set()

        self.eol_var = tk.StringVar(value=next(iter(LINE_ENDINGS)))
        ttk.Combobox(inp, textvariable=self.eol_var, values=list(LINE_ENDINGS),
                     state="readonly", width=13).pack(side="left", padx=(0, 8))
        ttk.Button(inp, text="Send", style="Accent.TButton",
                   command=self._send_line).pack(side="left")

        # Options / status bar
        bar = ttk.Frame(self, style="Panel.TFrame", padding=(12, 0, 12, 8))
        bar.pack(fill="x")
        self.echo_var = tk.BooleanVar(value=True)
        self.ts_var = tk.BooleanVar(value=False)
        self.scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Local echo", variable=self.echo_var).pack(side="left")
        ttk.Checkbutton(bar, text="Timestamps", variable=self.ts_var).pack(side="left", padx=10)
        ttk.Checkbutton(bar, text="Autoscroll", variable=self.scroll_var).pack(side="left")
        ttk.Button(bar, text="Ctrl+C", command=self._ctrl_c).pack(side="left", padx=(14, 4))
        ttk.Button(bar, text="Clear", command=self._clear).pack(side="left", padx=4)
        ttk.Button(bar, text="Save log…", command=self._save).pack(side="left", padx=4)
        self.status = ttk.Label(bar, text="", style="Status.TLabel")
        self.status.pack(side="right")
        self._update_status()

    # ---------- output helpers ----------
    def _write(self, text, tag):
        at_bottom = self.out.yview()[1] >= 0.999
        self.out.configure(state="normal")
        if self.ts_var.get():
            stamp = time.strftime("[%H:%M:%S] ")
            for chunk in text.splitlines(keepends=True):
                if self.at_line_start:
                    self.out.insert("end", stamp, "ts")
                self.out.insert("end", chunk, tag)
                self.at_line_start = chunk.endswith("\n")
        else:
            self.out.insert("end", text, tag)
            if text:
                self.at_line_start = text.endswith("\n")
        self.out.configure(state="disabled")
        if self.scroll_var.get() or at_bottom:
            self.out.see("end")

    def _newline_if_needed(self):
        if not self.at_line_start:
            self._write("\n", "rx")

    def _sys(self, msg, tag="sys"):
        self._newline_if_needed()
        self._write(f"── {msg}\n", tag)

    def _update_status(self):
        state = f"Connected to {self.ser.port}" if self.ser else "Disconnected"
        self.status.configure(text=f"{state}   RX {self.rx_bytes} B   TX {self.tx_bytes} B")

    # ---------- serial ----------
    @staticmethod
    def _ports():
        return [p.device for p in serial.tools.list_ports.comports()] or [DEFAULT_PORT]

    def _toggle(self):
        self._disconnect() if self.ser else self._connect()

    def _connect(self):
        port = self.port_var.get().strip()
        try:
            self.ser = serial.Serial(port=port, baudrate=BAUD,
                                     bytesize=serial.EIGHTBITS,
                                     parity=serial.PARITY_NONE,
                                     stopbits=serial.STOPBITS_ONE,
                                     xonxoff=False, rtscts=False, dsrdtr=False,
                                     timeout=0.05)
        except serial.SerialException as e:
            self.ser = None
            self._sys(f"Could not open {port}: {e}", "err")
            return
        self.stop_evt.clear()
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()
        self.conn_btn.configure(text="Disconnect", style="Danger.TButton")
        self.port_box.configure(state="disabled")
        self.led.itemconfigure(self.led_dot, fill=TX)
        self.title(f"Serial Terminal — {port} @ {BAUD} 8N1")
        self._sys(f"Connected to {port} @ {BAUD} 8N1")
        self._update_status()
        self.entry.focus_set()

    def _disconnect(self, reason=None):
        self.stop_evt.set()
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        port, self.ser = self.port_var.get(), None
        self.conn_btn.configure(text="Connect", style="Accent.TButton")
        self.port_box.configure(state="normal")
        self.led.itemconfigure(self.led_dot, fill=ERR)
        self._sys(reason or f"Disconnected from {port}", "err" if reason else "sys")
        self._update_status()

    def _read_loop(self):
        ser = self.ser
        while not self.stop_evt.is_set():
            try:
                data = ser.read(ser.in_waiting or 1)
            except Exception as e:
                self.rx_queue.put(("error", str(e)))
                return
            if data:
                self.rx_queue.put(("data", data))

    def _drain_rx(self):
        chunks = []
        try:
            while True:
                kind, payload = self.rx_queue.get_nowait()
                if kind == "error":
                    if self.ser:
                        self._disconnect(f"Connection lost: {payload}")
                    break
                chunks.append(payload)
        except queue.Empty:
            pass
        if chunks:
            data = b"".join(chunks)
            self.rx_bytes += len(data)
            text = data.decode("utf-8", errors="replace")
            text = text.replace("\r\n", "\n").replace("\r", "")
            self._write(text, "rx")
            self._update_status()
        self.after(30, self._drain_rx)

    def _send_raw(self, data):
        if not self.ser:
            self._sys("Not connected.", "err")
            return False
        try:
            self.ser.write(data)
        except Exception as e:
            self._disconnect(f"Write failed: {e}")
            return False
        self.tx_bytes += len(data)
        self._update_status()
        return True

    # ---------- input ----------
    def _send_line(self, _event=None):
        line = self.entry.get()
        eol = LINE_ENDINGS[self.eol_var.get()]
        if self._send_raw(line.encode("utf-8") + eol):
            if self.echo_var.get():
                self._newline_if_needed()
                self._write(f"» {line}\n", "tx")
            if line and (not self.history or self.history[-1] != line):
                self.history.append(line)
            self.hist_idx = len(self.history)
            self.entry.delete(0, "end")
        return "break"

    def _ctrl_c(self, _event=None):
        if self.entry.selection_present():
            return None  # let normal copy work
        if self._send_raw(b"\x03") and self.echo_var.get():
            self._newline_if_needed()
            self._write("» ^C\n", "tx")
        return "break"

    def _hist(self, step):
        if not self.history:
            return "break"
        self.hist_idx = max(0, min(len(self.history), self.hist_idx + step))
        self.entry.delete(0, "end")
        if self.hist_idx < len(self.history):
            self.entry.insert(0, self.history[self.hist_idx])
        return "break"

    def _clear(self):
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out.configure(state="disabled")
        self.at_line_start = True

    def _save(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            initialfile=time.strftime("serial_%Y%m%d_%H%M%S.txt"))
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.out.get("1.0", "end-1c"))
            self._sys(f"Log saved to {path}")

    def _on_close(self):
        self.stop_evt.set()
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.destroy()


if __name__ == "__main__":
    SerialTerminal().mainloop()
