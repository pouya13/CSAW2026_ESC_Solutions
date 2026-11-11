#!/usr/bin/env python3
"""
BLE GATT Explorer — a desktop GUI for discovering, connecting to, and
fully exploring Bluetooth Low Energy (GATT) devices, with PIN authentication.

Two kinds of PIN authentication are supported:

  1. Pairing passkey (link-layer).  When you tick "Pair / bond", the app
     registers a BlueZ pairing agent that answers the device's passkey
     request with the passkey you typed — so bonding completes without
     relying on a desktop popup.  This is the usual "enter the PIN to pair".

  2. App-level PIN.  Some devices expose a characteristic you write a PIN to
     in order to unlock features.  The "App-level PIN" panel does that.

Run:
    python ble_explorer.py

Requires: PySide6, qasync, bleak  (see requirements.txt)
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime

import qasync
from bleak import BleakClient, BleakScanner
from PySide6 import QtCore, QtGui, QtWidgets

# dbus-fast ships with bleak on Linux; used for the pairing agent.
try:
    from dbus_fast.aio import MessageBus
    from dbus_fast import BusType, DBusError
    from dbus_fast.service import ServiceInterface, method
    HAVE_DBUS = True
except Exception:  # pragma: no cover - non-Linux / missing dep
    HAVE_DBUS = False


# --------------------------------------------------------------------------
# Well-known 16-bit GATT UUIDs so the tree reads nicely.
# --------------------------------------------------------------------------
KNOWN_UUIDS = {
    "1800": "Generic Access", "1801": "Generic Attribute",
    "180a": "Device Information", "180f": "Battery Service",
    "1805": "Current Time Service", "181c": "User Data",
    "2a00": "Device Name", "2a01": "Appearance",
    "2a04": "Peripheral Preferred Conn. Params", "2a05": "Service Changed",
    "2a19": "Battery Level", "2a24": "Model Number String",
    "2a25": "Serial Number String", "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String", "2a28": "Software Revision String",
    "2a29": "Manufacturer Name String", "2aa6": "Central Address Resolution",
    "2902": "Client Characteristic Config", "2901": "Characteristic Description",
}


def friendly_uuid(uuid: str) -> str:
    u = str(uuid).lower()
    short = u
    if len(u) == 36 and u.endswith("-0000-1000-8000-00805f9b34fb"):
        short = u[4:8]
    return KNOWN_UUIDS.get(short, "")


def now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def parse_payload(text: str, encoding: str) -> bytes:
    text = text.strip()
    if encoding == "Hex":
        cleaned = "".join(text.replace("0x", "").replace(",", " ").split())
        if len(cleaned) % 2 != 0:
            raise ValueError("Hex needs an even number of digits")
        return bytes.fromhex(cleaned)
    if encoding == "UTF-8":
        return text.encode("utf-8")
    if encoding == "Decimal (uint, LE)":
        v = int(text, 10)
        return v.to_bytes(max(1, (v.bit_length() + 7) // 8), "little")
    if encoding == "Decimal (uint, BE)":
        v = int(text, 10)
        return v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if encoding == "Decimal bytes":
        return bytes(int(p, 10) for p in text.replace(",", " ").split())
    raise ValueError(f"Unknown encoding: {encoding}")


def render_value(data: bytes) -> str:
    if data is None:
        return "<none>"
    hex_part = " ".join(f"{b:02x}" for b in data)
    try:
        text = data.decode("utf-8")
        if text.isprintable():
            return f'{hex_part}    "{text}"'
    except UnicodeDecodeError:
        pass
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{hex_part}    |{ascii_part}|"


ROLE_KIND = QtCore.Qt.UserRole + 1
ROLE_OBJECT = QtCore.Qt.UserRole + 2

AGENT_PATH = "/org/bluez/agent/ble_explorer"


# --------------------------------------------------------------------------
# BlueZ pairing agent — answers the passkey/PIN request during bonding.
# --------------------------------------------------------------------------
if HAVE_DBUS:
    class PairingAgent(ServiceInterface):
        """Interactive BlueZ agent.

        Devices that show a passkey on their own screen generate a *fresh*
        passkey for each pairing attempt, so we must ask the user live rather
        than replay a value typed earlier.  Each request pops a dialog and
        awaits the answer before replying to BlueZ.
        """

        def __init__(self, window):
            super().__init__("org.bluez.Agent1")
            self._win = window

        @staticmethod
        def _to_int(text: str) -> int:
            digits = "".join(ch for ch in (text or "") if ch.isdigit())
            return int(digits) if digits else 0

        @method()
        def Release(self):
            pass

        @method()
        async def RequestPinCode(self, device: "o") -> "s":  # noqa: F722,F821
            self._win.log("Badge requested a PIN code.", "warn")
            val = await self._win.ask_passkey_dialog(
                "PIN code", "Enter the PIN code for the device:")
            if val is None:
                raise DBusError("org.bluez.Error.Rejected", "user cancelled")
            self._win.log(f"Agent -> PIN code '{val}'", "tx")
            return val

        @method()
        def DisplayPinCode(self, device: "o", pincode: "s"):  # noqa: F722,F821
            self._win.log(f"Enter this PIN code on the device: {pincode}", "rx")
            self._win.show_display_dialog(
                "Enter on device", f"Type this PIN on the device:\n\n{pincode}")

        @method()
        async def RequestPasskey(self, device: "o") -> "u":  # noqa: F722,F821
            self._win.log("Badge requested a passkey — enter the one on its screen.",
                          "warn")
            prefill = self._win.passkey_edit.text().strip()
            val = await self._win.ask_passkey_dialog(
                "Passkey entry",
                "Enter the 6-digit passkey shown on the device:", prefill)
            if val is None:
                raise DBusError("org.bluez.Error.Rejected", "user cancelled")
            pk = self._to_int(val)
            self._win.log(f"Agent -> passkey {pk:06d}", "tx")
            return pk

        @method()
        def DisplayPasskey(self, device: "o", passkey: "u", entered: "q"):  # noqa: F722,F821
            self._win.log(f"Enter this passkey on the device: {passkey:06d}", "rx")
            self._win.show_display_dialog(
                "Enter on device",
                f"Type this passkey on the device:\n\n{passkey:06d}")

        @method()
        async def RequestConfirmation(self, device: "o", passkey: "u"):  # noqa: F722,F821
            ok = await self._win.ask_confirm_dialog(passkey)
            if not ok:
                raise DBusError("org.bluez.Error.Rejected", "user rejected")
            self._win.log(f"Confirmed passkey {passkey:06d}", "ok")

        @method()
        def RequestAuthorization(self, device: "o"):  # noqa: F722,F821
            self._win.log("Authorizing device (auto-accept).", "ok")

        @method()
        def AuthorizeService(self, device: "o", uuid: "s"):  # noqa: F722,F821
            self._win.log(f"Authorizing service {uuid} (auto-accept).", "ok")

        @method()
        def Cancel(self):
            self._win.log("Pairing cancelled by device.", "warn")


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BLE GATT Explorer")
        self.resize(1240, 820)

        self.client: BleakClient | None = None
        self.scanner: BleakScanner | None = None
        self._scan_results: dict[str, tuple] = {}
        self._subscribed: set[str] = set()
        self._bus = None
        self._agent_registered = False

        self._build_ui()
        self._apply_theme()
        self._update_connect_enabled()
        self.log("Welcome. Step 1: click Scan, pick a device, then Connect.", "muted")
        if not HAVE_DBUS:
            self.log("dbus-fast not available — passkey agent disabled.", "warn")

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root = QtWidgets.QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        root.addLayout(self._build_topbar())

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_center_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 4)
        splitter.setStretchFactor(2, 3)
        root.addWidget(splitter, 1)

        root.addWidget(self._build_log())

        self.status = self.statusBar()
        self._set_status("Disconnected — scan to begin")

    def _build_topbar(self):
        bar = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("BLE GATT Explorer")
        title.setObjectName("title")
        bar.addWidget(title)
        sub = QtWidgets.QLabel("discover · explore · authenticate")
        sub.setObjectName("subtitle")
        bar.addWidget(sub)
        bar.addStretch(1)
        self.conn_dot = QtWidgets.QLabel("●")
        self.conn_dot.setObjectName("dotOff")
        self.conn_label = QtWidgets.QLabel("Not connected")
        self.conn_label.setObjectName("connLabel")
        bar.addWidget(self.conn_dot)
        bar.addWidget(self.conn_label)
        return bar

    def _build_left_panel(self):
        panel = QtWidgets.QGroupBox("1 · Devices & Connection")
        lay = QtWidgets.QVBoxLayout(panel)

        row = QtWidgets.QHBoxLayout()
        self.scan_btn = QtWidgets.QPushButton("▶  Scan")
        self.scan_btn.setToolTip("Start/stop scanning for nearby BLE devices")
        self.scan_btn.clicked.connect(self.on_scan_toggle)
        row.addWidget(self.scan_btn)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by name or address…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self._refresh_device_table)
        row.addWidget(self.filter_edit, 1)
        lay.addLayout(row)

        self.device_table = QtWidgets.QTableWidget(0, 3)
        self.device_table.setHorizontalHeaderLabels(["Name", "Address", "Signal"])
        h = self.device_table.horizontalHeader()
        h.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        h.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        h.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        self.device_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.device_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.device_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.device_table.verticalHeader().setVisible(False)
        self.device_table.itemSelectionChanged.connect(self._on_device_selected)
        self.device_table.doubleClicked.connect(lambda: self.on_connect_toggle())
        self.device_table.setToolTip("Double-click a row to connect")
        lay.addWidget(self.device_table, 1)

        self.addr_edit = QtWidgets.QLineEdit()
        self.addr_edit.setPlaceholderText("…or type an address: XX:XX:XX:XX:XX:XX")
        self.addr_edit.textChanged.connect(self._update_connect_enabled)
        self.addr_edit.returnPressed.connect(self.on_connect_toggle)
        lay.addWidget(self.addr_edit)

        # --- connection / pairing block ---
        conn = QtWidgets.QFrame()
        conn.setObjectName("connBlock")
        cl = QtWidgets.QVBoxLayout(conn)
        cl.setSpacing(6)

        self.pair_chk = QtWidgets.QCheckBox("Pair / bond with a passkey (PIN)")
        self.pair_chk.setToolTip(
            "Tick if the device requires bonding. When pairing starts, a prompt "
            "appears — enter the passkey the device shows at that moment.")
        self.pair_chk.toggled.connect(self._on_pair_toggled)
        cl.addWidget(self.pair_chk)

        self.passkey_edit = QtWidgets.QLineEdit()
        self.passkey_edit.setPlaceholderText("Optional: pre-fill passkey (prompt appears anyway)")
        self.passkey_edit.setEnabled(False)
        self.passkey_edit.returnPressed.connect(self.on_connect_toggle)
        cl.addWidget(self.passkey_edit)

        self._pair_hint = QtWidgets.QLabel(
            "A passkey prompt pops up during pairing — read the code off the "
            "device's screen and type it then.")
        self._pair_hint.setObjectName("hint")
        self._pair_hint.setWordWrap(True)
        self._pair_hint.setVisible(False)
        cl.addWidget(self._pair_hint)

        self.connect_btn = QtWidgets.QPushButton("Connect")
        self.connect_btn.setObjectName("primary")
        self.connect_btn.setToolTip("Connect to the selected / entered device")
        self.connect_btn.clicked.connect(self.on_connect_toggle)
        cl.addWidget(self.connect_btn)
        lay.addWidget(conn)
        return panel

    def _build_center_panel(self):
        panel = QtWidgets.QGroupBox("2 · GATT Services")
        lay = QtWidgets.QVBoxLayout(panel)

        row = QtWidgets.QHBoxLayout()
        self.refresh_btn = QtWidgets.QPushButton("↻ Refresh")
        self.refresh_btn.clicked.connect(lambda: self.run_async(self.populate_services()))
        self.readall_btn = QtWidgets.QPushButton("Read all")
        self.readall_btn.setToolTip("Read every readable characteristic")
        self.readall_btn.clicked.connect(lambda: self.run_async(self.read_all()))
        self.expand_btn = QtWidgets.QPushButton("Expand")
        self.expand_btn.clicked.connect(self.tree_expand_all)
        self.collapse_btn = QtWidgets.QPushButton("Collapse")
        self.collapse_btn.clicked.connect(lambda: self.tree.collapseAll())
        for b in (self.refresh_btn, self.readall_btn, self.expand_btn, self.collapse_btn):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(["Attribute", "Handle", "Properties / Value"])
        self.tree.setColumnWidth(0, 320)
        self.tree.setColumnWidth(1, 56)
        self.tree.itemSelectionChanged.connect(self._on_tree_selected)
        self.tree.setToolTip("Services contain characteristics contain descriptors")
        lay.addWidget(self.tree, 1)

        legend = QtWidgets.QLabel(
            "\U0001f4c1 service   ◈ characteristic   • descriptor")
        legend.setObjectName("legend")
        lay.addWidget(legend)
        return panel

    def _build_right_panel(self):
        panel = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(panel)
        lay.setContentsMargins(0, 0, 0, 0)

        box = QtWidgets.QGroupBox("3 · Interact with selected attribute")
        form = QtWidgets.QVBoxLayout(box)
        self.sel_label = QtWidgets.QLabel("Select a characteristic in the tree ←")
        self.sel_label.setWordWrap(True)
        self.sel_label.setObjectName("selInfo")
        form.addWidget(self.sel_label)

        enc_row = QtWidgets.QHBoxLayout()
        enc_row.addWidget(QtWidgets.QLabel("Encoding"))
        self.enc_combo = QtWidgets.QComboBox()
        self.enc_combo.addItems(
            ["Hex", "UTF-8", "Decimal (uint, LE)", "Decimal (uint, BE)", "Decimal bytes"])
        enc_row.addWidget(self.enc_combo, 1)
        form.addLayout(enc_row)

        self.write_edit = QtWidgets.QLineEdit()
        self.write_edit.setPlaceholderText("Value to write…")
        form.addWidget(self.write_edit)

        act_row = QtWidgets.QHBoxLayout()
        self.read_btn = QtWidgets.QPushButton("Read")
        self.read_btn.clicked.connect(lambda: self.run_async(self.read_selected()))
        self.write_btn = QtWidgets.QPushButton("Write")
        self.write_btn.clicked.connect(lambda: self.run_async(self.write_selected(True)))
        self.writenr_btn = QtWidgets.QPushButton("Write (no resp)")
        self.writenr_btn.clicked.connect(lambda: self.run_async(self.write_selected(False)))
        self.notify_btn = QtWidgets.QPushButton("Subscribe")
        self.notify_btn.clicked.connect(lambda: self.run_async(self.toggle_notify()))
        for b in (self.read_btn, self.write_btn, self.writenr_btn, self.notify_btn):
            act_row.addWidget(b)
        form.addLayout(act_row)
        lay.addWidget(box)

        # --- App-level PIN ---
        auth = QtWidgets.QGroupBox("\U0001f511  App-level PIN (write to characteristic)")
        auth.setObjectName("authBox")
        a = QtWidgets.QVBoxLayout(auth)
        a.addWidget(self._dim_label(
            "For devices that unlock by writing a PIN to a characteristic. "
            "(This is NOT link-layer pairing — use the Pair/bond box on the left "
            "for that.)"))

        a.addWidget(QtWidgets.QLabel("PIN value"))
        self.pin_edit = QtWidgets.QLineEdit()
        self.pin_edit.setPlaceholderText("e.g. 1234")
        a.addWidget(self.pin_edit)

        a.addWidget(QtWidgets.QLabel("Write to characteristic"))
        self.pin_target = QtWidgets.QComboBox()
        self.pin_target.setToolTip("Writable characteristics appear here once connected")
        a.addWidget(self.pin_target)

        a.addWidget(QtWidgets.QLabel("Encode PIN as"))
        self.pin_enc = QtWidgets.QComboBox()
        self.pin_enc.addItems(
            ["ASCII digits", "Decimal (uint, LE)", "Decimal (uint, BE)", "Hex"])
        a.addWidget(self.pin_enc)

        self.pin_send_btn = QtWidgets.QPushButton("Send PIN")
        self.pin_send_btn.setObjectName("primary")
        self.pin_send_btn.clicked.connect(lambda: self.run_async(self.send_pin()))
        a.addWidget(self.pin_send_btn)
        lay.addWidget(auth)

        lay.addStretch(1)
        self._set_interaction_enabled(False)
        return panel

    def _dim_label(self, text):
        lbl = QtWidgets.QLabel(text)
        lbl.setObjectName("hint")
        lbl.setWordWrap(True)
        return lbl

    def _build_log(self):
        box = QtWidgets.QGroupBox("Activity log")
        lay = QtWidgets.QVBoxLayout(box)
        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(5000)
        self.log_view.setMinimumHeight(130)
        self.log_view.setObjectName("log")
        lay.addWidget(self.log_view)
        box.setMaximumHeight(200)
        return box

    # ------------------------------------------------------------- styling
    def _apply_theme(self):
        self.setStyleSheet("""
        QMainWindow, QWidget { background: #0f1420; color: #d7dce6;
            font-family: 'Segoe UI','Ubuntu',sans-serif; font-size: 13px; }
        QGroupBox { border: 1px solid #253046; border-radius: 10px;
            margin-top: 14px; padding: 10px; background: #141b2b; }
        QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px;
            color: #8fb7ff; font-weight: 700; }
        QGroupBox#authBox { border: 1px solid #3a4d2f; background: #16200f; }
        QGroupBox#authBox::title { color: #a6d06a; }
        QFrame#connBlock { background: #0c1424; border: 1px solid #243457;
            border-radius: 9px; padding: 4px; }
        QLabel#title { font-size: 21px; font-weight: 800; color: #eef2fa; }
        QLabel#subtitle { color: #5f6c86; font-size: 12px; padding-left: 8px; }
        QLabel#connLabel { color: #b9c3d6; font-weight: 600; }
        QLabel#dotOff { color: #e0564f; font-size: 15px; }
        QLabel#dotOn  { color: #58c877; font-size: 15px; }
        QLabel#hint { color: #7f8aa0; font-size: 11px; }
        QLabel#legend { color: #6c7892; font-size: 11px; padding-top: 4px; }
        QLabel#selInfo { color: #cdd6e6; padding: 2px; }
        QPushButton { background: #1e2840; border: 1px solid #2d3a56;
            border-radius: 8px; padding: 7px 12px; color: #d7dce6; }
        QPushButton:hover { background: #27324f; border-color: #3b4a6e; }
        QPushButton:disabled { color: #566278; background: #161d2c;
            border-color: #222c40; }
        QPushButton#primary { background: #2e6df0; border: none; color: white;
            font-weight: 700; padding: 9px 12px; }
        QPushButton#primary:hover { background: #4079f5; }
        QPushButton#primary:disabled { background: #223055; color: #7a89a8; }
        QLineEdit, QComboBox, QPlainTextEdit {
            background: #0c111b; border: 1px solid #28334c; border-radius: 7px;
            padding: 6px; color: #e3e9f3; selection-background-color: #2e6df0; }
        QLineEdit:focus, QComboBox:focus { border-color: #2e6df0; }
        QLineEdit:disabled { color: #4b5568; background: #0a0e16; }
        QCheckBox { padding: 3px; }
        QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px;
            border: 1px solid #39456a; background: #0c111b; }
        QCheckBox::indicator:checked { background: #2e6df0; border-color: #2e6df0; }
        QTableWidget, QTreeWidget { background: #0c111b; border: 1px solid #22304a;
            border-radius: 8px; gridline-color: #1c2740;
            alternate-background-color: #0e1521; }
        QHeaderView::section { background: #16203a; color: #9fb0cf; padding: 6px;
            border: none; border-right: 1px solid #22304a; }
        QTableWidget::item:selected, QTreeWidget::item:selected {
            background: #243a66; color: #ffffff; }
        QPlainTextEdit#log { font-family: 'JetBrains Mono','Consolas',monospace;
            font-size: 12px; }
        QSplitter::handle { background: #1a2338; width: 3px; }
        QScrollBar:vertical { background: #0c111b; width: 11px; }
        QScrollBar::handle:vertical { background: #2a3a5c; border-radius: 5px; }
        QToolTip { background: #1a2338; color: #d7dce6; border: 1px solid #39456a; }
        """)
        self.device_table.setAlternatingRowColors(True)
        self.tree.setAlternatingRowColors(True)

    # ------------------------------------------------------------- helpers
    def log(self, message: str, kind: str = "info"):
        colors = {"info": "#cdd6e6", "muted": "#7f8aa0", "ok": "#58c877",
                  "err": "#ff6b6b", "warn": "#f0b840", "rx": "#5bc0de",
                  "tx": "#b388ff"}
        c = colors.get(kind, "#cdd6e6")
        self.log_view.appendHtml(
            f'<span style="color:#55607a">[{now()}]</span> '
            f'<span style="color:{c}">{message}</span>')
        sb = self.log_view.verticalScrollBar()
        sb.setValue(sb.maximum())
        print(f"[{now()}] [{kind}] {message}", flush=True)  # mirror for diagnostics

    def _set_status(self, text: str):
        self.status.showMessage(text)

    def run_async(self, coro):
        task = asyncio.ensure_future(coro)

        def _done(t):
            if not t.cancelled() and t.exception() is not None:
                self.log(f"Error: {t.exception()}", "err")
        task.add_done_callback(_done)
        return task

    def tree_expand_all(self):
        self.tree.expandAll()

    def _set_interaction_enabled(self, on: bool):
        for w in (self.read_btn, self.write_btn, self.writenr_btn, self.notify_btn,
                  self.pin_send_btn, self.refresh_btn, self.readall_btn):
            w.setEnabled(on)

    def _set_connected_ui(self, on: bool, name: str = ""):
        self.conn_dot.setObjectName("dotOn" if on else "dotOff")
        self.conn_dot.style().unpolish(self.conn_dot)
        self.conn_dot.style().polish(self.conn_dot)
        self.conn_label.setText(f"Connected: {name}" if on else "Not connected")
        self.connect_btn.setText("Disconnect" if on else "Connect")
        self._set_interaction_enabled(on)
        self._set_status(
            f"Connected to {name} — explore services on the right"
            if on else "Disconnected")

    def _on_pair_toggled(self, checked: bool):
        self.passkey_edit.setEnabled(checked)
        self._pair_hint.setVisible(checked)
        if checked:
            self.passkey_edit.setFocus()

    def _update_connect_enabled(self):
        if self.client and self.client.is_connected:
            self.connect_btn.setEnabled(True)
            return
        has_target = bool(self.addr_edit.text().strip() or self._selected_address())
        self.connect_btn.setEnabled(has_target)

    # -------------------------------------------------------------- scanning
    def on_scan_toggle(self):
        if self.scanner is None:
            self.run_async(self.start_scan())
        else:
            self.run_async(self.stop_scan())

    async def start_scan(self):
        self._scan_results.clear()
        self.device_table.setRowCount(0)
        self.scanner = BleakScanner(detection_callback=self._on_adv)
        try:
            await self.scanner.start()
        except Exception as e:
            self.scanner = None
            self.log(f"Could not start scan: {e}", "err")
            return
        self.scan_btn.setText("■  Stop")
        self.log("Scanning… pick a device when it appears.", "ok")

    async def stop_scan(self):
        if self.scanner is not None:
            try:
                await self.scanner.stop()
            except Exception:
                pass
            self.scanner = None
        self.scan_btn.setText("▶  Scan")
        self.log("Scan stopped.", "muted")

    def _on_adv(self, device, adv):
        name = adv.local_name or device.name or "<unnamed>"
        rssi = adv.rssi if adv.rssi is not None else -127
        self._scan_results[device.address] = (name, device.address, rssi, device)
        self._refresh_device_table()

    def _refresh_device_table(self):
        flt = self.filter_edit.text().strip().lower()
        rows = sorted(self._scan_results.values(), key=lambda r: -r[2])
        prev = self._selected_address()
        self.device_table.setRowCount(0)
        for name, addr, rssi, _dev in rows:
            if flt and flt not in name.lower() and flt not in addr.lower():
                continue
            r = self.device_table.rowCount()
            self.device_table.insertRow(r)
            nitem = QtWidgets.QTableWidgetItem(name)
            if name == "<unnamed>":
                nitem.setForeground(QtGui.QColor("#6c7892"))
            self.device_table.setItem(r, 0, nitem)
            self.device_table.setItem(r, 1, QtWidgets.QTableWidgetItem(addr))
            self.device_table.setItem(
                r, 2, QtWidgets.QTableWidgetItem(f"{self._rssi_bars(rssi)}  {rssi}"))
            if addr == prev:
                self.device_table.selectRow(r)

    @staticmethod
    def _rssi_bars(rssi: int) -> str:
        levels = [(-55, "████"), (-67, "███░"),
                  (-80, "██░░"), (-90, "█░░░")]
        for thresh, bars in levels:
            if rssi >= thresh:
                return bars
        return "░░░░"

    def _selected_address(self) -> str | None:
        items = self.device_table.selectedItems()
        if not items:
            return None
        cell = self.device_table.item(items[0].row(), 1)
        return cell.text() if cell else None

    def _on_device_selected(self):
        addr = self._selected_address()
        if addr:
            self.addr_edit.setText(addr)
        self._update_connect_enabled()

    # ---------------------------------------------- interactive pair dialogs
    def ask_passkey_dialog(self, title, prompt, prefill=""):
        """Async: show a passkey entry dialog, resolve with text or None."""
        loop = asyncio.get_event_loop()
        fut = loop.create_future()
        dlg = QtWidgets.QInputDialog(self)
        dlg.setWindowTitle(title)
        dlg.setLabelText(prompt)
        dlg.setInputMode(QtWidgets.QInputDialog.TextInput)
        dlg.setTextValue(prefill)
        dlg.setMinimumWidth(320)

        def finished(result):
            if not fut.done():
                fut.set_result(
                    dlg.textValue() if result == QtWidgets.QDialog.Accepted else None)
            dlg.deleteLater()
        dlg.finished.connect(finished)
        dlg.open()
        dlg.raise_()
        dlg.activateWindow()
        return fut

    def ask_confirm_dialog(self, passkey):
        """Async: numeric-comparison yes/no, resolve with bool."""
        loop = asyncio.get_event_loop()
        fut = loop.create_future()
        box = QtWidgets.QMessageBox(self)
        box.setWindowTitle("Confirm passkey")
        box.setText(f"Does the device show this passkey?\n\n{passkey:06d}")
        box.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        box.setIcon(QtWidgets.QMessageBox.Question)

        def finished(_):
            if not fut.done():
                fut.set_result(box.clickedButton() == box.button(
                    QtWidgets.QMessageBox.Yes))
            box.deleteLater()
        box.finished.connect(finished)
        box.open()
        box.raise_()
        return fut

    def show_display_dialog(self, title, text):
        box = QtWidgets.QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(QtWidgets.QMessageBox.Ok)
        box.finished.connect(lambda _: box.deleteLater())
        box.open()
        box.raise_()

    # ------------------------------------------------------- pairing agent
    async def ensure_agent(self):
        """Register our BlueZ pairing agent as the default (once)."""
        if not HAVE_DBUS or self._agent_registered:
            return self._agent_registered
        try:
            self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            agent = PairingAgent(self)
            self._bus.export(AGENT_PATH, agent)
            intro = await self._bus.introspect("org.bluez", "/org/bluez")
            obj = self._bus.get_proxy_object("org.bluez", "/org/bluez", intro)
            mgr = obj.get_interface("org.bluez.AgentManager1")
            await mgr.call_register_agent(AGENT_PATH, "KeyboardDisplay")
            try:
                await mgr.call_request_default_agent(AGENT_PATH)
            except Exception as e:
                self.log(f"Could not become default agent ({e}); "
                         "the desktop may prompt instead.", "warn")
            self._agent_registered = True
            self.log("Pairing agent registered — it will supply your passkey.", "ok")
        except Exception as e:
            self.log(f"Could not register pairing agent: {e}", "err")
        return self._agent_registered

    async def unregister_agent(self):
        if not (HAVE_DBUS and self._agent_registered and self._bus):
            return
        try:
            intro = await self._bus.introspect("org.bluez", "/org/bluez")
            obj = self._bus.get_proxy_object("org.bluez", "/org/bluez", intro)
            mgr = obj.get_interface("org.bluez.AgentManager1")
            await mgr.call_unregister_agent(AGENT_PATH)
        except Exception:
            pass
        self._agent_registered = False

    # ------------------------------------------------------------- connect
    def on_connect_toggle(self):
        if self.client and self.client.is_connected:
            self.run_async(self.disconnect())
        else:
            self.run_async(self.connect())

    async def connect(self):
        addr = self.addr_edit.text().strip() or self._selected_address() or ""
        if not addr:
            self.log("Select a device or enter an address first.", "warn")
            return
        pair = self.pair_chk.isChecked()
        if self.scanner is not None:
            await self.stop_scan()

        self.connect_btn.setEnabled(False)
        if pair:
            await self.ensure_agent()
        self.log(f"Connecting to {addr}…", "info")

        target = self._scan_results.get(addr)
        device = target[3] if target else addr
        try:
            self.client = BleakClient(
                device, disconnected_callback=self._on_disconnected,
                timeout=30.0, pair=pair)
            await self.client.connect()
        except Exception as e:
            self.log(f"Connection failed: {e}", "err")
            if "key-missing" in str(e) or "AuthenticationFailed" in str(e):
                self.log("Tip: a stale bond may exist. Remove it with "
                         f"`bluetoothctl remove {addr}` and retry.", "warn")
            self.client = None
            self.connect_btn.setEnabled(True)
            self._update_connect_enabled()
            return
        self.connect_btn.setEnabled(True)
        name = target[0] if target else addr
        self.log(f"Connected to {addr}" + (" (bonded)" if pair else ""), "ok")
        self._set_connected_ui(True, name)
        await self.populate_services()

    def _on_disconnected(self, _client):
        self.log("Device disconnected.", "warn")
        self._subscribed.clear()
        self._set_connected_ui(False)
        self.tree.clear()
        self.pin_target.clear()
        self.sel_label.setText("Select a characteristic in the tree ←")
        self._update_connect_enabled()

    async def disconnect(self):
        if self.client:
            try:
                await self.client.disconnect()
            except Exception as e:
                self.log(f"Disconnect error: {e}", "err")
        self.client = None
        self._set_connected_ui(False)
        self.tree.clear()
        self.pin_target.clear()
        self.sel_label.setText("Select a characteristic in the tree ←")
        self.log("Disconnected.", "muted")
        self._update_connect_enabled()

    # ----------------------------------------------------------- GATT tree
    async def populate_services(self):
        if not (self.client and self.client.is_connected):
            return
        self.tree.clear()
        self.pin_target.clear()
        services = list(self.client.services)
        self.log(f"Discovered {len(services)} service(s).", "ok")
        writable = {"write", "write-without-response"}

        for service in services:
            s_item = QtWidgets.QTreeWidgetItem(self.tree)
            fn = friendly_uuid(service.uuid)
            s_item.setText(0, f"\U0001f4c1 {service.uuid}" + (f"  — {fn}" if fn else ""))
            s_item.setText(1, str(service.handle))
            s_item.setData(0, ROLE_KIND, "service")
            s_item.setData(0, ROLE_OBJECT, service)
            s_item.setForeground(0, QtGui.QColor("#8fb7ff"))

            for char in service.characteristics:
                c_item = QtWidgets.QTreeWidgetItem(s_item)
                cn = friendly_uuid(char.uuid)
                c_item.setText(0, f"◈ {char.uuid}" + (f"  — {cn}" if cn else ""))
                c_item.setText(1, str(char.handle))
                c_item.setText(2, ", ".join(char.properties))
                c_item.setData(0, ROLE_KIND, "char")
                c_item.setData(0, ROLE_OBJECT, char)
                if writable.intersection(char.properties):
                    self.pin_target.addItem(
                        f"{cn or char.uuid}  (h{char.handle})", userData=char)

                for desc in char.descriptors:
                    d_item = QtWidgets.QTreeWidgetItem(c_item)
                    dn = friendly_uuid(desc.uuid)
                    d_item.setText(0, f"• {desc.uuid}" + (f"  — {dn}" if dn else ""))
                    d_item.setText(1, str(desc.handle))
                    d_item.setData(0, ROLE_KIND, "desc")
                    d_item.setData(0, ROLE_OBJECT, desc)
                    d_item.setForeground(0, QtGui.QColor("#9aa6bd"))
        self.tree.expandToDepth(1)
        if self.pin_target.count() == 0:
            self.log("No writable characteristics (app-level PIN unavailable).", "muted")

    async def run_demo(self, addr, shot=None):
        """Auto-scan, connect to a bonded device, and read its riddle char
        (used to capture a connected-state screenshot)."""
        self.addr_edit.setText(addr)
        self.pair_chk.setChecked(False)
        await self.start_scan()
        for _ in range(60):
            if addr in self._scan_results:
                break
            await asyncio.sleep(0.5)
        self._refresh_device_table()
        for r in range(self.device_table.rowCount()):
            cell = self.device_table.item(r, 1)
            if cell and cell.text() == addr:
                self.device_table.selectRow(r)
                break
        await self.stop_scan()
        self.addr_edit.setText(addr)
        await self.connect()
        await asyncio.sleep(0.4)
        target = None

        def _walk(item):
            nonlocal target
            for i in range(item.childCount()):
                ch = item.child(i)
                obj = ch.data(0, ROLE_OBJECT)
                if obj is not None and str(getattr(obj, "uuid", "")).lower().startswith("4bf0ff03"):
                    target = ch
                _walk(ch)

        _walk(self.tree.invisibleRootItem())
        if target is not None:
            self.tree.setCurrentItem(target)
            self._on_tree_selected()
            idx = self.enc_combo.findText("UTF-8")
            if idx >= 0:
                self.enc_combo.setCurrentIndex(idx)
            await self.read_selected()
        self.log("Connected to Silicon_Badge_6 — riddle characteristic read.", "ok")
        if shot:
            await asyncio.sleep(0.6)
            pix = self.grab()
            pix.save(shot)
            self.log(f"Saved screenshot -> {shot}", "ok")

    def _selected_obj(self):
        items = self.tree.selectedItems()
        if not items:
            return None, None
        it = items[0]
        return it.data(0, ROLE_KIND), it.data(0, ROLE_OBJECT)

    def _on_tree_selected(self):
        kind, obj = self._selected_obj()
        if obj is None:
            self.sel_label.setText("Select a characteristic in the tree ←")
            return
        if kind == "char":
            self.sel_label.setText(
                f"<b>Characteristic</b><br>{obj.uuid}<br>handle {obj.handle} &nbsp; "
                f"<span style='color:#8fa6c8'>{', '.join(obj.properties)}</span>")
        elif kind == "desc":
            self.sel_label.setText(
                f"<b>Descriptor</b><br>{obj.uuid}<br>handle {obj.handle}")
        else:
            self.sel_label.setText(
                f"<b>Service</b><br>{obj.uuid}<br>handle {obj.handle}")

    # -------------------------------------------------------- read / write
    async def read_selected(self):
        kind, obj = self._selected_obj()
        if obj is None:
            self.log("Select a characteristic or descriptor to read.", "warn")
            return
        try:
            if kind == "char":
                data = await self.client.read_gatt_char(obj)
            elif kind == "desc":
                data = await self.client.read_gatt_descriptor(obj.handle)
            else:
                self.log("Services are not readable.", "warn")
                return
        except Exception as e:
            self.log(f"Read failed: {e}", "err")
            return
        self.log(f"READ {obj.uuid} ← {render_value(data)}", "rx")
        self._update_tree_value(obj, render_value(data))

    async def write_selected(self, response: bool):
        kind, obj = self._selected_obj()
        if obj is None or kind not in ("char", "desc"):
            self.log("Select a characteristic or descriptor to write.", "warn")
            return
        try:
            data = parse_payload(self.write_edit.text(), self.enc_combo.currentText())
        except Exception as e:
            self.log(f"Bad payload: {e}", "err")
            return
        try:
            if kind == "char":
                await self.client.write_gatt_char(obj, data, response=response)
            else:
                await self.client.write_gatt_descriptor(obj.handle, data)
        except Exception as e:
            self.log(f"Write failed: {e}", "err")
            return
        self.log(f"WROTE {obj.uuid} → {render_value(data)} "
                 f"({'with resp' if response else 'no resp'})", "tx")

    async def read_all(self):
        if not (self.client and self.client.is_connected):
            return
        self.log("Reading all readable characteristics…", "info")
        for service in self.client.services:
            for char in service.characteristics:
                if "read" in char.properties:
                    try:
                        data = await asyncio.wait_for(
                            self.client.read_gatt_char(char), timeout=5.0)
                        self.log(f"  {char.uuid} = {render_value(data)}", "rx")
                        self._update_tree_value(char, render_value(data))
                    except Exception as e:
                        self.log(f"  {char.uuid} <unreadable: {e}>", "muted")
        self.log("Read-all complete.", "ok")

    def _update_tree_value(self, obj, text: str):
        def walk(item):
            if item.data(0, ROLE_OBJECT) is obj:
                if item.data(0, ROLE_KIND) == "char":
                    props = ", ".join(obj.properties)
                    item.setText(2, f"{props}    = {text}")
                else:
                    item.setText(2, text)
                return True
            for i in range(item.childCount()):
                if walk(item.child(i)):
                    return True
            return False
        for i in range(self.tree.topLevelItemCount()):
            if walk(self.tree.topLevelItem(i)):
                break

    # ------------------------------------------------------- notifications
    async def toggle_notify(self):
        kind, obj = self._selected_obj()
        if obj is None or kind != "char":
            self.log("Select a characteristic to subscribe to.", "warn")
            return
        uuid = str(obj.uuid)
        if uuid in self._subscribed:
            try:
                await self.client.stop_notify(obj)
            except Exception as e:
                self.log(f"Unsubscribe failed: {e}", "err")
                return
            self._subscribed.discard(uuid)
            self.notify_btn.setText("Subscribe")
            self.log(f"Unsubscribed from {uuid}", "muted")
            return
        if not {"notify", "indicate"}.intersection(obj.properties):
            self.log("This characteristic does not support notify/indicate.", "warn")
            return
        try:
            await self.client.start_notify(obj, self._on_notify)
        except Exception as e:
            self.log(f"Subscribe failed: {e}", "err")
            return
        self._subscribed.add(uuid)
        self.notify_btn.setText("Unsubscribe")
        self.log(f"Subscribed to {uuid}", "ok")

    def _on_notify(self, sender, data: bytearray):
        uuid = getattr(sender, "uuid", sender)
        self.log(f"NOTIFY {uuid} ← {render_value(bytes(data))}", "rx")

    # ---------------------------------------------------- app-level PIN
    async def send_pin(self):
        if not (self.client and self.client.is_connected):
            self.log("Connect to a device first.", "warn")
            return
        if self.pin_target.count() == 0:
            self.log("No writable characteristic available for the PIN.", "warn")
            return
        char = self.pin_target.currentData()
        pin = self.pin_edit.text().strip()
        if not pin:
            self.log("Enter a PIN first.", "warn")
            return
        enc = self.pin_enc.currentText()
        try:
            if enc == "ASCII digits":
                data = pin.encode("ascii")
            else:
                data = parse_payload(pin, enc)
        except Exception as e:
            self.log(f"Bad PIN encoding: {e}", "err")
            return
        response = "write" in char.properties
        try:
            await self.client.write_gatt_char(char, data, response=response)
        except Exception as e:
            self.log(f"PIN write failed: {e}", "err")
            return
        self.log(f"PIN sent to {char.uuid} → {render_value(data)}", "tx")
        if "read" in char.properties:
            try:
                back = await asyncio.wait_for(
                    self.client.read_gatt_char(char), timeout=5.0)
                self.log(f"Auth response ← {render_value(back)}", "rx")
            except Exception:
                pass

    # ------------------------------------------------------------- close
    def closeEvent(self, event):
        print(f"[{now()}] window closed by user; shutting down", flush=True)
        if self.client and self.client.is_connected:
            self.run_async(self.client.disconnect())
        if self.scanner is not None:
            self.run_async(self.scanner.stop())
        self.run_async(self.unregister_agent())
        super().closeEvent(event)


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("BLE GATT Explorer")
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    win = MainWindow()
    win.show()
    win.raise_()
    win.activateWindow()
    print(f"[{now()}] GUI started and window shown", flush=True)

    if "--demo" in sys.argv:
        _i = sys.argv.index("--demo")
        _addr = sys.argv[_i + 1] if _i + 1 < len(sys.argv) else "B8:D6:1A:4C:48:66"
        _shot = None
        if "--shot" in sys.argv:
            _j = sys.argv.index("--shot")
            _shot = sys.argv[_j + 1] if _j + 1 < len(sys.argv) else None
        win.run_async(win.run_demo(_addr, _shot))

    with loop:
        loop.run_forever()


if __name__ == "__main__":
    main()
