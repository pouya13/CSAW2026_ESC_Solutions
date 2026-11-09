import time
import serial
import string

alphabet = string.ascii_lowercase + " !@-_"

"""
[AUTH REQUIRED] Developer mode requires device verification.
Enter MAC suffix (6 hex digits, e.g. A4C138):

SSID: SmartHomeGW_4C4864
BSSID: b8:d6:1a:4c:48:65
but the suffix from the ssid is correct the esp stores it differently (4C4864)


Developer mode unlocked successfully.
Available log commands:
log1, log2, ..., log100
[6843216] Developer mode unlocked via UART oracle & MAC auth

🚀 python .\enumerate_devmode_chal1.py
anomaly: System log 37: Info: Critical diagnostic mode activated. Run command 'claim_flag_uart_s1' to dump flag.


one or more commands start with help
This help menu is outdated. System commands have been reorganized.
Supported characters: lowercase letters (a-z), spaces ( ), and special characters (!, @, -, _).
esc_2026{Challenge_1_UART_cli_6319c043576b5ae2}
[7837154] FLAG CAPTURED by competitor
"""

ser = serial.Serial(port="COM8",
    baudrate=115200,
    parity=serial.PARITY_NONE,
    stopbits=serial.STOPBITS_ONE,
    bytesize=8,
    timeout=0.1)

for i in range(1, 101):
    probe = f"log{i}\n"
    ser.reset_input_buffer()
    ser.write(probe.encode())
    out = ""
    deadline = time.time() + 2.6
    while time.time() < deadline:
        out += ser.read(256).decode(errors="replace")
        if "starts with" in out or "RATE-LIMIT" in out:
            break
    if not "Peripheral check passed" in out:
        print(f"anomaly: {out}")

ser.close()
