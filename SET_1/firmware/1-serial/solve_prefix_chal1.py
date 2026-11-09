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
[6843216] Developer mode unlocked via UART or                                                                                               acle & MAC auth

"""

ser = serial.Serial(port="COM8",
    baudrate=115200,
    parity=serial.PARITY_NONE,
    stopbits=serial.STOPBITS_ONE,
    bytesize=8,
    timeout=0.1)

prefixes = ["mode developer --help"] # can obviously be set to be [] instead if we want to start the exploration from zero again

i = 0
m = len(prefixes)
while i<m:
    found = []
    prefix = prefixes[i]
    for c in alphabet:
        probe = prefix + c + "\n"
        ser.reset_input_buffer()
        ser.write(probe.encode())
        out = ""
        print(probe)
        deadline = time.time() + 2.6
        while time.time() < deadline:
            out += ser.read(256).decode(errors="replace")
            if "starts with" in out or "RATE-LIMIT" in out:
                break
        if "one or more commands start with" in out:
            print(out)
            found.append(prefix+c)

    i+=1
    m+=len(found)
    prefixes += found
    print("current search space:", prefixes)
print(f"found prefixes: {', '.join(prefixes)}")
ser.close()
