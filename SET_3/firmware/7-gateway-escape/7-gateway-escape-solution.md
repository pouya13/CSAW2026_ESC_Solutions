# Smart Gateway Escape (400 pts)

Checking strings:
```
{"event":"escape","ok":false,"reason":"UART disabled 
 connect via BLE first"}
```

Connecting and checking previously observed MAC (B8:D6:1A:4C:48:64)
```
$ bluetoothctl
[bluetooth]# scan on
[bluetooth]# Discovery started
...
[bluetooth]# [NEW] Device B8:D6:1A:4C:48:66 Gateway_Escape_7
...
[bluetooth]#
[bluetooth]# info B8:D6:1A:4C:48:66
Device B8:D6:1A:4C:48:66 (public)
        Name: Gateway_Escape_7
        Alias: Gateway_Escape_7
        Paired: no
        Bonded: no
        Trusted: no
        Blocked: no
        Connected: no
        LegacyPairing: no
        UUID: Vendor specific           (4fafc201-1fb5-459e-8fcc-c5c9c331914b)
        RSSI: 0xffffffb0 (-80)
        TxPower: 0x0009 (9)
[bluetooth]#
[bluetooth]# connect B8:D6:1A:4C:48:66
Attempting to connect to B8:D6:1A:4C:48:66
[CHG] Device B8:D6:1A:4C:48:66 Connected: yes
[Gateway_Escape_7]# Connection successful
[Gateway_Escape_7]# [NEW] Primary Service (Handle 0x0000)
        /org/bluez/hci0/dev_B8_D6_1A_4C_48_66/service0001
        00001801-0000-1000-8000-00805f9b34fb
        Generic Attribute Profile
[Gateway_Escape_7]# [NEW] Characteristic (Handle 0x0000)
        /org/bluez/hci0/dev_B8_D6_1A_4C_48_66/service0001/char0002
        00002a05-0000-1000-8000-00805f9b34fb
        Service Changed
[Gateway_Escape_7]# [NEW] Descriptor (Handle 0x0000)
        /org/bluez/hci0/dev_B8_D6_1A_4C_48_66/service0001/char0002/desc0004
        00002902-0000-1000-8000-00805f9b34fb
        Client Characteristic Configuration
[Gateway_Escape_7]# [NEW] Primary Service (Handle 0x0000)
        /org/bluez/hci0/dev_B8_D6_1A_4C_48_66/service0028
        4fafc201-1fb5-459e-8fcc-c5c9c331914b
        Vendor specific
[Gateway_Escape_7]# [NEW] Characteristic (Handle 0x0000)
        /org/bluez/hci0/dev_B8_D6_1A_4C_48_66/service0028/char0029
        beb5483e-36e1-4688-b7f5-ea07361b26a8
        Vendor specific
[Gateway_Escape_7]# [NEW] Characteristic (Handle 0x0000)
        /org/bluez/hci0/dev_B8_D6_1A_4C_48_66/service0028/char002b
        d0e12345-6789-4abc-def0-123456789abc
        Vendor specific
[Gateway_Escape_7]# [NEW] Characteristic (Handle 0x0000)
        /org/bluez/hci0/dev_B8_D6_1A_4C_48_66/service0028/char002d
        cba1d466-344c-4be3-ab3f-189f80dd7518
        Vendor specific
```

Observed states during connections:
Locked -> Connected -> Guarded

Ok let's poll the IDs showd in discovery:
```
00001801-0000-1000-8000-00805f9b34fb write failed: Bluetooth command failed (code: 10, error: No attribute found within the given range)
00002a05-0000-1000-8000-00805f9b34fb write failed: Bluetooth command failed (code: 2, error: Attribute can't be read)
00002902-0000-1000-8000-00805f9b34fb write failed: Bluetooth command failed (code: 10, error: No attribute found within the given range)
4fafc201-1fb5-459e-8fcc-c5c9c331914b write failed: Bluetooth command failed (code: 10, error: No attribute found within the given range)
beb5483e-36e1-4688-b7f5-ea07361b26a8 -> {"message":"If you are reading this, I didn't make it. As you see, they left these BLE services unprotected, but the exit is never left unguarded! Don't worry, I left something for you even though I am not here. I was trying to find a moment where the exit is totally unguarded, but I failed. Analyze the Wi-Fi subcarrier signal variance over time. I hope you make it out!"}
d0e12345-6789-4abc-def0-123456789abc -> {"log_id":70,"drive_url":"https://drive.google.com/drive/folders/1hDcAnyGrbPCVt5zssnUBbFR-d9BFzHjA","aes_key_hex":"9f3cc1aabd7b54b2932b3bf39e6ea8cb05c05a52263ebba51b2b53a57da861ec"}
cba1d466-344c-4be3-ab3f-189f80dd7518 -> 
```

Download the file from Google Drive.
Decrypting with provided key:
```
with open("log_070.enc", "rb") as f:
    blob = f.read()
iv, ct = blob[:16], blob[16:]
pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
with open("log_070.csv", "wb") as f:
    f.write(pt)
print(pt[:120].decode(errors="replace"))
```

csv file appeared:
```
timestamp_ms,rssi,subcarrier_count,amplitudes
1767225600000,-50,64,"[15.34,15.72,11.31,15.68,22.86,14.86,19.67,13.40,13.49,12.06,10.18,14.24,16.84,15.69,12.71,13.50,14.48,14.34,14.79,14.15,18.70,16.99,14.04,13.79,9.63,11.56,14.65,16.22,9.41,15.92,11.23,12.95,15.07,20.01,14.29,15.37,13.14,9.44,19.91,14.44,9.07,17.86,9.97,13.83,16.49,15.36,12.57,17.91,9.70,10.69,18.13,21.69,10.97,18.33,15.37,14.75,14.54,17.32,17.71,17.39,21.08,17.69,19.37,17.52]"
1767225600500,-49,64,"[16.59,16.49,11.64,16.87,15.98,13.90,13.14,10.77,13.08,13.22,15.39,12.72,16.25,16.34,18.89,12.75,11.76,15.57,18.36,14.44,16.46,11.08,14.83,14.90,16.98,15.48,16.36,16.66,13.12,16.14,16.62,13.38,12.52,13.52,15.45,18.09,14.50,14.20,13.19,12.78,13.21,15.03,13.09,14.48,15.20,10.77,12.10,15.94,16.68,19.84,15.68,13.86,15.01,12.54,18.83,12.95,20.23,17.78,16.09,17.49,13.12,18.70,13.46,12.83]"
```

analyzing amplitudes with a bit of statistical magic and getting the following timestamps:
```
2026-01-01 11:48:00 -> 11:49:59  (120s)   epoch 1767268080
2026-01-01 13:48:00 -> 14:17:59  (1800s)  epoch 1767275280
2026-01-01 15:08:00 -> 15:09:59  (120s)   epoch 1767280080
2026-01-01 15:48:00 -> 15:48:29  (30s)    epoch 1767282480
2026-01-01 16:18:00 -> 16:19:59  (120s)   epoch 1767284280
2026-01-01 17:18:00 -> 17:19:59  (120s)   epoch 1767287880
2026-01-01 18:48:00 -> 18:49:59  (120s)   epoch 1767293280
```


iterating ovet such timestamps, we are truing to set CLOCK_SET_CHAR via "cba1d466-344c-4be3-ab3f-189f80dd7518" UUID and checking the status. Once we reached "UNGUARDED", we fire `escape` and get the flag:
```
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

```

Flag: **esc_2026{Challenge_7_WiFi_MotionDetection_f9dc4caf}**