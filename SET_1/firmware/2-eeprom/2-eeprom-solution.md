# EEPROM Secrets (200 pts)

## XOR EEPROM

FW prints this help menu:
```
  dump_eeprom  - Dump config database (protected by an exclusive key repeating over identity)
```

Printed EEPROM:
```
--- EEPROM HEX DUMP ---
0010: F4 B9 78 2E 31 3B FF 81 1A 4C 48 64 A8 F6 2A 4D 
0020: 07 02 DE BF 79 29 17 23 EF D6 1A 4C 04 2C DC D4 
0030: 5C 20 27 0B CA E7 45 0B 1F 64 B8 D6 5E 19 2E 67 
0040: FE BA 75 23 3A 56 E7 91 4D 4C 48 64 CF 5E 83 4F 
0050: 1B 01 CA A0 7F 3E 17 23 EF D6 1A 4C C0 FD 12 D3 
0060: 49 38 27 16 D9 B1 7F 13 0F 33 B8 D6 0B 6E 7B 65 
0070: F5 B7 69 38 2D 16 E7 91 4D 4C 48 64 FC AE 21 D5 
0080: 0F 05 CA B7 7D 29 17 23 EF D6 1A 4C 96 C9 06 D4 
0090: 5D 2D 3A 00 DD B8 45 0B 1F 64 B8 D6 4F 2A 3F 65 
00A0: EE B7 6F 20 3C 3B FF 81 1A 4C 48 64 46 3B E0 5C 
00B0: 8C 8D 8E 8F 88 89 8A 8B 84 85 86 87 80 81 82 83 
00C0: FC FD FE FF F8 F9 FA FB F4 F5 F6 F7 F0 F1 F2 F3 
00D0: EC ED EE EF E8 E9 EA EB E4 E5 E6 E7 E0 E1 E2 E3 
00E0: DC DD DE DF D8 D9 DA DB D4 D5 D6 D7 D0 D1 D2 D3 
00F0: CC CD CE CF C8 C9 CA CB C4 C5 C6 C7 C0 C1 C2 C3 
-----------------------
```

get_mac gives `MAC: B8:D6:1A:4C:48:64`.

After XORing MAC and EERPOM (`xor_dump.py`), we got
```
4d 61 73 74 65 72 5f 47 57 00 00 00 44 78 3b 99   b'Master_GW\x00\x00\x00Dx;\x99'
```
Seems like `44:78:3b` is expected suffix.

## Getting access

Checking cleared `dump_card` for any hints about the suffix location:
```
{"sector":1,"blocks":[
{"block":4,"data":"010000004C6F63616C47000000000000"},
{"block":5,"data":"4C4864FF000000000000000000000000"},
{"block":6,"data":"00000000000000000000000000000000"}]},
```

Beginning of block 5 is exactly like this message:
```
[AUDIT] Tap session logged: count=1 (Last visit status : Gateway MAC Suffix: 4C:48:64 Response: 0xFF (Access Denied))
```

Let's rewrite block 5 with master gateway data
```
> write_block 5 44783b99

{"event":"write_block","status":"pending","block":5,"timeout_s":15,"msg":"Present card within the timeout"}
[5814947] RFID Card presented (UID: 4A10F055)
{"event":"write_block","ok":true,"block":5}
[5814966] [AUDIT] Tap session logged: count=2 (Gateway MAC Suffix: 4C:48:64)
[5814972] [AUDIT] Session counter updated to 3.
[5814979] [ACCESS-CTL] Primary gateway authorization verified! Access Granted.
esc_2026{eeprom_master_2fe3088dc9313488}
```


Flag: **esc_2026{eeprom_master_2fe3088dc9313488}**