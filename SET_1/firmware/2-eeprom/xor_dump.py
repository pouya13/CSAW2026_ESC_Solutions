mac = bytes.fromhex("B8D61A4C4864")

hexdump = """
F4 B9 78 2E 31 3B FF 81 1A 4C 48 64 A8 F6 2A 4D 
07 02 DE BF 79 29 17 23 EF D6 1A 4C 04 2C DC D4 
5C 20 27 0B CA E7 45 0B 1F 64 B8 D6 5E 19 2E 67 
FE BA 75 23 3A 56 E7 91 4D 4C 48 64 CF 5E 83 4F 
1B 01 CA A0 7F 3E 17 23 EF D6 1A 4C C0 FD 12 D3 
49 38 27 16 D9 B1 7F 13 0F 33 B8 D6 0B 6E 7B 65 
F5 B7 69 38 2D 16 E7 91 4D 4C 48 64 FC AE 21 D5 
0F 05 CA B7 7D 29 17 23 EF D6 1A 4C 96 C9 06 D4 
5D 2D 3A 00 DD B8 45 0B 1F 64 B8 D6 4F 2A 3F 65 
EE B7 6F 20 3C 3B FF 81 1A 4C 48 64 46 3B E0 5C 
8C 8D 8E 8F 88 89 8A 8B 84 85 86 87 80 81 82 83 
FC FD FE FF F8 F9 FA FB F4 F5 F6 F7 F0 F1 F2 F3 
EC ED EE EF E8 E9 EA EB E4 E5 E6 E7 E0 E1 E2 E3 
DC DD DE DF D8 D9 DA DB D4 D5 D6 D7 D0 D1 D2 D3 
CC CD CE CF C8 C9 CA CB C4 C5 C6 C7 C0 C1 C2 C3
"""

data = bytes.fromhex(hexdump.replace("\n", " "))
out = bytes(b ^ mac[i % len(mac)] for i, b in enumerate(data))
# print(out.decode(errors="replace"))

for i in range(0, len(out), 16):
    rec = out[i:i+16]
    print(rec.hex(' '), " ", rec)