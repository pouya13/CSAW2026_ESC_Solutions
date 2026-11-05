import serial

s = serial.Serial("/dev/ttyUSB0", 115200, timeout=5)

s.write(f"write_block 5 44783b99\r\n".encode())
print(s.read(99999).decode(errors="replace"))
