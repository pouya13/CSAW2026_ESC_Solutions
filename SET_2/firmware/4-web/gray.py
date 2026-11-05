h = "4b4f59304e5c5d4a3052585b5b515956305d59304f514b4e304e583054574e304e5c5730555a51542730565d515470564f5b483069615f647b52"

# https://en.wikipedia.org/wiki/Gray_code
def gray(n):
    m = n >> 1
    while m:
        n ^= m
        m >>= 1
    return n

print("".join(chr(gray(b)) for b in bytes.fromhex(h)))