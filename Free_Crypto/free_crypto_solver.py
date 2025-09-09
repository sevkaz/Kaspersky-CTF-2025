import itertools, string, base64
from free_crypto import decrypt_block, xortext, divide_into_blocks

with open("output.txt") as f:
    b64 = f.read().strip()
ct = base64.b64decode(b64)

blk_len = 2
ct_blocks = [ct[i:i+blk_len] for i in range(0, len(ct), blk_len)]

iv = ct_blocks[0]    # if IV is prepended
ct_blocks = ct_blocks[1:]

printable_bytes = [ord(c) for c in string.printable]

def is_printable(b):
    try:
        s = b.decode()
    except:
        return False
    return all(ch in string.printable for ch in s)

# First block brute-force
for a, b in itertools.product(printable_bytes, repeat=2):
    kblk = bytes([a, b])
    pblk = xortext(decrypt_block(ct_blocks[0], kblk), iv[:2])
    if pblk.startswith(b"ka"):
        print("Found candidate:", kblk, pblk)
        break
