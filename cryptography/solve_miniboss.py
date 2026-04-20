from pwn import process

BLOCK_SIZE = 16

p = process("/challenge/run")

def enc_prefix(prefix: bytes) -> bytes:
    """
    Send hex-encoded prefix to the oracle.
    Plaintext = prefix || flag.
    Return full ciphertext bytes.
    """
    p.recvuntil(b"Data? ")
    # Convert raw bytes -> hex string -> send as ASCII
    p.sendline(prefix.hex().encode())
    line = p.recvline().decode().strip()
    assert line.startswith("Ciphertext: ")
    ct_hex = line.split()[1]
    return bytes.fromhex(ct_hex)

# Reasonable alphabet for pwn.college flags
ALPHABET = (
    b"abcdefghijklmnopqrstuvwxyz"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"0123456789"
    b"{}_-.@"
)

known_flag = b""
MAX_LEN = 80  # upper bound; adjust if needed

for i in range(MAX_LEN):
    print(f"[*] Recovering byte #{i}...")

    # Choose padding so that flag[i] is the last byte of its block
    pad_len = (BLOCK_SIZE - 1 - (i % BLOCK_SIZE)) % BLOCK_SIZE
    prefix_pad = b"A" * pad_len

    # Block where flag[i] lives (0-based)
    block_index = i // BLOCK_SIZE

    # 1) Get target block from oracle with just the padding prefix
    ct = enc_prefix(prefix_pad)
    start = block_index * BLOCK_SIZE
    target_block = ct[start:start + BLOCK_SIZE]

    # 2) Build dictionary: block -> candidate byte
    codebook = {}
    for ch in ALPHABET:
        pt = prefix_pad + known_flag + bytes([ch])
        ct_candidate = enc_prefix(pt)
        block = ct_candidate[start:start + BLOCK_SIZE]
        codebook[block] = ch

    if target_block not in codebook:
        print(f"[!] No match in codebook at position {i}, stopping.")
        break

    recovered = codebook[target_block]
    known_flag += bytes([recovered])
    print(f"[+] Recovered byte: {chr(recovered)!r}")
    print(f"    Flag so far: {known_flag.decode(errors='replace')}")

    if recovered == ord('}'):
        break

print("\n[*] Final recovered flag guess:", known_flag.decode(errors="replace"))