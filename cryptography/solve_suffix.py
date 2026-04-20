from pwn import process

p = process("/challenge/run")

def read_menu():
    # Eat menu until the "Choice? " prompt
    p.recvuntil(b"Choice? ")

def enc_chosen(pt: bytes) -> bytes:
    """Encrypt chosen plaintext (choice 1). Returns ciphertext bytes."""
    read_menu()
    p.sendline(b"1")
    p.recvuntil(b"Data? ")
    p.sendline(pt)
    line = p.recvline().decode().strip()
    assert line.startswith("Result: ")
    ct_hex = line.split()[1]
    return bytes.fromhex(ct_hex)

def enc_tail(length: int) -> bytes:
    """Encrypt tail of flag of given length (choice 2). Returns ciphertext bytes."""
    read_menu()
    p.sendline(b"2")
    p.recvuntil(b"Length? ")
    p.sendline(str(length).encode())
    line = p.recvline().decode().strip()
    assert line.startswith("Result: ")
    ct_hex = line.split()[1]
    return bytes.fromhex(ct_hex)

# Reasonable alphabet for pwn.college flags
ALPHABET = (
    b"abcdefghijklmnopqrstuvwxyz"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"0123456789"
    b"{}_-.@"
)

known_suffix = b""
MAX_LEN = 80  # upper bound; most flags are much shorter

for k in range(1, MAX_LEN + 1):
    print(f"[*] Recovering byte #{k} from the end...")
    codebook = {}

    # Build dictionary: ciphertext -> guessed first byte
    for ch in ALPHABET:
        pt = bytes([ch]) + known_suffix
        ct = enc_chosen(pt)
        codebook[ct] = ch

    # Encrypt the last k bytes of the flag
    tail_ct = enc_tail(k)

    if tail_ct not in codebook:
        print(f"[!] No match in codebook at k={k}, stopping.")
        break

    recovered = codebook[tail_ct]
    known_suffix = bytes([recovered]) + known_suffix  # prepend
    print(f"[+] Recovered byte: {chr(recovered)!r}")
    print(f"    Known suffix so far: {known_suffix.decode(errors='replace')}")

    # Optional early stop if it looks like a full flag
    if known_suffix.startswith(b"pwn.college{") and known_suffix.endswith(b"}"):
        break

print("\n[*] Final recovered flag (guess):", known_suffix.decode(errors="replace"))