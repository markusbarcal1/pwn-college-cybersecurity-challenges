import urllib.parse
import urllib.request

BASE = "http://challenge.localhost/"

def get_ciphertext_hex(query: str) -> str:
    """
    Sends ?query=... to the server and parses the ciphertext hex
    from the HTML response.
    """
    params = urllib.parse.urlencode({"query": query})
    url = BASE + "?" + params
    with urllib.request.urlopen(url) as resp:
        html = resp.read().decode()

    # HTML contains something like:
    # <b>Results:</b><pre>abcdef1234...</pre>
    marker = "<b>Results:</b><pre>"
    start = html.index(marker) + len(marker)
    end = html.index("</pre>", start)
    ct_hex = html[start:end].strip()
    return ct_hex

# Reasonable alphabet for pwn.college flags
ALPHABET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "{}_-@."
)

print("[*] Building codebook...")
ct_to_char = {}

for ch in ALPHABET:
    # query must be a valid SQL expression that returns our plaintext
    # SELECT 'X' FROM secrets
    q = f"'{ch}'"
    ct_hex = get_ciphertext_hex(q)
    ct_to_char[ct_hex] = ch

print("[*] Codebook size:", len(ct_to_char))

# Now recover the flag one character at a time
flag_chars = []

for i in range(1, 256):  # 1-based index, 256 is just an upper bound
    # SELECT SUBSTR(flag, i, 1) FROM secrets
    q = f"SUBSTR(flag,{i},1)"
    ct_hex = get_ciphertext_hex(q)
    ch = ct_to_char.get(ct_hex, "?")
    flag_chars.append(ch)
    print(f"[+] index {i}: {ch}")
    if ch == "}":
        break

flag = "".join(flag_chars)
print("[*] Recovered flag:", flag)