from Crypto.Util.strxor import strxor

while True:
    try:
        ct = input("Encrypted String: ").strip()
        key = input("Key String: ").strip()
    except EOFError:
        break

    pt = strxor(ct.encode(), key.encode()).decode()
    print("Plaintext:", pt)
    print()