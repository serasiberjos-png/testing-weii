import os

import secrets

import hashlib

from getpass import getpass
 
def generate_key(length=32):

    """Generate random 32-byte key (cryptographically secure)."""

    return secrets.token_bytes(length)
 
def derive_subkeys(key):

    """Derive subkeys dari key utama menggunakan SHA-256."""

    h = hashlib.sha256(key).digest()

    xor_key = h[:16]                    # repeating XOR key

    shift_key = int.from_bytes(h[16:20], 'big') % 8

    # Key-dependent permutation table (mirip RC4 init)

    perm_key = list(range(256))

    j = 0

    for i in range(256):

        j = (j + perm_key[i] + h[i % len(h)]) % 256

        perm_key[i], perm_key[j] = perm_key[j], perm_key[i]

    return xor_key, shift_key, perm_key
 
def custom_encrypt(data: bytes, key: bytes) -> bytes:

    xor_key, shift_key, perm_key = derive_subkeys(key)

    # Layer 1: XOR repeating

    encrypted = bytearray(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(data))

    # Layer 2: Cyclic left shift

    encrypted = bytearray(((b << shift_key) | (b >> (8 - shift_key))) & 0xFF for b in encrypted)

    # Layer 3: Byte permutation

    return bytes(perm_key[b] for b in encrypted)
 
def custom_decrypt(data: bytes, key: bytes) -> bytes:

    xor_key, shift_key, perm_key = derive_subkeys(key)

    # Inverse permutation

    inv_perm = [0] * 256

    for i, p in enumerate(perm_key):

        inv_perm[p] = i

    decrypted = bytearray(inv_perm[b] for b in data)

    # Inverse shift (right cyclic)

    decrypted = bytearray(((b >> shift_key) | (b << (8 - shift_key))) & 0xFF for b in decrypted)

    # Inverse XOR

    return bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(decrypted))
 
def process_path(path: str, key: bytes, mode: str = 'encrypt'):

    """Proses SATU path yang didefinisikan (file atau folder) – hapus original setelah sukses."""

    func = custom_encrypt if mode == 'encrypt' else custom_decrypt

    ext = '.enc' if mode == 'encrypt' else ''

    path = os.path.normpath(path)

    if os.path.isfile(path):

        try:

            with open(path, 'rb') as f:

                data = f.read()  # ← perbaikan di sini

            processed = func(data, key)

            if mode == 'encrypt':

                outpath = path + ext

            else:  # decrypt

                outpath = path[:-4] if path.lower().endswith('.enc') else path + '.dec'

            with open(outpath, 'wb') as f:

                f.write(processed)

            os.remove(path)  # HAPUS FILE ASLI

            print(f"✓ {mode.upper()} OK: {path} → {outpath}")

        except Exception as e:

            print(f"✗ GAGAL proses file: {path}\n  {type(e).__name__}: {e}")

    elif os.path.isdir(path):

        print(f"Memproses folder (hanya target ini): {path}")

        for root, _, files in os.walk(path, topdown=False):

            for file in files:

                filepath = os.path.join(root, file)

                if mode == 'decrypt' and not filepath.lower().endswith('.enc'):

                    continue

                try:

                    with open(filepath, 'rb') as f:

                        data = f.read()

                    processed = func(data, key)

                    outpath = filepath + ext if mode == 'encrypt' else filepath[:-4]

                    with open(outpath, 'wb') as f:

                        f.write(processed)

                    os.remove(filepath)

                    print(f"  ✓ {mode.upper()}: {filepath} → {outpath}")

                except Exception as e:

                    print(f"  ✗ GAGAL: {filepath} → {e}")

    else:

        print(f"✗ Path tidak valid: {path}")
 
def main():

    targets = []  # HANYA path yang kamu tambahkan manual yang akan diproses
 
    while True:

        print("\n" + "═"*70)

        print("   SELECTIVE ENCRYPTOR - HANYA TARGET YANG KAMU DEFINISIKAN")

        print("   (File asli dihapus setelah sukses - HATI-HATI!)")

        print("═"*70)

        print("1. Generate Key Baru")

        print("2. Tambah target (file atau folder)")

        print("3. Lihat daftar target")

        print("4. ENKRIPSI semua target yang ditambahkan")

        print("5. DEKRIPSI semua target yang ditambahkan")

        print("6. Clear daftar target")

        print("7. Keluar")

        choice = input("\nPilih: ").strip()

        if choice == '1':

            key = generate_key()

            print("\nKey (hex):")

            print(key.hex())

            print("→ Simpan aman di tempat lain!\n")

        elif choice == '2':

            p = input("Masukkan path file ATAU folder: ").strip()

            p = os.path.expanduser(p)

            if os.path.exists(p):

                targets.append(p)

                print(f"✓ Ditambahkan: {p}")

            else:

                print("✗ Path tidak ditemukan")

        elif choice == '3':

            if not targets:

                print("Belum ada target yang ditambahkan.")

            else:

                print("\nTarget yang akan diproses:")

                for i, t in enumerate(targets, 1):

                    print(f"  {i}. {t}")

        elif choice in ['4', '5']:

            if not targets:

                print("Tidak ada target untuk diproses.")

                continue

            key_hex = getpass("Masukkan key (hex): ")

            try:

                key = bytes.fromhex(key_hex)

            except ValueError:

                print("Format hex salah!")

                continue

            mode = 'encrypt' if choice == '4' else 'decrypt'

            print(f"\n>>> MEMPROSES HANYA TARGET YANG DITAMBAHKAN ({mode.upper()}) <<<\n")

            for path in targets[:]:

                process_path(path, key, mode)

            print("\nSelesai.")

        elif choice == '6':

            targets.clear()

            print("Daftar target dikosongkan.")

        elif choice == '7':

            print("Keluar. Gunakan dengan penuh tanggung jawab.")

            break

        else:

            print("Pilihan tidak valid.")
 
if __name__ == "__main__":

    main()
 