import os
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

MAGIC = b'CL01'
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_LEN = 32
CHUNK_SIZE = 64 * 1024

def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    key = kdf.derive(password_bytes)
    return key

def encrypt_file(in_path: str, out_path: str, password: str, iterations: int = 200_000):
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt, iterations)
    aesgcm = AESGCM(key)
    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        fout.write(MAGIC)
        fout.write(salt)
        fout.write(nonce)
        chunk_index = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            nonce_int = int.from_bytes(nonce, 'big') ^ chunk_index
            chunk_nonce = nonce_int.to_bytes(NONCE_SIZE, 'big')
            ciphertext = aesgcm.encrypt(chunk_nonce, chunk, None)
            fout.write(struct.pack('<I', len(ciphertext)))
            fout.write(ciphertext)
            chunk_index += 1
        hide_file(in_path)


def decrypt_file(in_path: str, out_path: str, password: str, iterations: int = 200_000):
    with open(in_path, 'rb') as fin:
        magic = fin.read(4)
        if magic != MAGIC:
            raise ValueError('Unrecognized file format')
        salt = fin.read(SALT_SIZE)
        nonce = fin.read(NONCE_SIZE)
        key = derive_key(password, salt, iterations)
        aesgcm = AESGCM(key)
        with open(out_path, 'wb') as fout:
            chunk_index = 0
            while True:
                size_bytes = fin.read(4)
                if not size_bytes:
                    break
                (ct_len,) = struct.unpack('<I', size_bytes)
                ciphertext = fin.read(ct_len)
                if len(ciphertext) != ct_len:
                    raise IOError("File truncated or corrupted")
                nonce_int = int.from_bytes(nonce, 'big') ^ chunk_index
                chunk_nonce = nonce_int.to_bytes(NONCE_SIZE, 'big')
                plaintext = aesgcm.decrypt(chunk_nonce, ciphertext, None)
                fout.write(plaintext)
                chunk_index += 1

import subprocess
import platform

def hide_file(path: str):
    """Hide a file after encryption (Windows-safe, reversible)."""
    try:
        if platform.system() == "Windows":
            subprocess.run(["attrib", "+h", path], check=True, shell=True)
        else:
            # On Linux/macOS, prefixing with '.' hides the file
            import os
            dir_name, base_name = os.path.split(path)
            if not base_name.startswith('.'):
                os.rename(path, os.path.join(dir_name, '.' + base_name))
    except Exception as e:
        print(f"Failed to hide file: {e}")

def secure_delete(path: str, passes: int = 3):
    try:
        if not os.path.isfile(path):
            return
        length = os.path.getsize(path)
        with open(path, 'ba+', buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass
