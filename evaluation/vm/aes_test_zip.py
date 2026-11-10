"""Build a deterministic, benign WinZip-AES (AES-256) ZIP to prove an extractor can open
the encrypted-archive format MalwareBazaar uses, before any real sample is involved.

Independent of 7-Zip on purpose: the extractor under test only decrypts. Two entries cover
both AE versions: AE-1 (stored, CRC kept) and AE-2 (deflated, CRC zeroed).

    python -I evaluation/vm/aes_test_zip.py OUT.zip      # password: infected
"""
import hashlib, hmac, struct, sys, zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PASSWORD = b"infected"
ENTRIES = [  # (name, AE version, method 0=stored/8=deflate, content) -- plain benign text
    ("aes-test/ae1-stored.txt", 1, 0, b"FilesMagic AES extractor test, entry 1 (AE-1, stored). Benign text only.\n"),
    ("aes-test/ae2-deflate.txt", 2, 8, b"FilesMagic AES extractor test, entry 2 (AE-2, deflate). Benign text only.\n" * 20),
]
DOS_TIME, DOS_DATE = 0, (2026 - 1980) << 9 | 11 << 5 | 9  # fixed 2026-11-09 for byte-identical output


def _encrypt(name, data):
    salt = hashlib.sha256(b"fm-aes-test:" + name.encode()).digest()[:16]  # ponytail: fixed salt = reproducible test file, never for real secrets
    k = hashlib.pbkdf2_hmac("sha1", PASSWORD, salt, 1000, 66)
    ecb = Cipher(algorithms.AES(k[:32]), modes.ECB()).encryptor()
    stream = b"".join(ecb.update((i + 1).to_bytes(16, "little")) for i in range(-(-len(data) // 16)))
    ct = bytes(a ^ b for a, b in zip(data, stream))  # WinZip CTR: little-endian counter from 1
    return salt + k[64:] + ct + hmac.new(k[32:64], ct, hashlib.sha1).digest()[:10]


def build():
    local, central = b"", b""
    for name, ae, method, content in ENTRIES:
        n = name.encode()
        body = content
        if method:
            c = zlib.compressobj(9, zlib.DEFLATED, -15); body = c.compress(content) + c.flush()
        enc = _encrypt(name, body)
        crc = zlib.crc32(content) if ae == 1 else 0
        extra = struct.pack("<HHH2sBH", 0x9901, 7, ae, b"AE", 3, method)
        fixed = struct.pack("<HHHHHIII", 51, 1, 99, DOS_TIME, DOS_DATE, crc, len(enc), len(content))
        offset = len(local)
        local += b"PK\3\4" + fixed + struct.pack("<HH", len(n), len(extra)) + n + extra + enc
        central += (b"PK\1\2" + struct.pack("<H", 51) + fixed
                    + struct.pack("<HHHHHII", len(n), len(extra), 0, 0, 0, 0, offset) + n + extra)
    end = struct.pack("<4sHHHHIIH", b"PK\5\6", 0, 0, len(ENTRIES), len(ENTRIES), len(central), len(local), 0)
    return local + central + end


if __name__ == "__main__":
    out = build()
    open(sys.argv[1], "wb").write(out)
    print(hashlib.sha256(out).hexdigest(), len(out), sys.argv[1])
    for name, _, _, content in ENTRIES:
        print(hashlib.sha256(content).hexdigest(), len(content), name)
