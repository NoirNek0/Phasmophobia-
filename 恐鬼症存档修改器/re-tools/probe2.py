import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aes as A

SAVE = os.path.expandvars(
    r"%USERPROFILE%\AppData\LocalLow\Kinetic Games\Phasmophobia\SaveFile.txt")
PW = "t36gref9u84y7f43g"
PWB = PW.encode()

SALTS = [
    b"Ivan Medvedev",
    b"Easy Save 3", b"EasySave3", b"ES3", b"es3",
    b"", b"\x00" * 8, b"\x00" * 16,
    PWB, PWB[:8],
    b"Phasmophobia", b"Kinetic Games", b"Phasmo",
]
ITERS = [1, 2, 1000, 1024, 10000]


def looks(pt):
    if not pt or len(pt) < 32:
        return None
    pr = sum(1 for c in pt if 32 <= c < 127 or c in (9, 10, 13)) / len(pt)
    if pr < 0.93:
        return None
    if A.pkcs7_unpad(pt) is None:
        return None
    return pr


def main():
    data = open(SAVE, "rb").read()
    hits = []
    tried = 0
    for salt in SALTS:
        for it in ITERS:
            for size in (16, 32):
                try:
                    key = hashlib.pbkdf2_hmac("sha1", PWB, salt, it, size)
                except Exception:
                    continue
                tried += 1
                for lname, ct, iv in (
                    ("iv-prefix", data[16:], data[:16]),
                    ("iv-zero", data, bytes(16)),
                    ("iv-key", data, key),
                ):
                    try:
                        pt = A.cbc_decrypt(ct, key, iv)
                    except Exception:
                        continue
                    pr = looks(pt)
                    if pr:
                        hits.append((salt, it, size, lname, pr, pt[:80]))
    print("tried %d derivations x 3 layouts" % tried)
    if not hits:
        print("[!] no hit")
        return
    for h in hits:
        print("[+] salt=%r iters=%d key=%d layout=%s printable=%.3f" % h[:5])
        print("    %r" % h[5])


if __name__ == "__main__":
    main()
