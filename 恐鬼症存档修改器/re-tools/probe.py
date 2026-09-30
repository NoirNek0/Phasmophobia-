import hashlib
import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aes as A

SAVE = os.path.expandvars(
    r"%USERPROFILE%\AppData\LocalLow\Kinetic Games\Phasmophobia\SaveFile.txt")
PASSWORD = "t36gref9u84y7f43g"


def selftest():
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    got = A.ecb_encrypt(pt, key)
    assert got == ct, "AES-128 encrypt FAILED: %s" % got.hex()
    assert A.ecb_decrypt(ct, key) == pt, "AES-128 decrypt FAILED"
    k192 = bytes(range(24))
    c192 = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
    assert A.ecb_encrypt(pt, k192) == c192, "AES-192 FAILED"
    k256 = bytes(range(32))
    c256 = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    assert A.ecb_encrypt(pt, k256) == c256, "AES-256 FAILED"
    print("[ok] AES-128/192/256 self-test passed (FIPS-197 vectors)\n")


def key_candidates(pw):
    b = pw.encode("utf-8")
    out = []
    out.append(("md5(pw)", hashlib.md5(b).digest()))
    out.append(("md5(pwhex)", hashlib.md5(hashlib.md5(b).hexdigest().encode()).digest()))
    out.append(("sha256(pw)[:16]", hashlib.sha256(b).digest()[:16]))
    out.append(("sha256(pw)[:24]", hashlib.sha256(b).digest()[:24]))
    out.append(("sha256(pw)", hashlib.sha256(b).digest()))
    out.append(("sha1(pw)[:16]", hashlib.sha1(b).digest()[:16]))
    for size in (16, 24, 32):
        if len(b) <= size:
            out.append(("pw+zero%-d" % size, b + bytes(size - len(b))))
            out.append(("pw+pkcs%-d" % size, b + bytes([size - len(b)]) * (size - len(b))))
        out.append(("pw[:%d]+zero" % size, (b[:size] + bytes(size))[:size]))
    rep = (b * 8)[:32]
    for size in (16, 24, 32):
        out.append(("pw*rep[:%d]" % size, rep[:size]))
    return out


def score(pt):
    if not pt:
        return -1.0
    printable = sum(1 for c in pt if 32 <= c < 127 or c in (9, 10, 13))
    return printable / len(pt)


def main():
    selftest()
    data = open(SAVE, "rb").read()
    print("file size = %d bytes (%.2f blocks)\n" % (len(data), len(data) / 16))

    results = []

    def try_dec(name, key, mode, ct, iv=None, off=0):
        try:
            if mode == "CBC":
                pt = A.cbc_decrypt(ct, key, iv)
            else:
                pt = A.ecb_decrypt(ct, key)
        except Exception as e:
            return
        s = score(pt)
        unp = A.pkcs7_unpad(pt) is not None
        has_brace = b"{" in pt or b"SaveFile" in pt or b"$" in pt
        results.append((s + (0.5 if unp else 0) + (1.0 if has_brace else 0),
                        name, mode, off, s, unp, has_brace, pt[:96]))

    for kname, key in key_candidates(PASSWORD):
        if len(key) not in (16, 24, 32):
            continue
        try_dec(kname, key, "CBC", data[16:], iv=data[:16], off=0)
        try_dec(kname, key, "CBC", data, iv=bytes(16))
        try_dec(kname, key, "CBC", data, iv=key)
        try_dec(kname, key, "ECB", data)

    results.sort(key=lambda r: -r[0])
    print("top candidates (score, keyderiv, mode, iv_offset, printable, pkcs7ok, brace):")
    for r in results[:12]:
        sc, name, mode, off, s, unp, hb, head = r
        print("  %6.2f  %-18s %-4s off=%d  pr=%.2f  pkcs7=%s brace=%s" %
              (sc, name, mode, off, s, unp, hb))
        print("          %r" % head[:72])
    print()
    best = results[0]
    if best[0] < 1.3:
        print("[!] No confident hit - none of the naive derivations worked.")
    else:
        print("[+] Best: %s / %s" % (best[1], best[2]))


if __name__ == "__main__":
    main()
