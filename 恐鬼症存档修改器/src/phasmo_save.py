import argparse
import hashlib
import os
import re
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aes as A

PASSWORD = b"t36gref9u84y7f43g"
PBKDF2_ITERS = 100
KEYLEN = 16
IVLEN = 16

DEFAULT_SAVE = os.path.expandvars(
    r"%USERPROFILE%\AppData\LocalLow\Kinetic Games\Phasmophobia\SaveFile.txt")


def derive_key(iv, password=PASSWORD):
    return hashlib.pbkdf2_hmac("sha1", password, iv, PBKDF2_ITERS, KEYLEN)


def decrypt_bytes(data, password=PASSWORD):
    if len(data) < IVLEN * 2 or (len(data) - IVLEN) % 16:
        raise ValueError("file is not IV+AES-CBC shaped (%d bytes)" % len(data))
    iv, ct = data[:IVLEN], data[IVLEN:]
    pt = A.pkcs7_unpad(A.cbc_decrypt(ct, derive_key(iv, password), iv))
    if pt is None:
        raise ValueError("PKCS7 padding invalid - wrong password or damaged file")
    return pt


def encrypt_bytes(plaintext, password=PASSWORD, iv=None):
    iv = os.urandom(IVLEN) if iv is None else iv
    ct = A.cbc_encrypt(A.pkcs7_pad(plaintext), derive_key(iv, password), iv)
    return iv + ct


def read_plain(path):
    return decrypt_bytes(open(path, "rb").read())


def _entry_pattern(key):
    return re.compile(
        rb'("' + re.escape(key.encode()) + rb'"\s*:\s*\{\s*"__type"\s*:\s*"'
        rb'(int|float|string|bool)"\s*,\s*"value"\s*:\s*)(-?[0-9.eE+]+|"[^"]*"|True|False)'
    )


def get_value(text, key):
    m = _entry_pattern(key).search(text)
    return None if m is None else m.group(3).decode()


def set_value(text, key, newval):
    pat = _entry_pattern(key)
    if not pat.search(text):
        raise KeyError("no such key in save: %s" % key)
    return pat.sub(lambda m: m.group(1) + str(newval).encode(), text, count=1)


def list_keys(text):
    return re.findall(rb'"([^"]+)"\s*:\s*\{\s*"__type"\s*:\s*"', text)


def main():
    ap = argparse.ArgumentParser(description="Phasmophobia SaveFile.txt editor")
    ap.add_argument("--save", default=DEFAULT_SAVE)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keys", help="list keys in the save")
    p_get = sub.add_parser("get", help="print a key's value")
    p_get.add_argument("key")
    p_set = sub.add_parser("set", help="set a key's value")
    p_set.add_argument("key")
    p_set.add_argument("value")
    p_set.add_argument("--apply", action="store_true",
                       help="write back to the real save (otherwise writes <save>.new)")

    args = ap.parse_args()

    if args.cmd == "keys":
        text = read_plain(args.save)
        for k in list_keys(text):
            print("%-40s %s" % (k.decode(), get_value(text, k.decode())))
        return

    if args.cmd == "get":
        print(get_value(read_plain(args.save), args.key))
        return

    if args.cmd == "set":
        text = read_plain(args.save)
        before = get_value(text, args.key)
        new = set_value(text, args.key, args.value)
        assert decrypt_bytes(encrypt_bytes(new)) == new, "round-trip check failed"
        out = args.save if args.apply else args.save + ".new"
        if args.apply:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            shutil.copy2(args.save, args.save + ".bak-" + stamp)
        with open(out, "wb") as f:
            f.write(encrypt_bytes(new))
        print("%s: %s -> %s" % (args.key, before, args.value))
        print("written to %s" % out)


if __name__ == "__main__":
    main()
