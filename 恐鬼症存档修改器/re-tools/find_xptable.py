import os
import struct
import sys

ROOT = os.environ.get(
    "PHASMO_DATA", r"D:\game\steamapps\common\Phasmophobia\Phasmophobia_Data")

CUMULATIVE = [100, 331, 668, 1100, 1624]
DELTAS = [231, 337, 432, 495]


def pats(vals, fmt):
    return (struct.pack("<%d%s" % (len(vals), fmt), *vals), fmt, vals)


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    pats_list = [pats(CUMULATIVE, "i"), pats(CUMULATIVE, "f"),
                 pats(DELTAS, "i"), pats(DELTAS, "f")]
    pats_list.append(pats([331, 668, 1100], "i"))

    total = 0
    CHUNK = 8 << 20
    for dirpath, _, files in os.walk(ROOT):
        for fn in files:
            path = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            total += size
            with open(path, "rb") as f:
                pos, carry = 0, b""
                while True:
                    buf = f.read(CHUNK)
                    if not buf:
                        break
                    data = carry + buf
                    base = pos - len(carry)
                    for pat, fmt, vals in pats_list:
                        s = 0
                        while True:
                            i = data.find(pat, s)
                            if i < 0:
                                break
                            s = i + 1
                            lo = max(0, i - 32)
                            print("[+] %s" % os.path.relpath(path, ROOT))
                            print("    off 0x%08X  %s%s = %s"
                                  % (base + i, fmt, len(vals), vals))
                            print("    ctx %s"
                                  % data[lo:i + len(pat) + 32].hex(" "))
                    carry = data[-64:]
                    pos += len(buf)
    print("\nscanned %.1f MB" % (total / 1e6))


if __name__ == "__main__":
    main()
