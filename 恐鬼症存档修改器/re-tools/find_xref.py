import os
import struct
import sys

DLL = os.environ.get(
    "PHASMO_DLL", r"D:\game\steamapps\common\Phasmophobia\GameAssembly.dll")

MODRM_RIP = (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D)
PREFIXES = [(b"\x48\x8b", 2), (b"\x48\x8d", 2), (b"\x4c\x8b", 2),
            (b"\x4c\x8d", 2), (b"\x8b", 1), (b"\x8d", 1)]


def sections(path):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0", "not a PE"
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsize = struct.unpack_from("<H", data, pe + 20)[0]
    base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
    secs = []
    off = pe + 24 + optsize
    for i in range(nsec):
        e = data[off + i * 40: off + (i + 1) * 40]
        name = e[:8].rstrip(b"\0").decode(errors="replace")
        vsize, va, rsize, raw = struct.unpack_from("<IIII", e, 8)
        chars = struct.unpack_from("<I", e, 36)[0]
        secs.append((name, va, vsize, raw, rsize, chars))
    return data, base, secs


def rva_of_fileoff(secs, foff):
    for name, va, vsize, raw, rsize, _ in secs:
        if raw and raw <= foff < raw + rsize:
            return va + (foff - raw)
    return None


def main():
    target = int(sys.argv[1], 0)
    data, base, secs = sections(DLL)
    print("image base  = 0x%X" % base)
    for name, va, vsize, raw, rsize, chars in secs:
        print("  %-8s rva=0x%08X vsize=0x%08X raw=0x%08X" % (name, va, vsize, raw))
    print("target RVA  = 0x%X\n" % target)

    exec_secs = [(n, va, vs, r, rs) for n, va, vs, r, rs, c in secs
                 if c & 0x20000000 and r]
    hits = []
    for name, va, vsize, raw, rsize in exec_secs:
        blob = data[raw:raw + rsize]
        for pre, plen in PREFIXES:
            start = 0
            while True:
                i = blob.find(pre, start)
                if i < 0:
                    break
                start = i + 1
                j = i + plen
                if j + 5 > len(blob):
                    continue
                if blob[j] not in MODRM_RIP:
                    continue
                disp = struct.unpack_from("<i", blob, j + 1)[0]
                rip_rva = rva_of_fileoff(secs, raw + j + 5)
                if rip_rva is None:
                    continue
                if rip_rva + disp == target:
                    hits.append(raw + i)

    print("references found: %d" % len(hits))
    for h in hits:
        print("   file offset 0x%08X   RVA 0x%08X" % (h, rva_of_fileoff(secs, h) or -1))


if __name__ == "__main__":
    main()
