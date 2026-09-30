import bisect
import json
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from find_xref import DLL, sections, rva_of_fileoff, MODRM_RIP, PREFIXES

CAP = Cs(CS_ARCH_X86, CS_MODE_64)
CAP.detail = True


def raw_hits(data, secs, target):
    out = []
    for name, va, vsize, raw, rsize, chars in secs:
        if not (chars & 0x20000000) or not raw:
            continue
        blob = data[raw:raw + rsize]
        for pre, plen in PREFIXES:
            start = 0
            while True:
                i = blob.find(pre, start)
                if i < 0:
                    break
                start = i + 1
                j = i + plen
                if j + 5 > len(blob) or blob[j] not in MODRM_RIP:
                    continue
                disp = struct.unpack_from("<i", blob, j + 1)[0]
                rip_rva = rva_of_fileoff(secs, raw + j + 5)
                if rip_rva is not None and rip_rva + disp == target:
                    out.append(raw + i)
    return sorted(set(out))


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    target = int(sys.argv[1], 0)
    data, base, secs = sections(DLL)
    hits = raw_hits(data, secs, target)
    print("raw (deduped) candidate offsets: %d" % len(hits))

    good = []
    for off in hits:
        insns = list(CAP.disasm(data[off:off + 16], base + off))
        if not insns:
            continue
        ins = insns[0]
        next_rva = rva_of_fileoff(secs, off + ins.size)
        if next_rva is None:
            continue
        for op in ins.operands:
            if op.type == 3 and op.mem.base == 41:
                if next_rva + op.mem.disp == target:
                    good.append((off, ins.mnemonic, ins.op_str, ins.size))
                    break
    print("validated instructions: %d\n" % len(good))

    sm = json.load(open("dump/script.json"))["ScriptMethod"]
    addrs = sorted((e["Address"], e["Name"], e.get("Signature", "")) for e in sm)
    keys = [a for a, _, _ in addrs]

    seen = {}
    for off, mn, ops, size in good:
        rva = rva_of_fileoff(secs, off)
        k = bisect.bisect_right(keys, rva) - 1
        name = addrs[k][1] if k >= 0 else "<none>"
        seen.setdefault(name, []).append((hex(rva), mn + " " + ops))
        print("  rva=%-10s %-28s  %s" % (hex(rva), name, mn + " " + ops))

    print("\n=== distinct enclosing methods: %d ===" % len(seen))
    for name in sorted(seen):
        print("  %-70s x%d" % (name, len(seen[name])))


if __name__ == "__main__":
    main()
