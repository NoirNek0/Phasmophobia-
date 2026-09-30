import bisect
import collections
import json
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from find_xref import DLL, sections, rva_of_fileoff
from verify_hits import raw_hits

CAP = Cs(CS_ARCH_X86, CS_MODE_64)
CAP.detail = True


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    target = int(sys.argv[1], 0)
    data, base, secs = sections(DLL)
    hits = raw_hits(data, secs, target)
    print("candidates: %d" % len(hits))

    sm = json.load(open("dump/script.json"))["ScriptMethod"]
    addrs = sorted((e["Address"], e["Name"], e.get("Signature", "")) for e in sm)
    keys = [a for a, _, _ in addrs]
    rva2name = dict((a, n) for a, n, _ in addrs)

    def enclosing(rva):
        k = bisect.bisect_right(keys, rva) - 1
        return addrs[k][1] if k >= 0 else "<none>"

    kinds = collections.Counter()
    helpers = collections.Counter()
    real = []
    for off in hits:
        insns = list(CAP.disasm(data[off:off + 24], base + off))
        if not insns:
            kinds["undecodable"] += 1
            continue
        i0 = insns[0]
        i1 = insns[1] if len(insns) > 1 else None
        next_rva = rva_of_fileoff(secs, off + i0.size)
        tgt = None
        for op in i0.operands:
            if op.type == 3 and op.mem.base == 41 and next_rva is not None:
                tgt = next_rva + op.mem.disp
        if tgt != target:
            kinds["not-a-ref"] += 1
            continue
        if i0.mnemonic == "lea" and i1 and i1.mnemonic == "call":
            kinds["stub"] += 1
            helpers[i1.op_str] += 1
        elif i0.mnemonic == "mov":
            kinds["mov-load"] += 1
            rva = rva_of_fileoff(secs, off)
            real.append((rva, i0.mnemonic + " " + i0.op_str, enclosing(rva)))
        else:
            kinds["other:" + i0.mnemonic] += 1
            rva = rva_of_fileoff(secs, off)
            real.append((rva, i0.mnemonic + " " + i0.op_str, enclosing(rva)))

    print("\nkind breakdown:", dict(kinds))
    print("\nregistration helpers called by stubs:")
    for h, n in helpers.most_common(10):
        rva = int(h, 16) - base if h.startswith("0x") else None
        nm = rva2name.get(rva, "<not a method>") if rva else "?"
        print("   %-18s x%-4d  %s" % (h, n, nm))

    print("\n=== non-stub sites (%d) ===" % len(real))
    seen = collections.Counter()
    for rva, ins, name in real:
        print("  rva=%-10s %-26s %s" % (hex(rva), ins, name))
        seen[name] += 1
    print("\n=== enclosing methods ===")
    for name, n in seen.most_common():
        print("  %-72s x%d" % (name, n))


if __name__ == "__main__":
    main()
