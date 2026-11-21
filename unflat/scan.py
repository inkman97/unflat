import bisect
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from .code import CANON

PROTECTORS = {
    ".vmp": "VMProtect", ".themida": "Themida", ".winlice": "WinLicense", ".enigma": "Enigma Protector",
    ".tvm": "Tiger VM", "upx": "UPX (packer)", ".aspack": "ASPack (packer)", ".mpress": "MPRESS (packer)",
    ".obsidiu": "Obsidium", ".svmp": "VMProtect (stub)",
}
RIP = re.compile(r"\[rip ([+-]) (0x[0-9a-f]+)\]")
TABLE_JUMP = re.compile(r"qword ptr \[(\w+) \+ (\w+)\*8(?: [+-] 0x[0-9a-f]+)?\]")
INDEX8 = re.compile(r"\+ (\w+)\*8")
BYTE_FETCH = re.compile(r"byte ptr \[(\w+)(?: [+-] [^\]]+)?\]")
SELECT = ("cmov", "set")


@dataclass
class FunctionScore:
    start: int
    end: int
    insns: int = 0
    jmp_reg: int = 0
    selected: int = 0
    opaque: int = 0
    fetch_dispatch: int = 0
    tables: list = field(default_factory=list)

    @property
    def flattened(self):
        return self.selected >= 5 and self.selected * 2 >= self.jmp_reg

    @property
    def vm(self):
        return self.fetch_dispatch >= 1 and (any(n >= 4 for _, n in self.tables) or self.fetch_dispatch >= 3)


def _entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum(c / len(data) * math.log2(c / len(data)) for c in counts.values())


def code_pointer_tables(image, min_entries=4):
    tables = []
    for sec in image.sections:
        if sec.executable:
            continue
        data = image.read(sec.start, sec.end - sec.start)
        run_start, run = None, 0
        for off in range(0, len(data) - 7, 8):
            value = int.from_bytes(data[off:off + 8], "little")
            if image.is_code(value):
                if run == 0:
                    run_start = sec.start + off
                run += 1
                continue
            if run >= min_entries:
                tables.append((run_start, run))
            run = 0
        if run >= min_entries:
            tables.append((run_start, run))
    return tables


def scan(image, code):
    tables = code_pointer_tables(image)
    table_starts = sorted(t[0] for t in tables)
    by_start = dict(tables)
    results = []
    for start, end in image.functions:
        i, j = bisect.bisect_left(code.addrs, start), bisect.bisect_left(code.addrs, end)
        addrs = code.addrs[i:j]
        f = FunctionScore(start, end, len(addrs))
        refs = set()
        for k, va in enumerate(addrs):
            size, mnem, ops = code.lite[va]
            m = RIP.search(ops)
            if m:
                target = va + size + int(m.group(2), 16) * (1 if m.group(1) == "+" else -1)
                t = bisect.bisect_right(table_starts, target) - 1
                if t >= 0 and table_starts[t] <= target < table_starts[t] + 8 * by_start[table_starts[t]]:
                    refs.add(table_starts[t])
            if mnem == "ud2":
                f.opaque += 1
            indirect = (mnem in ("jmp", "call") and (CANON.get(ops) == ops or TABLE_JUMP.search(ops)))
            if not indirect:
                continue
            back = addrs[max(0, k - 10):k]
            if mnem == "jmp" and CANON.get(ops) == ops:
                f.jmp_reg += 1
                if any(code.lite[b][1].startswith(SELECT) for b in back):
                    f.selected += 1
            window = back + [va]
            for n, b in enumerate(window):
                bm, bo = code.lite[b][1], code.lite[b][2]
                fetch = BYTE_FETCH.search(bo) if bm in ("movzx", "movsx") else None
                if not fetch or fetch.group(1) in ("rsp", "rbp", "rip"):
                    continue
                dest = CANON.get(bo.split(",")[0].strip())
                if any(CANON.get(x) == dest for later in window[n + 1:] for x in INDEX8.findall(code.lite[later][2])):
                    f.fetch_dispatch += 1
                    break
        f.tables = [(t, by_start[t]) for t in sorted(refs)]
        results.append(f)
    return results


def sections_report(image):
    rows, hints = [], set()
    for s in image.sections:
        data = image.section_data(s)
        rows.append((s.name, s.start, s.end - s.start, _entropy(data), s.executable))
        low = s.name.lower()
        for key, name in PROTECTORS.items():
            if low.startswith(key):
                hints.add(name)
        if s.executable and _entropy(data) > 7.2:
            hints.add(f"high entropy executable section {s.name} (packed or encrypted code)")
    return rows, sorted(hints)


def report(image, code, results, out, verbose=False):
    rows, hints = sections_report(image)
    flat = sorted((f for f in results if f.flattened), key=lambda f: -f.selected)
    vms = sorted((f for f in results if f.vm), key=lambda f: -f.fetch_dispatch)
    out.write(f"{image.path}: {len(code.addrs)} instructions, {len(results)} functions\n\nsections:\n")
    for name, start, size, ent, ex in rows:
        out.write(f"  {name:<10} {start:#x}  {size:#9x}  entropy {ent:4.2f}{'  exec' if ex else ''}\n")
    out.write("\nhints: " + ("; ".join(hints) if hints else "none") + "\n")
    verdict = []
    if flat:
        verdict.append(f"control-flow flattening in {len(flat)} function(s)")
    if vms:
        verdict.append(f"bytecode VM suspected in {len(vms)} function(s)")
    out.write("verdict: " + ("; ".join(verdict) if verdict else "no flattening or VM dispatcher found") + "\n")
    if flat:
        out.write(f"\nflattened functions ({len(flat)}), by selected dispatchers:\n")
        for f in flat[: None if verbose else 15]:
            out.write(f"  {f.start:#x}  {f.insns:>6} insns  jmp-reg {f.jmp_reg:<4} selected {f.selected:<4} ud2 {f.opaque:<3}"
                      f"  -> unflat flat -f {f.start:#x} -l out.txt\n")
        if not verbose and len(flat) > 15:
            out.write(f"  ... {len(flat) - 15} more (use -v)\n")
        out.write("  patch all: unflat flat <file> -o <file>.unflat\n")
    if vms:
        out.write(f"\nVM candidates ({len(vms)}):\n")
        for f in vms:
            tabs = ", ".join(f"{t:#x} ({n} entries)" for t, n in f.tables) or "none referenced"
            out.write(f"  {f.start:#x}  {f.insns:>6} insns  fetch+dispatch sites {f.fetch_dispatch:<3} handler tables: {tabs}"
                      f"  -> unflat vm -e {f.start:#x}\n")
    if verbose:
        out.write("\nall functions with indirect jumps:\n")
        for f in results:
            if f.jmp_reg or f.fetch_dispatch:
                out.write(f"  {f.start:#x}  insns {f.insns:<6} jmp-reg {f.jmp_reg:<4} selected {f.selected:<4}"
                          f" fetch+dispatch {f.fetch_dispatch:<3} tables {len(f.tables)}\n")
