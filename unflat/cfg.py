from capstone.x86 import X86_OP_IMM

STOP = {"ret", "retf", "ud2", "int3", "hlt", ".byte"}
CC = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"]


def _direct_target(code, va):
    ins = code.insn(va)
    if ins and ins.operands and ins.operands[0].type == X86_OP_IMM:
        return ins.operands[0].imm
    return None


def walk(code, entry, edges, bounds=None):
    """Recursive descent from entry. edges maps a dispatcher jmp address to its resolved targets."""
    seen, blocks, todo = set(), {}, [entry]
    inside = (lambda va: bounds[0] <= va < bounds[1]) if bounds else (lambda va: True)
    while todo:
        start = todo.pop()
        if start in blocks or start not in code or not inside(start):
            continue
        va, insns, succ = start, [], []
        while va in code and va not in seen:
            seen.add(va)
            insns.append(va)
            mnem = code.mnemonic(va)
            if mnem in STOP:
                break
            if mnem == "jmp":
                succ = list(edges.get(va, [])) or [t for t in [_direct_target(code, va)] if t is not None]
                break
            if mnem.startswith("j"):
                succ = [t for t in [_direct_target(code, va)] if t is not None] + [code.after(va)]
                break
            va = code.after(va)
            if va in blocks:
                succ = [va]
                break
        if insns:
            blocks[start] = (insns, succ)
            todo.extend(succ)
    return blocks


def coverage(code, functions, edges):
    total = 0
    for start, end in functions:
        total += sum(len(b[0]) for b in walk(code, start, edges, (start, end)).values())
    return total


def listing(code, blocks, dispatch_by_jmp, out):
    for start in sorted(blocks):
        insns, succ = blocks[start]
        out.write(f"\nloc_{start:x}:\n")
        for va in insns:
            size, mnem, ops = code.lite[va]
            d = dispatch_by_jmp.get(va)
            if d and d.status == "cond":
                out.write(f"  {va:016x}  {mnem} {ops:<24} ; if {CC[d.cc]} -> loc_{d.taken:x} else loc_{d.fallthrough:x}\n")
            elif d and d.status == "goto":
                note = " (opaque predicate removed)" if d.opaque else ""
                out.write(f"  {va:016x}  {mnem} {ops:<24} ; goto loc_{d.taken:x}{note}\n")
            elif d and d.status == "context":
                alts = ", ".join(f"loc_{t:x}" for t in d.targets)
                out.write(f"  {va:016x}  {mnem} {ops:<24} ; depends on the incoming path: {alts}\n")
            elif d:
                out.write(f"  {va:016x}  {mnem} {ops:<24} ; {d.status} dispatcher\n")
            else:
                out.write(f"  {va:016x}  {mnem} {ops}\n")


def dot(blocks, dispatch_by_jmp, out, name="cfg"):
    out.write(f"digraph {name} {{\n  node [shape=box fontname=monospace];\n")
    for start, (insns, succ) in sorted(blocks.items()):
        out.write(f'  n{start:x} [label="{start:x}\\n{len(insns)} insns"];\n')
        d = dispatch_by_jmp.get(insns[-1])
        for i, t in enumerate(succ):
            style = ' [color=green]' if d and d.status == "cond" and i == 0 else ""
            out.write(f"  n{start:x} -> n{t:x}{style};\n")
    out.write("}\n")
