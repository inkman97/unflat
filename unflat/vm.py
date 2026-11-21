from collections import Counter, defaultdict
from dataclasses import dataclass, field

from capstone.x86 import X86_OP_IMM
from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_READ,
                     UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_WRITE_UNMAPPED, UC_MODE_64, Uc, UcError)
from unicorn import x86_const as X

from .abi import ARGS, setup_imports, setup_tls

M64 = (1 << 64) - 1
PAGE = 0x1000
STACK, STACK_SIZE = 0x7FF000000, 0x400000
RETURN = 0xDEAD0000
ALU = {"add", "sub", "xor", "and", "or", "imul", "mul", "shl", "shr", "sar", "rol", "ror", "not", "neg", "inc", "dec"}
NATIVE = {"add": "add", "lea": "add", "inc": "add", "sub": "sub", "dec": "sub", "neg": "sub", "xor": "xor",
          "and": "and", "or": "or", "imul": "mul", "mul": "mul", "shl": "shl", "sal": "shl", "shr": "shr", "sar": "shr",
          "pxor": "xor", "xorps": "xor", "vpxor": "xor", "paddq": "add", "psubq": "sub", "pand": "and", "por": "or"}
OPS = {
    "add": lambda a, b: (a + b) & M64, "sub": lambda a, b: (a - b) & M64, "xor": lambda a, b: a ^ b,
    "and": lambda a, b: a & b, "or": lambda a, b: a | b, "mul": lambda a, b: (a * b) & M64,
    "shl": lambda a, b: (a << (b & 63)) & M64, "shr": lambda a, b: a >> (b & 63),
}


@dataclass
class Handler:
    address: int
    hits: int = 0
    body: list = field(default_factory=list)
    kinds: Counter = field(default_factory=Counter)

    @property
    def kind(self):
        return self.kinds.most_common(1)[0][0] if self.kinds else "?"


@dataclass
class VInsn:
    index: int
    vip: int
    opcode: int
    handler: int
    operands: bytes
    kind: str
    detail: str


class Tracer:
    def __init__(self, image, code, max_insns=2_000_000):
        self.image, self.code, self.max = image, code, max_insns
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        size = (image.size + PAGE - 1) & ~(PAGE - 1)
        self.uc.mem_map(image.base, size)
        self.uc.mem_write(image.base, bytes(image.mapped))
        self.uc.mem_map(STACK, STACK_SIZE)
        setup_tls(self.uc, image.abi, self_pointer=True)
        setup_imports(self.uc, image, STACK + STACK_SIZE // 2)
        self.trace, self.mem = [], []
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._write)
        self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._fetch_unmapped)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self._data_unmapped)

    def _code(self, uc, addr, size, _):
        self.trace.append(addr)
        if len(self.trace) >= self.max:
            uc.emu_stop()

    def _read(self, uc, access, addr, size, value, _):
        data = bytes(uc.mem_read(addr, size))
        for off in range(0, size, 8):
            chunk = data[off:off + 8]
            self.mem.append((len(self.trace) - 1, "r", addr + off, len(chunk), int.from_bytes(chunk, "little")))

    def _write(self, uc, access, addr, size, value, _):
        self.mem.append((len(self.trace) - 1, "w", addr, size, value & ((1 << (8 * size)) - 1)))

    def _fetch_unmapped(self, uc, access, addr, size, value, _):
        try:
            uc.mem_map(addr & ~(PAGE - 1), PAGE)
            uc.mem_write(addr, b"\xC3")
            return True
        except UcError:
            return False

    def _data_unmapped(self, uc, access, addr, size, value, _):
        try:
            uc.mem_map(addr & ~(PAGE - 1), PAGE)
            return True
        except UcError:
            return False

    def run(self, entry, args=()):
        sp = STACK + STACK_SIZE // 2
        sp -= 8
        self.uc.mem_write(sp, RETURN.to_bytes(8, "little"))
        self.uc.reg_write(X.UC_X86_REG_RSP, sp)
        for reg, value in zip(ARGS[self.image.abi], args):
            self.uc.reg_write(getattr(X, f"UC_X86_REG_{reg.upper()}"), value)
        try:
            self.uc.emu_start(entry, RETURN)
            self.error = None
        except UcError as e:
            self.error = str(e)
        self.result = self.uc.reg_read(X.UC_X86_REG_RAX)
        return self


class VMAnalysis:
    def __init__(self, tracer, min_targets=2):
        self.t, self.code = tracer, tracer.code
        self.sites = defaultdict(Counter)
        for i in range(len(self.t.trace) - 1):
            va = self.t.trace[i]
            if va in self.code and self._indirect(va):
                self.sites[va][self.t.trace[i + 1]] += 1
        multi = {s for s, tg in self.sites.items() if len(tg) >= min_targets}
        self.handler_set = set().union(*(set(self.sites[s]) for s in multi)) if multi else set()
        self.dispatch_sites = {s for s, tg in self.sites.items() if set(tg) <= self.handler_set and self.handler_set}
        lo, hi = tracer.image.base, tracer.image.base + tracer.image.size
        self.is_pointer = lambda v: lo <= v < hi
        self.handlers = {h: Handler(h) for h in self.handler_set}
        self.insns = self._split()

    def _indirect(self, va):
        mnem = self.code.mnemonic(va)
        if mnem not in ("jmp", "call"):
            return False
        ins = self.code.insn(va)
        return bool(ins.operands) and ins.operands[0].type != X86_OP_IMM

    def _split(self):
        trace, starts = self.t.trace, []
        for i in range(1, len(trace)):
            if trace[i - 1] in self.dispatch_sites and trace[i] in self.handler_set:
                starts.append(i)
        mem_by_step = defaultdict(list)
        for step, kind, addr, size, value in self.t.mem:
            mem_by_step[step].append((kind, addr, size, value))
        fetches = [self._fetch(s, starts[n - 1] if n else 0, mem_by_step) for n, s in enumerate(starts)]
        known = [f for f in fetches if f]
        lo = min((f[0] for f in known), default=0) - 16
        hi = max((f[0] for f in known), default=0) + 16
        out = []
        for n, s in enumerate(starts):
            end = starts[n + 1] if n + 1 < len(starts) else len(trace)
            h = self.handlers[trace[s]]
            h.hits += 1
            if not h.body:
                h.body = trace[s:end]
            vip, opcode = fetches[n] or (None, None)
            events = [e for step in range(s, end) for e in mem_by_step.get(step, [])]
            nxt = fetches[n + 1] if n + 1 < len(fetches) else None
            reads = [(addr, size, value) for kind, addr, size, value in events
                     if kind == "r" and lo <= addr < hi and size <= 4 and (not nxt or addr != nxt[0])]
            operand = bytes(b for addr, size, value in reads for b in value.to_bytes(size, "little"))
            if vip is None and reads:
                vip = min(a for a, _, _ in reads) - 1
            native = {NATIVE[self.code.mnemonic(va)] for va in trace[s:end] if va in self.code and self.code.mnemonic(va) in NATIVE}
            kind, detail = self._semantics(events, operand, vip, nxt, lo, hi, end == len(trace), native)
            h.kinds[kind] += 1
            out.append(VInsn(n, vip, opcode, h.address, operand, kind, detail))
        vips = [v.vip for v in out if v.vip is not None]
        self.bytecode = (min(vips), max(vips)) if vips else None
        return out

    def _fetch(self, start, previous, mem_by_step):
        for step in range(start - 1, previous - 1, -1):
            reads = [e for e in mem_by_step.get(step, []) if e[0] == "r" and e[2] <= 2]
            if reads:
                return reads[-1][1], reads[-1][3]
        return None

    def _semantics(self, events, operand, vip, nxt, lo, hi, last, native):
        if last:
            return "exit", f"returns {self.t.result:#x}"
        data_reads = [v for k, a, s, v in events if k == "r" and not lo <= a < hi and s >= 4 and not self.is_pointer(v)]
        writes = [(a, v) for k, a, s, v in events if k == "w" and s >= 4 and not self.is_pointer(v)]
        if vip is not None and nxt is not None:
            expected = vip + 1 + len(operand)
            if nxt[0] != expected:
                return "branch", f"vip {vip:#x} -> {nxt[0]:#x}"
        imm = int.from_bytes(operand, "little") if operand else None
        found = {}
        for a, w in writes:
            for name, fn in OPS.items():
                if name not in native or "alu" in found:
                    continue
                for x in data_reads:
                    for y in data_reads:
                        if x != y and fn(x, y) == w and w not in (x, y):
                            found["alu"] = (name, f"{x:#x} {name} {y:#x} = {w:#x}")
            if imm is not None and w == imm and len(operand) >= 2:
                found.setdefault("const", ("push-const", f"const {w:#x}"))
            if w in data_reads:
                found.setdefault("move", ("move", f"value {w:#x}" + (f" index {operand[0]}" if operand else "")))
        for key in ("alu", "const", "move"):
            if key in found:
                return found[key]
        return "other", ""


def report(analysis, out):
    a = analysis
    out.write(f"emulated instructions: {len(a.t.trace)}  result rax: {a.t.result:#x}"
              f"{'  stopped: ' + a.t.error if a.t.error else ''}\n")
    if not a.dispatch_sites:
        out.write("no dispatcher found (no indirect jump/call with several targets)\n")
        return
    out.write("dispatch sites: " + ", ".join(f"{s:#x}" for s in sorted(a.dispatch_sites)) + "\n")
    if a.bytecode:
        out.write(f"bytecode: {a.bytecode[0]:#x} .. {a.bytecode[1]:#x}\n")
    names = {h: f"H{i:02d}" for i, h in enumerate(sorted(a.handlers))}
    out.write(f"\nhandlers ({len(a.handlers)}):\n")
    for h in sorted(a.handlers.values(), key=lambda x: x.address):
        alu = sorted({a.code.mnemonic(v) for v in h.body if v in a.code and a.code.mnemonic(v) in ALU})
        out.write(f"  {names[h.address]}  {h.address:#x}  hits {h.hits:<6} {h.kind:<11} alu: {' '.join(alu) or '-'}\n")
    out.write("\nvirtual program (first execution of each vip):\n")
    seen = set()
    for v in a.insns:
        if v.vip in seen:
            continue
        seen.add(v.vip)
        off = f"+{v.vip - a.bytecode[0]:04x}" if v.vip is not None and a.bytecode else "?"
        opc = f"{v.opcode:02x}" if v.opcode is not None else "??"
        out.write(f"  {off}  op {opc}  {names[v.handler]}  {a.handlers[v.handler].kind:<11} {v.operands.hex() or '-':<10} {v.detail}\n")
    out.write(f"\nexecution trace ({len(a.insns)} virtual instructions):\n")
    for v in a.insns:
        off = f"+{v.vip - a.bytecode[0]:04x}" if v.vip is not None and a.bytecode else "?"
        out.write(f"  {v.index:>6}  {off}  {names[v.handler]}  {v.kind:<11} {v.detail}\n")
