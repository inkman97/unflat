from functools import lru_cache

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

TERMINATORS = {"jmp", "ret", "retf", "ud2", "int3", "hlt", ".byte"}

_GPR = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"] + [f"r{i}" for i in range(8, 16)]
_ALIAS = {
    "rax": "eax ax al ah", "rbx": "ebx bx bl bh", "rcx": "ecx cx cl ch", "rdx": "edx dx dl dh",
    "rsi": "esi si sil", "rdi": "edi di dil", "rbp": "ebp bp bpl", "rsp": "esp sp spl",
}
CANON = {r: r for r in _GPR}
for full, names in _ALIAS.items():
    CANON.update({n: full for n in names.split()})
for i in range(8, 16):
    CANON.update({f"r{i}d": f"r{i}", f"r{i}w": f"r{i}", f"r{i}b": f"r{i}"})


class Code:
    def __init__(self, image):
        self.image = image
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        lite = Cs(CS_ARCH_X86, CS_MODE_64)
        lite.skipdata = True
        self.addrs, self.lite = [], {}
        for sec in image.code_sections():
            data = image.read(sec.start, sec.end - sec.start)
            for addr, size, mnem, ops in lite.disasm_lite(data, sec.start):
                self.addrs.append(addr)
                self.lite[addr] = (size, mnem, ops)
        self.index = {a: i for i, a in enumerate(self.addrs)}

    def __contains__(self, va):
        return va in self.lite

    @lru_cache(maxsize=65536)
    def insn(self, va):
        size = self.lite[va][0]
        return next(self.md.disasm(self.image.read(va, size), va), None)

    def mnemonic(self, va):
        return self.lite[va][1]

    def after(self, va):
        return va + self.lite[va][0]

    def before(self, va, count):
        i = self.index[va]
        return self.addrs[max(0, i - count):i][::-1]

    def block_start(self, va, limit=256):
        start = va
        for prev in self.before(va, limit):
            if self.mnemonic(prev) in TERMINATORS or self.mnemonic(prev).startswith("j"):
                break
            start = prev
        return start

    def span(self, start, end):
        i, j = self.index[start], self.index[end]
        return self.addrs[i:j + 1]

    def regs(self, va):
        ins = self.insn(va)
        read, written = ins.regs_access()
        canon = lambda ids: {CANON[n] for n in (ins.reg_name(r) for r in ids) if n in CANON}
        return canon(read), canon(written)

    def constant_written(self, va, reg):
        ins = self.insn(va)
        if not ins.operands or ins.operands[0].type != X86_OP_REG or CANON.get(ins.reg_name(ins.operands[0].reg)) != reg:
            return None
        if ins.mnemonic == "lea" and ins.operands[1].type == X86_OP_MEM and ins.operands[1].mem.base == X86_REG_RIP:
            return ins.address + ins.size + ins.operands[1].mem.disp
        if ins.mnemonic in ("mov", "movabs") and ins.operands[1].type == X86_OP_IMM:
            return ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF
        if ins.mnemonic == "xor" and ins.operands[1].type == X86_OP_REG and ins.operands[0].reg == ins.operands[1].reg:
            return 0
        return None


def discover_functions(image, code):
    starts = set()
    entry = image.pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if entry:
        starts.add(image.base + entry)
    for exp in getattr(getattr(image.pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
        starts.add(image.base + exp.address)
    for va in code.addrs:
        size, mnem, ops = code.lite[va]
        if mnem == "call" and ops.startswith("0x"):
            starts.add(int(ops, 16))
    starts = sorted(s for s in starts if s in code)
    ends = [s.end for s in image.code_sections()]
    return [(a, b) for a, b in zip(starts, starts[1:] + [max(ends)])]
