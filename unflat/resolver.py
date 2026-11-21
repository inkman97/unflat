import random
from dataclasses import dataclass, field
from typing import Optional

from capstone.x86 import X86_OP_MEM, X86_OP_REG
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE, UC_MODE_64, Uc, UcError
from unicorn import x86_const as X

from .abi import setup_imports, setup_tls
from .code import CANON

UC_REG = {r: getattr(X, f"UC_X86_REG_{r.upper()}") for r in sorted(set(CANON.values()))}
STACK, STACK_SIZE = 0x7FF000000, 0x200000
SCRATCH, SCRATCH_SIZE = 0x10000000, 0x2000000
PAGE = 0x1000


@dataclass
class Dispatch:
    jmp: int
    size: int
    start: int
    reg: str
    cmov: Optional[int] = None
    cc: Optional[int] = None
    taken: Optional[int] = None
    fallthrough: Optional[int] = None
    opaque: bool = False
    patch: Optional[tuple] = None
    status: str = "unresolved"
    alternatives: list = field(default_factory=list)
    selector: Optional[tuple] = None

    @property
    def targets(self):
        if self.status == "context":
            return self.alternatives
        return [t for t in (self.taken, self.fallthrough) if t is not None]


class Resolver:
    def __init__(self, image, code, backward_limit=4000):
        self.image, self.code, self.limit = image, code, backward_limit
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        size = (image.size + PAGE - 1) & ~(PAGE - 1)
        self.uc.mem_map(image.base, size)
        self.uc.mem_write(image.base, bytes(image.mapped))
        self.img_lo, self.img_hi = image.base, image.base + size
        for base, sz in ((STACK, STACK_SIZE), (SCRATCH, SCRATCH_SIZE)):
            self.uc.mem_map(base, sz)
        setup_tls(self.uc, image.abi)
        setup_imports(self.uc, image, STACK + STACK_SIZE // 2)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._map_page)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._log_write)
        self.writes, self.force = [], None
        self.uc.hook_add(UC_HOOK_CODE, self._on_code)

    def _map_page(self, uc, access, addr, size, value, _):
        try:
            uc.mem_map(addr & ~(PAGE - 1), PAGE)
            return True
        except UcError:
            return False

    def _log_write(self, uc, access, addr, size, value, _):
        if self.img_lo <= addr < self.img_hi:
            self.writes.append((addr, bytes(uc.mem_read(addr, size))))

    def _on_code(self, uc, addr, size, _):
        if self.force is not None and addr == self.force[0]:
            apply_force(uc, self.force, addr + size)

    def find(self):
        found = []
        for va in self.code.addrs:
            size, mnem, ops = self.code.lite[va]
            if mnem == "jmp" and ops in CANON and CANON[ops] == ops:
                found.append(Dispatch(va, size, self.code.block_start(va), ops))
        return found

    def resolve(self, d):
        span = self.code.span(d.start, d.jmp)
        calls = [a for a in span if self.code.mnemonic(a) == "call"]
        start = self.code.after(calls[-1]) if calls else d.start
        span = self.code.span(start, d.jmp)
        cmov = self.selector_of(span, d.reg)
        live = self._live_in(span)
        consts = {r: self._constant(start, r) for r in live}
        variants = (True, False) if cmov else (None,)
        results = []
        for variant in variants:
            seen = {self._run(start, d.jmp, d.reg, consts, cmov, variant, seed) for seed in (1, 2)}
            if len(seen) != 1 or None in seen:
                return d
            results.append(seen.pop())
        if not all(t in self.code for t in results):
            return d
        d.taken = results[0]
        d.fallthrough = results[1] if cmov else None
        if cmov:
            d.cmov, d.cc = cmov[0], self.condition_code(cmov[0])
        self.classify(d)
        return d

    def classify(self, d):
        dead = [t for t in d.targets if self.code.mnemonic(t) in ("ud2", "int3")]
        live = [t for t in d.targets if t not in dead]
        if d.cmov is None or d.taken == d.fallthrough:
            d.status, d.fallthrough = "goto", None
        elif dead and live:
            d.status, d.opaque, d.taken, d.fallthrough = "goto", True, live[0], None
        else:
            d.status = "cond"

    def selector_of(self, span, reg):
        needed = {reg}
        for va in reversed(span[:-1]):
            read, written = self.code.regs(va)
            if not written & needed:
                continue
            ins = self.code.insn(va)
            ops = ins.operands
            if ins.mnemonic.startswith("cmov"):
                if len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
                    return va, CANON[ins.reg_name(ops[0].reg)], CANON[ins.reg_name(ops[1].reg)]
                return None
            if ins.mnemonic.startswith("set") and ops and ops[0].type == X86_OP_REG:
                return va, CANON[ins.reg_name(ops[0].reg)], None
            needed = (needed - written) | (read - {"rsp"})
        return None

    def is_switch(self, d):
        for va in self.code.span(d.start, d.jmp):
            ins = self.code.insn(va)
            if any(op.type == X86_OP_MEM and op.mem.index and op.mem.scale in (4, 8) for op in ins.operands):
                return self.selector_of(self.code.span(d.start, d.jmp), d.reg) is None
        return False

    def _live_in(self, span):
        live, written = set(), set()
        for va in span:
            read, wr = self.code.regs(va)
            live |= read - written
            written |= wr
        return live - {"rsp", "rip"}

    def _constant(self, start, reg):
        fn = self.image.function_of(start)
        for va in self.code.before(start, self.limit):
            if fn and va < fn[0]:
                break
            if reg in self.code.regs(va)[1]:
                return self.code.constant_written(va, reg)
        return None

    def _run(self, start, end, reg, consts, cmov, variant, seed):
        rng = random.Random(seed)
        for name, uc_reg in UC_REG.items():
            value = consts.get(name)
            if value is None:
                value = SCRATCH + rng.randrange(0x100000, SCRATCH_SIZE - 0x100000) & ~7
            self.uc.reg_write(uc_reg, value)
        self.uc.reg_write(X.UC_X86_REG_RSP, STACK + STACK_SIZE // 2)
        self.uc.reg_write(X.UC_X86_REG_EFLAGS, 0x202)
        self.force = (cmov[0], variant, cmov[1], cmov[2]) if cmov else None
        self.writes = []
        try:
            self.uc.emu_start(start, end, count=2000)
            ok = self.uc.reg_read(X.UC_X86_REG_RIP) == end
            target = self.uc.reg_read(UC_REG[reg]) if ok else None
        except UcError:
            target = None
        for addr, old in reversed(self.writes):
            self.uc.mem_write(addr, old)
        self.force = None
        return target

    def condition_code(self, va):
        raw = self.image.read(va, self.code.lite[va][0])
        i = raw.index(0x0F)
        return raw[i + 1] & 0x0F


def apply_force(uc, force, next_va):
    _, taken, dst, src = force
    if src is None:
        value = uc.reg_read(UC_REG[dst])
        uc.reg_write(UC_REG[dst], (value & ~0xFF) | int(bool(taken)))
    elif taken:
        uc.reg_write(UC_REG[dst], uc.reg_read(UC_REG[src]))
    uc.reg_write(X.UC_X86_REG_RIP, next_va)
