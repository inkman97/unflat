import random
from dataclasses import dataclass, field
from typing import Optional

from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_INVALID, X86_REG_RIP
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
    """An indirect jmp or call whose target is computed at runtime (a flattening dispatcher).

    kind is "jmp" (jmp reg), "jmpm" (jmp [mem]), "call" (call reg) or "callm" (call [mem]).
    `jmp` is the address of that instruction whatever its kind; `regs` are the registers that make up its target.
    For calls, call_mode says how the patch treats the return address: "discard" when every target throws it away
    as its first instruction (the call becomes a jmp past that instruction), "keep" otherwise (the patch pushes
    the same return address the original call would have pushed).
    """
    jmp: int
    size: int
    start: int
    reg: Optional[str]
    kind: str = "jmp"
    regs: frozenset = frozenset()
    cmov: Optional[int] = None
    cc: Optional[int] = None
    taken: Optional[int] = None
    fallthrough: Optional[int] = None
    opaque: bool = False
    patch: Optional[tuple] = None
    status: str = "unresolved"
    alternatives: list = field(default_factory=list)
    selector: Optional[tuple] = None
    call_mode: Optional[str] = None
    raw_targets: list = field(default_factory=list)

    @property
    def is_call(self):
        return self.kind.startswith("call")

    @property
    def ret(self):
        return self.jmp + self.size

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
            if mnem not in ("jmp", "call") or ops.startswith("0x"):
                continue
            if ops in CANON:
                if CANON[ops] != ops:
                    continue
                d = Dispatch(va, size, self.code.block_start(va), ops, mnem, frozenset({ops}))
            elif "ptr [" in ops:
                regs, slot = self.operand(va)
                if regs is None:
                    continue
                d = Dispatch(va, size, self.code.block_start(va), None, mnem + "m", regs)
                if slot is not None and (self._import_slot(slot) or not self._code_slot(slot)):
                    continue  # import thunk, ifunc stub, call through the IAT or GOT
                if self._fetched_index(d):
                    continue  # opcode fetched from data (VM / interpreter dispatch): see `unflat vm`
            else:
                continue
            if d.is_call and not self._call_candidate(d):
                continue
            found.append(d)
        return found

    def operand(self, va):
        """Registers that make up a memory operand, and the slot address when it is a fixed rip-relative one."""
        ins = self.code.insn(va)
        if ins is None or not ins.operands or ins.operands[0].type != X86_OP_MEM:
            return None, None
        mem = ins.operands[0].mem
        if ins.operands[0].size != 8 or mem.segment != X86_REG_INVALID:
            return None, None
        regs = {CANON[ins.reg_name(r)] for r in (mem.base, mem.index) if r not in (X86_REG_INVALID, X86_REG_RIP)}
        if mem.base == X86_REG_RIP and mem.index == X86_REG_INVALID:
            return frozenset(), va + ins.size + mem.disp
        if not regs and mem.base == X86_REG_INVALID:
            return frozenset(), mem.disp & 0xFFFFFFFFFFFFFFFF
        return frozenset(regs), None

    def _import_slot(self, slot):
        """Slots filled by the loader: IAT (PE), GOT and IRELATIVE slots (ELF). Their file value is not the target."""
        if slot in self.image.irelative:
            return True
        if self.image.fmt == "pe":
            iat = self.image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[12]
            lo = self.image.base + iat.VirtualAddress
            return iat.Size and lo <= slot < lo + iat.Size
        return any(s.name.startswith((".got", ".plt")) and s.start <= slot < s.end for s in self.image.sections)

    def _fetched_index(self, d):
        """True when the index of a `[base + index*scale]` dispatch is loaded from memory in the same block."""
        ins = self.code.insn(d.jmp)
        mem = ins.operands[0].mem
        if mem.index == X86_REG_INVALID:
            return False
        index = CANON[ins.reg_name(mem.index)]
        for va in reversed(self.code.span(d.start, d.jmp)[:-1]):
            if index in self.code.regs(va)[1]:
                load = self.code.insn(va)
                return any(op.type == X86_OP_MEM and op.mem.base not in (X86_REG_RIP, X86_REG_INVALID)
                           for op in load.operands[1:]) and load.mnemonic.startswith("mov")
        return False

    def _code_slot(self, slot):
        value = int.from_bytes(self.image.read(slot, 8), "little") if self.img_lo <= slot < self.img_hi else 0
        return value in self.code

    def _call_candidate(self, d):
        """An indirect call is a dispatcher only if a cmov/setCC picks its target, or (call reg) the register is
        loaded with a constant code address in the same block. Calls through function pointers are left alone."""
        span = self.code.span(d.start, d.jmp)
        if d.regs and self.selector_of(span, d.regs):
            return True
        if d.kind != "call":
            return False
        for va in reversed(span[:-1]):
            if d.reg in self.code.regs(va)[1]:
                value = self.code.constant_written(va, d.reg)
                return value is not None and value in self.code
        return False

    def resolve(self, d):
        span = self.code.span(d.start, d.jmp)
        calls = [a for a in span[:-1] if self.code.mnemonic(a) == "call"]
        start = self.code.after(calls[-1]) if calls else d.start
        span = self.code.span(start, d.jmp)
        cmov = self.selector_of(span, d.regs)
        live = self._live_in(span)
        consts = {r: self._constant(start, r) for r in live}
        variants = (True, False) if cmov else (None,)
        results = []
        for variant in variants:
            seen = {self._run(start, d, consts, cmov, variant, seed) for seed in (1, 2)}
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
        if d.is_call:
            self.call_mode(d)

    def call_mode(self, d):
        """Decide how a call dispatcher is patched (see Dispatch). Targets are moved past the discarding instruction."""
        d.raw_targets = [t for t in (d.taken, d.fallthrough) if t is not None]
        skips = [self.discard_skip(t) for t in d.raw_targets]
        if skips and all(s is not None for s in skips):
            d.call_mode = "discard"
            d.taken = skips[0]
            d.fallthrough = skips[1] if len(skips) > 1 else None
        else:
            d.call_mode = "keep"

    def discard_skip(self, target, window=24):
        """If the instruction at target throws the return address away with no other visible effect, return the
        address right after it; otherwise None.

        Accepted: `lea rsp, [rsp + 8]`; `add rsp, 8` when the flags it sets are overwritten before being read;
        `pop reg` when reg is overwritten before being read. Anything that can't be proven in a straight line of
        code is refused, and the call is patched in "keep" mode instead.
        """
        if target not in self.code:
            return None
        ins = self.code.insn(target)
        if ins is None:
            return None
        ops, nxt = ins.op_str.replace(" ", ""), target + ins.size
        if ins.mnemonic == "lea" and ops == "rsp,[rsp+8]":
            return nxt
        if ins.mnemonic == "add" and ops == "rsp,8":
            return nxt if self._flags_dead(nxt, window) else None
        if ins.mnemonic == "pop" and ops in CANON and CANON[ops] == ops and ops != "rsp":
            return nxt if self._reg_dead(nxt, ops, window) else None
        return None

    def _flags_dead(self, va, window):
        for _ in range(window):
            if va not in self.code:
                return False
            mnem = self.code.mnemonic(va)
            if mnem in FLAG_READERS or mnem.startswith(("j", "cmov", "set")) or mnem in ("call", "ret"):
                return False
            if mnem in FLAG_WRITERS:
                return True
            va = self.code.after(va)
        return False

    def _reg_dead(self, va, reg, window):
        for _ in range(window):
            if va not in self.code:
                return False
            mnem = self.code.mnemonic(va)
            if mnem.startswith("j") or mnem in ("call", "ret"):
                return False
            ins = self.code.insn(va)
            read, written = self.code.regs(va)
            ops = ins.operands
            zeroing = (mnem in ("xor", "sub") and len(ops) == 2 and ops[0].type == X86_OP_REG
                       and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg)
            if reg in read and not zeroing:
                return False
            if reg in written:
                dest = ins.reg_name(ins.operands[0].reg) if ins.operands and ins.operands[0].type == X86_OP_REG else ""
                return dest in (reg, FULL32.get(reg))  # 64-bit write or zero-extending 32-bit write
            va = self.code.after(va)
        return False

    def selector_of(self, span, regs):
        needed = {regs} if isinstance(regs, str) else set(regs)
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
                return self.selector_of(self.code.span(d.start, d.jmp), d.regs) is None
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

    def _run(self, start, d, consts, cmov, variant, seed):
        end = d.jmp
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
            target = read_target(self.uc, self.code, d) if ok else None
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


FLAG_WRITERS = {"cmp", "test", "add", "sub", "and", "or", "xor", "neg"}
FLAG_READERS = {"adc", "sbb", "pushfq", "pushf", "lahf", "rcl", "rcr", "cmc", "into"}
FULL32 = {"rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx", "rsi": "esi", "rdi": "edi", "rbp": "ebp",
          **{f"r{i}": f"r{i}d" for i in range(8, 16)}}


def read_target(uc, code, d):
    """The address the dispatch instruction at d.jmp would transfer control to, given the current emulator state."""
    if d.reg is not None:
        return uc.reg_read(UC_REG[d.reg])
    ins = code.insn(d.jmp)
    mem = ins.operands[0].mem
    if mem.base == X86_REG_RIP:
        addr = d.jmp + ins.size
    elif mem.base != X86_REG_INVALID:
        addr = uc.reg_read(UC_REG[CANON[ins.reg_name(mem.base)]])
    else:
        addr = 0
    if mem.index != X86_REG_INVALID:
        addr += uc.reg_read(UC_REG[CANON[ins.reg_name(mem.index)]]) * mem.scale
    addr = (addr + mem.disp) & 0xFFFFFFFFFFFFFFFF
    try:
        return int.from_bytes(uc.mem_read(addr, 8), "little")
    except UcError:
        return None


def apply_force(uc, force, next_va):
    _, taken, dst, src = force
    if src is None:
        value = uc.reg_read(UC_REG[dst])
        uc.reg_write(UC_REG[dst], (value & ~0xFF) | int(bool(taken)))
    elif taken:
        uc.reg_write(UC_REG[dst], uc.reg_read(UC_REG[src]))
    uc.reg_write(X.UC_X86_REG_RIP, next_va)
