import random
from collections import defaultdict

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UcError
from unicorn import x86_const as X

from .abi import VOLATILE
from .resolver import SCRATCH, SCRATCH_SIZE, STACK, STACK_SIZE, UC_REG, apply_force

STACK_TOP = STACK + STACK_SIZE // 2
SEEDS = (11, 23)


class Explorer:
    """Follows paths from a function entry, carrying known register and stack values between blocks."""

    def __init__(self, resolver, max_states_per_block=16, max_steps=20000):
        self.r, self.code, self.uc = resolver, resolver.code, resolver.uc
        self.max_states, self.max_steps = max_states_per_block, max_steps
        self.dispatch = {}
        self.stops = set()
        for va in self.code.addrs:
            mnem = self.code.mnemonic(va)
            if mnem.startswith("j") and mnem != "jmp" or mnem in ("ret", "ud2", "int3", "hlt"):
                self.stops.add(va)
        self.results = defaultdict(lambda: defaultdict(set))
        self.dirty = set()
        self.uc.hook_add(UC_HOOK_CODE, self._step)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._stack_write)

    def register(self, dispatches):
        for d in dispatches:
            self.dispatch[d.jmp] = d
            self.stops.add(d.jmp)
            d.selector = self.r.selector_of(self.code.span(d.start, d.jmp), d.reg)

    def _step(self, uc, addr, size, _):
        if not self.active:
            return
        if addr != self.entry and addr in self.stops:
            self.stop_at = addr
            uc.emu_stop()
            return
        if self.force and addr == self.force[0]:
            apply_force(uc, self.force, addr + size)
            return
        if addr in self.code and self.code.mnemonic(addr) == "call":
            for reg in VOLATILE[self.r.image.abi]:
                uc.reg_write(UC_REG[reg], self._unknown())
            uc.reg_write(X.UC_X86_REG_RIP, addr + size)

    def _stack_write(self, uc, access, addr, size, value, _):
        if self.active and STACK <= addr < STACK + STACK_SIZE:
            self.stack_log.append((addr, size, value & ((1 << (8 * size)) - 1)))

    def _unknown(self):
        return SCRATCH + self.rng.randrange(0x100000, SCRATCH_SIZE - 0x100000) & ~7

    def _run(self, start, regs, stack, seed, force):
        self.rng = random.Random(seed)
        for name, uc_reg in UC_REG.items():
            self.uc.reg_write(uc_reg, regs.get(name, self._unknown()))
        if "rsp" not in regs:
            self.uc.reg_write(X.UC_X86_REG_RSP, STACK_TOP)
        self.uc.reg_write(X.UC_X86_REG_EFLAGS, 0x202)
        for addr in self.dirty:
            self.uc.mem_write(addr, bytes(8))
        self.dirty = set(stack)
        for addr, value in stack.items():
            self.uc.mem_write(addr, value.to_bytes(8, "little"))
        self.entry, self.force, self.stop_at, self.stack_log, self.active = start, force, None, [], True
        self.r.writes = []
        try:
            self.uc.emu_start(start, 0, count=3000)
        except UcError:
            self.stop_at = None
        self.active = False
        out_regs = {name: self.uc.reg_read(uc_reg) for name, uc_reg in UC_REG.items()}
        out_stack = {}
        for addr, size, value in self.stack_log:
            for base in {addr & ~7, (addr + size - 1) & ~7}:
                out_stack[base] = int.from_bytes(self.uc.mem_read(base, 8), "little")
                self.dirty.add(base)
        for addr, old in reversed(self.r.writes):
            self.uc.mem_write(addr, old)
        return self.stop_at, out_regs, {**stack, **out_stack}

    def _known(self, a, b):
        return {k: v for k, v in a.items() if b.get(k) == v and not SCRATCH <= v < SCRATCH + SCRATCH_SIZE}

    def explore(self, entry, bounds=None):
        todo, seen, count, steps = [(entry, {"rsp": STACK_TOP}, {})], set(), defaultdict(int), 0
        while todo and steps < self.max_steps:
            start, regs, stack = todo.pop()
            if bounds and not bounds[0] <= start < bounds[1]:
                continue
            sig = (start, frozenset(regs.items()), frozenset(stack.items()))
            if sig in seen or count[start] >= self.max_states:
                continue
            seen.add(sig)
            count[start] += 1
            steps += 1
            for succ, nregs, nstack in self._advance(start, regs, stack):
                todo.append((succ, nregs, nstack))
        return steps

    def _advance(self, start, regs, stack):
        probe = [self._run(start, regs, stack, s, None) for s in SEEDS]
        end = probe[0][0]
        if end is None or end != probe[1][0]:
            return []
        d = self.dispatch.get(end)
        if d is None:
            mnem = self.code.mnemonic(end)
            if mnem.startswith("j"):
                state = self._merge(probe)
                ins = self.code.insn(end)
                return [(t, *state) for t in (ins.operands[0].imm, self.code.after(end))]
            return []
        sel = d.selector
        variants = (True, False) if sel else (None,)
        out = []
        for variant in variants:
            force = (sel[0], variant, sel[1], sel[2]) if variant is not None else None
            runs = [self._run(start, regs, stack, s, force) for s in SEEDS]
            if runs[0][0] != end or runs[1][0] != end:
                continue
            target = runs[0][1][d.reg]
            if target != runs[1][1][d.reg] or target not in self.code:
                self.results[d.jmp][variant].add(None)
                continue
            self.results[d.jmp][variant].add(target)
            nregs, nstack = self._merge(runs)
            out.append((target, nregs, nstack))
        return out

    def _merge(self, runs):
        (_, ra, sa), (_, rb, sb) = runs
        return self._known(ra, rb), self._known(sa, sb)

    def apply(self, dispatches):
        for d in dispatches:
            res = self.results.get(d.jmp)
            if not res:
                continue
            sel = d.selector
            if sel:
                taken, fall = res.get(True, set()), res.get(False, set())
                if len(taken) == 1 and len(fall) == 1 and None not in taken | fall:
                    d.cmov, d.cc = sel[0], self.r.condition_code(sel[0])
                    d.taken, d.fallthrough = taken.pop(), fall.pop()
                    self.r.classify(d)
                elif d.status == "unresolved":
                    self._context(d, taken | fall)
            else:
                targets = res.get(None, set())
                if len(targets) == 1 and None not in targets:
                    d.cmov, d.taken, d.fallthrough = None, targets.pop(), None
                    self.r.classify(d)
                elif d.status == "unresolved" and len(targets - {None}) > 1:
                    self._context(d, targets)

    @staticmethod
    def _context(d, targets):
        known = sorted(t for t in targets if t is not None)
        if known:
            d.status, d.alternatives = "context", known
