import struct

from capstone.x86 import X86_OP_MEM, X86_REG_RIP

FLAG_SAFE = {"mov", "movabs", "lea", "movsxd", "movsx", "movzx", "nop", "xchg"}
CONTROL = ("j", "call", "ret", "int", "loop", "syscall")
SECTION_FLAGS = 0x60000020


def _jmp(src, dst):
    return b"\xE9" + struct.pack("<i", dst - (src + 5))


def _jcc(cc, src, dst):
    return bytes([0x0F, 0x80 | cc]) + struct.pack("<i", dst - (src + 6))


def _call(src, dst):
    return b"\xE8" + struct.pack("<i", dst - (src + 5))


def _push_ret(at, ret):
    """Push the address `ret` as a call would, from code placed at `at`.

    Position-independent (the image may be loaded anywhere), leaves flags and registers untouched:
        lea  rsp, [rsp - 8]
        push rax
        lea  rax, [rip + ret]
        mov  [rsp + 8], rax
        pop  rax
    """
    lea_rax = at + 6
    return (b"\x48\x8D\x64\x24\xF8" + b"\x50"
            + b"\x48\x8D\x05" + struct.pack("<i", ret - (lea_rax + 7))
            + b"\x48\x89\x44\x24\x08" + b"\x58")


def _relocate(code, va, new_va):
    ins = code.insn(va)
    raw = bytearray(ins.bytes)
    if any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP for op in ins.operands):
        target = va + ins.size + ins.disp
        raw[ins.disp_offset:ins.disp_offset + 4] = struct.pack("<i", target - (new_va + ins.size))
    return bytes(raw)


class Cave:
    def __init__(self, image):
        self.va = (image.end + 0xFFF) & ~0xFFF
        self.data = bytearray()

    def add(self, code, keep, target, push_ret=None):
        """Append a stub: the kept instructions, optionally a push of the return address `push_ret`, a jmp."""
        va = self.va + len(self.data)
        cursor = va
        for k in keep:
            raw = _relocate(code, k, cursor)
            self.data += raw
            cursor += len(raw)
        if push_ret is not None:
            raw = _push_ret(cursor, push_ret)
            self.data += raw
            cursor += len(raw)
        self.data += _jmp(cursor, target)
        return va


def plan(code, d, cave):
    if d.status not in ("cond", "goto"):
        return None
    start = d.cmov if d.cmov is not None else _first_link(code, d)
    if start is None:
        start = d.jmp  # nothing to drop before it (e.g. jmp [rip + slot])
    region = code.span(start, d.jmp)
    drop = _dispatch_chain(code, d, region)
    keep = [va for va in region if va not in drop]
    if any(code.mnemonic(va).startswith(CONTROL) for va in keep):
        return None
    end = d.jmp + d.size
    if d.is_call and d.call_mode != "discard":
        return _plan_keep(code, d, cave, start, keep, end)
    targets = [d.taken, d.fallthrough] if d.status == "cond" else [d.taken]
    if all(code.mnemonic(va) in FLAG_SAFE for va in keep):
        # Everything kept runs after the selector and leaves the flags alone: keep it in place if it fits.
        out = _branch_out(code, keep, start, targets, d.cc)
        if start + len(out) <= end:
            return start, out + b"\x90" * (end - start - len(out))
        if not keep:
            return None
    # Kept instructions move into the cave, one copy per target, after the jcc has consumed the flags.
    targets = [cave.add(code, keep, t) for t in targets]
    out = _branch_out(code, [], start, targets, d.cc)
    if start + len(out) > end:
        return None
    return start, out + b"\x90" * (end - start - len(out))


def _branch_out(code, keep, start, targets, cc):
    out, cursor = bytearray(), start
    for va in keep:
        raw = _relocate(code, va, cursor)
        out += raw
        cursor += len(raw)
    if len(targets) == 2:
        out += _jcc(cc, cursor, targets[0])
        cursor += 6
    out += _jmp(cursor, targets[-1])
    return bytes(out)


def _plan_keep(code, d, cave, start, keep, end):
    """Patch a call dispatcher so that its targets still find the original return address on the stack.

    goto: a direct `call target` placed so that it ends exactly where the original call ended.
    cond: `jcc stub_taken` + `call fallthrough` (ending where the original call ended), where the stub pushes the
    original return address and jumps; or, when that doesn't fit, two stubs that each push it.
    """
    out, cursor = bytearray(), start
    flag_safe = all(code.mnemonic(va) in FLAG_SAFE for va in keep)
    relocated = bytearray()
    for va in keep:
        raw = _relocate(code, va, start + len(relocated))
        relocated += raw
    push = d.ret
    if d.status == "goto":
        if len(relocated) + 5 <= end - start:
            pad = end - 5 - (start + len(relocated))
            return start, bytes(relocated) + b"\x90" * pad + _call(end - 5, d.taken)
        stub = cave.add(code, keep, d.taken, push)
        out = _jmp(start, stub)
    else:
        if flag_safe and len(relocated) + 11 <= end - start:
            stub = cave.add(code, [], d.taken, push)
            pad = end - 11 - (start + len(relocated))
            body = bytes(relocated) + b"\x90" * pad
            jcc_at = start + len(body)
            return start, body + _jcc(d.cc, jcc_at, stub) + _call(end - 5, d.fallthrough)
        stubs = [cave.add(code, keep, t, push) for t in (d.taken, d.fallthrough)]
        out += _jcc(d.cc, cursor, stubs[0])
        cursor += 6
        out += _jmp(cursor, stubs[1])
    if start + len(out) > end:
        return None
    return start, bytes(out) + b"\x90" * (end - start - len(out))


def _dispatch_chain(code, d, region):
    owned = set(d.regs)
    if d.cmov is not None:
        owned.add(code.regs(d.cmov)[1].pop())
    chain = {d.jmp}
    for va in region[:-1]:
        written = code.regs(va)[1]
        if va == d.cmov or (written and written <= owned):
            chain.add(va)
    return chain


def _first_link(code, d):
    first = None
    for va in reversed(code.span(d.start, d.jmp)[:-1]):
        written = code.regs(va)[1]
        if written and written <= set(d.regs):
            first = va
        elif code.mnemonic(va) not in FLAG_SAFE:
            break
    return first


def apply(image, code, dispatches):
    cave = Cave(image)
    patched, skipped = [], []
    for d in dispatches:
        p = plan(code, d, cave)
        if p is None:
            if d.status in ("cond", "goto"):
                skipped.append(d)
            continue
        va, raw = p
        off = image.file_offset(va)
        d.patch = (va, bytes(image.raw[off:off + len(raw)]), raw)
        image.raw[off:off + len(raw)] = raw
        patched.append(d)
    if cave.data:
        try:
            if image.fmt == "pe":
                _add_section(image, ".unflat", cave.va, bytes(cave.data))
            else:
                _add_segment(image, cave.va, bytes(cave.data))
        except RuntimeError:
            # No room for the cave: undo the patches that jump into it, keep the in-place ones.
            cave_lo, cave_hi = cave.va, cave.va + len(cave.data)
            for d in [d for d in patched if any(cave_lo <= t < cave_hi for t in _jump_targets(image, code, d))]:
                patched.remove(d)
                skipped.append(d)
                _restore(image, code, d)
    return patched, skipped


def _add_section(image, name, va, data):
    pe, raw = image.pe, image.raw
    oh = pe.OPTIONAL_HEADER
    falign, salign = oh.FileAlignment, oh.SectionAlignment
    nt = pe.DOS_HEADER.e_lfanew
    count = struct.unpack_from("<H", raw, nt + 6)[0]
    header = nt + 24 + pe.FILE_HEADER.SizeOfOptionalHeader + count * 40
    first_raw = min(s.PointerToRawData for s in pe.sections if s.PointerToRawData)
    if header + 40 > min(oh.SizeOfHeaders, first_raw):
        raise RuntimeError("no room in the PE header for a new section")
    raw += b"\0" * (-len(raw) % falign)
    ptr = len(raw)
    size = len(data) + (-len(data) % falign)
    raw += data + b"\0" * (size - len(data))
    struct.pack_into("<8sIIIIIIHHI", raw, header, name.encode(), len(data), va - image.base, size, ptr, 0, 0, 0, 0, SECTION_FLAGS)
    struct.pack_into("<H", raw, nt + 6, count + 1)
    struct.pack_into("<I", raw, nt + 24 + 56, (va - image.base + len(data) + salign - 1) & ~(salign - 1))


def _jump_targets(image, code, d):
    va, _, raw = d.patch
    out, i = [], 0
    while i < len(raw):
        if raw[i] == 0xE9:
            out.append(va + i + 5 + struct.unpack_from("<i", raw, i + 1)[0]); i += 5
        elif raw[i] == 0x0F and i + 1 < len(raw) and raw[i + 1] & 0xF0 == 0x80:
            out.append(va + i + 6 + struct.unpack_from("<i", raw, i + 2)[0]); i += 6
        else:
            i += 1
    return out


def _restore(image, code, d):
    va, old, _ = d.patch
    off = image.file_offset(va)
    image.raw[off:off + len(old)] = old


PT_LOAD, PT_NOTE, PF_RX = 1, 4, 5
PHDR = struct.Struct("<IIQQQQQQ")


def _add_segment(image, va, data):
    """ELF: append the cave to the file and map it by turning a PT_NOTE program header into a PT_LOAD (R+X).

    The new PT_LOAD is moved right after the last existing PT_LOAD, so loadable segments stay sorted by address
    (the kernel sizes the mapping of PIE binaries from the first and last PT_LOAD entries).
    """
    raw = image.raw
    phoff = struct.unpack_from("<Q", raw, 0x20)[0]
    phentsize, phnum = struct.unpack_from("<HH", raw, 0x36)
    if phentsize != PHDR.size:
        raise RuntimeError("unexpected ELF program header size")
    phdrs = [list(PHDR.unpack_from(raw, phoff + i * phentsize)) for i in range(phnum)]
    note = next((i for i, p in enumerate(phdrs) if p[0] == PT_NOTE), None)
    if note is None:
        raise RuntimeError("no PT_NOTE program header to reuse for the cave segment")
    raw += b"\0" * (-len(raw) % 0x1000)
    off = len(raw)
    raw += data
    entry = phdrs.pop(note)
    entry[:] = [PT_LOAD, PF_RX, off, va, va, len(data), len(data), 0x1000]
    last_load = max(i for i, p in enumerate(phdrs) if p[0] == PT_LOAD)
    phdrs.insert(last_load + 1, entry)
    for i, p in enumerate(phdrs):
        PHDR.pack_into(raw, phoff + i * phentsize, *p)
    image.segments.append(type(image.segments[0])(va, len(data), off, len(data)))
