import struct

from capstone.x86 import X86_OP_MEM, X86_REG_RIP

FLAG_SAFE = {"mov", "movabs", "lea", "movsxd", "movsx", "movzx", "nop", "xchg"}
CONTROL = ("j", "call", "ret", "int", "loop", "syscall")
SECTION_FLAGS = 0x60000020


def _jmp(src, dst):
    return b"\xE9" + struct.pack("<i", dst - (src + 5))


def _jcc(cc, src, dst):
    return bytes([0x0F, 0x80 | cc]) + struct.pack("<i", dst - (src + 6))


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

    def add(self, code, keep, target):
        va = self.va + len(self.data)
        cursor = va
        for k in keep:
            raw = _relocate(code, k, cursor)
            self.data += raw
            cursor += len(raw)
        self.data += _jmp(cursor, target)
        return va


def plan(code, d, cave):
    if d.status not in ("cond", "goto"):
        return None
    start = d.cmov if d.cmov is not None else _first_link(code, d)
    if start is None:
        return None
    region = code.span(start, d.jmp)
    drop = _dispatch_chain(code, d, region)
    keep = [va for va in region if va not in drop]
    if any(code.mnemonic(va).startswith(CONTROL) for va in keep):
        return None
    end = d.jmp + d.size
    targets = [d.taken, d.fallthrough] if d.status == "cond" else [d.taken]
    out, cursor = bytearray(), start
    if all(code.mnemonic(va) in FLAG_SAFE for va in keep):
        for va in keep:
            raw = _relocate(code, va, cursor)
            out += raw
            cursor += len(raw)
    else:
        targets = [cave.add(code, keep, t) for t in targets]
    if len(targets) == 2:
        out += _jcc(d.cc, cursor, targets[0])
        cursor += 6
    out += _jmp(cursor, targets[-1])
    if start + len(out) > end:
        return None
    return start, bytes(out) + b"\x90" * (end - start - len(out))


def _dispatch_chain(code, d, region):
    owned = {d.reg}
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
        if written and written <= {d.reg}:
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
