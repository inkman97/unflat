"""Calling-convention and thread-environment details that differ between Windows x64 and System V (Linux) x64."""
from unicorn import UC_HOOK_CODE, UcError
from unicorn import x86_const as X

ARGS = {"win64": ("rcx", "rdx", "r8", "r9"),
        "sysv": ("rdi", "rsi", "rdx", "rcx", "r8", "r9")}
VOLATILE = {"win64": ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"),
            "sysv": ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")}
TLS, TLS_SIZE = 0x7FFD0000, 0x10000
CANARY = 0x2F8A6C4D91E3B700  # stack protector value read from fs:0x28 (low byte zero, as glibc does)


def setup_tls(uc, abi, self_pointer=False):
    """Map a thread block: the TEB at gs:0 on Windows, the TCB at fs:0 on Linux."""
    uc.mem_map(TLS, TLS_SIZE)
    if abi == "win64":
        uc.reg_write(X.UC_X86_REG_GS_BASE, TLS)
        if self_pointer:
            uc.mem_write(TLS + 0x30, TLS.to_bytes(8, "little"))
    else:
        tcb = TLS + TLS_SIZE // 2  # static TLS blocks live below the TCB (negative fs offsets)
        uc.reg_write(X.UC_X86_REG_FS_BASE, tcb)
        uc.mem_write(tcb, tcb.to_bytes(8, "little"))          # tcb->tcb
        uc.mem_write(tcb + 0x10, tcb.to_bytes(8, "little"))   # tcb->self
        uc.mem_write(tcb + 0x28, CANARY.to_bytes(8, "little"))


# ------------------------------------------------------------------ ELF imports
LIBC = {"memset", "__memset_chk", "memcpy", "__memcpy_chk", "memmove", "__memmove_chk", "mempcpy",
        "bzero", "explicit_bzero", "strlen"}
MAX_COPY = 1 << 20


def setup_imports(uc, image, stack_top, budget=200_000):
    """ELF only: map the import stubs (each a `ret`), emulate a few libc memory helpers, resolve ifuncs.

    Must run before the caller adds its own code hooks, so ifunc resolvers don't show up in traces.
    """
    if image.fmt != "elf":
        return
    from .image import IMPORT_BASE, IMPORT_SIZE
    uc.mem_map(IMPORT_BASE, IMPORT_SIZE)
    uc.mem_write(IMPORT_BASE, b"\xC3" * IMPORT_SIZE)
    names = {va: name for va, name in image.imports.items() if name in LIBC}
    if names:
        uc.hook_add(UC_HOOK_CODE, _libc, names, IMPORT_BASE, IMPORT_BASE + IMPORT_SIZE - 1)
    _resolve_ifuncs(uc, image, stack_top, budget)


def _reg(uc, name):
    return uc.reg_read(getattr(X, f"UC_X86_REG_{name.upper()}"))


def _libc(uc, addr, size, names):
    name = names.get(addr)
    if not name:
        return
    dst, src, n = _reg(uc, "rdi"), _reg(uc, "rsi"), _reg(uc, "rdx")
    try:
        if name in ("memset", "__memset_chk"):
            uc.mem_write(dst, bytes([src & 0xFF]) * min(n, MAX_COPY))
            ret = dst
        elif name in ("bzero", "explicit_bzero"):
            uc.mem_write(dst, bytes(min(src, MAX_COPY)))
            ret = dst
        elif name in ("memcpy", "__memcpy_chk", "memmove", "__memmove_chk", "mempcpy"):
            n = min(n, MAX_COPY)
            uc.mem_write(dst, bytes(uc.mem_read(src, n)))
            ret = dst + n if name == "mempcpy" else dst
        else:  # strlen
            n = 0
            while n < MAX_COPY and uc.mem_read(dst + n, 1) != b"\0":
                n += 1
            ret = n
        uc.reg_write(X.UC_X86_REG_RAX, ret)
    except UcError:
        pass


def _resolve_ifuncs(uc, image, stack_top, budget):
    """R_X86_64_IRELATIVE: call each resolver once and store the implementation it picks in the GOT slot."""
    sentinel = 0xDEAD1000
    try:
        uc.mem_map(sentinel & ~0xFFF, 0x1000)
    except UcError:
        pass
    for slot, resolver in image.irelative.items():
        sp = stack_top - 0x100
        uc.mem_write(sp, sentinel.to_bytes(8, "little"))
        uc.reg_write(X.UC_X86_REG_RSP, sp)
        uc.reg_write(X.UC_X86_REG_RAX, 0)
        try:
            uc.emu_start(resolver, sentinel, count=budget)
        except UcError:
            continue
        impl = uc.reg_read(X.UC_X86_REG_RAX)
        if uc.reg_read(X.UC_X86_REG_RIP) == sentinel and image.is_code(impl):
            uc.mem_write(slot, impl.to_bytes(8, "little"))
