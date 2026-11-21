import bisect
import struct
from dataclasses import dataclass, field

EXEC = 0x20000000          # IMAGE_SCN_MEM_EXECUTE
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4
PT_LOAD, PF_X = 1, 1
R_64, R_GLOB_DAT, R_JUMP_SLOT, R_RELATIVE, R_IRELATIVE = 1, 6, 7, 8, 37
IMPORT_BASE, IMPORT_SIZE = 0x7FFC0000, 0x10000


@dataclass
class Section:
    name: str
    start: int
    end: int
    executable: bool


@dataclass
class Segment:
    vaddr: int
    memsz: int
    offset: int
    filesz: int


@dataclass
class Image:
    """A loaded x64 binary, PE or ELF, mapped at its preferred addresses.

    fmt is "pe" or "elf"; abi is "win64" or "sysv" (argument registers, volatile registers, TLS segment).
    Addresses are the ones a disassembler shows: ImageBase-based for PE, p_vaddr for ELF (0-based for PIE).
    """
    path: str
    fmt: str
    base: int
    raw: bytearray
    mapped: bytes
    sections: list
    segments: list = field(default_factory=list)
    functions: list = field(default_factory=list)
    entry: int = 0
    symbols: dict = field(default_factory=dict)
    imports: dict = field(default_factory=dict)      # ELF: stub address -> imported symbol name
    irelative: dict = field(default_factory=dict)    # ELF: GOT slot -> ifunc resolver (R_X86_64_IRELATIVE)
    pe: object = None

    @property
    def abi(self):
        return "win64" if self.fmt == "pe" else "sysv"

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            magic = f.read(4)
        if magic == b"\x7fELF":
            return cls._load_elf(path)
        if magic[:2] == b"MZ":
            return cls._load_pe(path)
        raise ValueError("unsupported file: expected an x64 PE or ELF")

    # ---------------------------------------------------------------- PE
    @classmethod
    def _load_pe(cls, path):
        import pefile
        pe = pefile.PE(path)
        if pe.FILE_HEADER.Machine != 0x8664:
            raise ValueError("only x64 PE files are supported")
        base = pe.OPTIONAL_HEADER.ImageBase
        sections = [
            Section(s.Name.rstrip(b"\0").decode(errors="replace"),
                    base + s.VirtualAddress,
                    base + s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData),
                    bool(s.Characteristics & EXEC))
            for s in pe.sections
        ]
        img = cls(path, "pe", base, bytearray(open(path, "rb").read()), pe.get_memory_mapped_image(), sections, pe=pe)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        img.entry = base + ep if ep else 0
        for exp in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
            if exp.name:
                img.symbols[exp.name.decode(errors="replace")] = base + exp.address
        img.functions = img._pdata()
        return img

    def _pdata(self):
        sec = next((s for s in self.sections if s.name == ".pdata"), None)
        if not sec:
            return []
        lo, hi = sec.start - self.base, sec.end - self.base
        out = set()
        for off in range(lo, min(hi, len(self.mapped)) - 11, 12):
            begin, end, _ = struct.unpack_from("<III", self.mapped, off)
            if 0 < begin < end and self.is_code(self.base + begin):
                out.add((self.base + begin, self.base + end))
        return sorted(out)

    # --------------------------------------------------------------- ELF
    @classmethod
    def _load_elf(cls, path):
        from elftools.elf.elffile import ELFFile
        raw = bytearray(open(path, "rb").read())
        with open(path, "rb") as f:
            elf = ELFFile(f)
            if elf.elfclass != 64 or elf["e_machine"] != "EM_X86_64":
                raise ValueError("only x86-64 ELF files are supported")
            loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
            if not loads:
                raise ValueError("ELF has no PT_LOAD segments")
            segments = [Segment(s["p_vaddr"], s["p_memsz"], s["p_offset"], s["p_filesz"]) for s in loads]
            base = min(s.vaddr for s in segments) & ~0xFFF
            top = max(s.vaddr + s.memsz for s in segments)
            mapped = bytearray(top - base)
            for s in segments:
                data = raw[s.offset:s.offset + s.filesz]
                mapped[s.vaddr - base:s.vaddr - base + len(data)] = data
            imports, irelative = cls._relocate(elf, mapped, base)
            sections = [
                Section(s.name, s["sh_addr"], s["sh_addr"] + s["sh_size"], bool(s["sh_flags"] & SHF_EXECINSTR))
                for s in elf.iter_sections()
                if s["sh_flags"] & SHF_ALLOC and s["sh_addr"] and s["sh_size"]
            ]
            if not sections:  # section headers stripped: fall back to the segments
                sections = [Section(f"LOAD{i}", s["p_vaddr"], s["p_vaddr"] + s["p_memsz"], bool(s["p_flags"] & PF_X))
                            for i, s in enumerate(loads)]
            img = cls(path, "elf", base, raw, bytes(mapped), sections, segments, imports=imports, irelative=irelative)
            img.entry = elf["e_entry"]
            ranges = set()
            for name in (".symtab", ".dynsym"):
                tab = elf.get_section_by_name(name)
                if not tab:
                    continue
                for sym in tab.iter_symbols():
                    if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"] and img.is_code(sym["st_value"]):
                        img.symbols.setdefault(sym.name, sym["st_value"])
                        if sym["st_size"]:
                            ranges.add((sym["st_value"], sym["st_value"] + sym["st_size"]))
            ranges |= img._eh_frame(elf)
            if not any(lo <= r[0] < hi for r in ranges for lo, hi in [(s.start, s.end) for s in img.code_sections()]):
                hdr = next((s for s in elf.iter_segments() if s["p_type"] == "PT_GNU_EH_FRAME"), None)
                if hdr is not None:
                    ranges |= img._eh_frame_hdr(hdr["p_vaddr"])
        img.functions = sorted(ranges)
        return img

    @staticmethod
    def _relocate(elf, mapped, base):
        """Apply the dynamic relocations the loader would apply, at load bias 0 (addresses = p_vaddr).

        RELATIVE and symbol relocations to local definitions get their final value. Imported symbols
        point to one-byte stubs in IMPORT_BASE (see abi.setup_imports). IRELATIVE slots (ifuncs, common in
        static binaries) are recorded and resolved later by running the resolver in the emulator.
        """
        imports, irelative, stubs = {}, {}, {}
        dyn = next((s for s in elf.iter_segments() if s["p_type"] == "PT_DYNAMIC"), None)
        if dyn is None:
            return imports, irelative
        try:
            tables = dyn.get_relocation_tables()
        except Exception:
            return imports, irelative
        for table in tables.values():
            if not table.is_RELA():
                continue
            for r in table.iter_relocations():
                off, typ, add, sym = r["r_offset"], r["r_info_type"], r["r_addend"], r["r_info_sym"]
                if not 0 <= off - base <= len(mapped) - 8:
                    continue
                value = None
                if typ == R_RELATIVE:
                    value = add
                elif typ == R_IRELATIVE:
                    irelative[off] = add
                    value = add
                elif typ in (R_64, R_GLOB_DAT, R_JUMP_SLOT):
                    name, where = "", 0
                    if sym:
                        try:
                            s = dyn.get_symbol(sym)
                            name, where = s.name, s["st_value"] if s["st_shndx"] != "SHN_UNDEF" else 0
                        except Exception:
                            pass
                    if where:
                        value = where + (add if typ == R_64 else 0)
                    elif name:
                        if name not in stubs:
                            stubs[name] = IMPORT_BASE + 16 * len(stubs)
                            imports[stubs[name]] = name
                        value = stubs[name] + (add if typ == R_64 else 0)
                if value is not None:
                    struct.pack_into("<Q", mapped, off - base, value & 0xFFFFFFFFFFFFFFFF)
        return imports, irelative

    def _eh_frame(self, elf):
        """Function ranges from .eh_frame FDEs: the ELF counterpart of .pdata, present even when stripped."""
        out = set()
        try:
            if not elf.has_dwarf_info() and not elf.get_section_by_name(".eh_frame"):
                return out
            for entry in elf.get_dwarf_info().EH_CFI_entries():
                hdr = getattr(entry, "header", None)
                if hdr is None or "initial_location" not in hdr:
                    continue
                start, size = hdr["initial_location"], hdr["address_range"]
                if size and self.is_code(start):
                    out.add((start, start + size))
        except Exception:
            pass
        return out

    def _eh_frame_hdr(self, hdr_va):
        """Function ranges from .eh_frame_hdr's sorted table, through PT_GNU_EH_FRAME.

        Used when section headers are stripped. Handles the encodings GCC and Clang emit:
        table entries as DW_EH_PE_datarel|sdata4 (0x3b), FDE pc_begin as pcrel|sdata4 (0x1b) or udata4/udata8.
        """
        out = set()
        try:
            version, ptr_enc, count_enc, table_enc = self.read(hdr_va, 4)
            if version != 1 or table_enc != 0x3B or count_enc != 0x03:
                return out
            pos = hdr_va + 4 + {0x1B: 4, 0x03: 4, 0x0B: 4}.get(ptr_enc, 4)
            count = struct.unpack("<I", self.read(pos, 4))[0]
            pos += 4
            for i in range(count):
                _, fde_rel = struct.unpack("<ii", self.read(pos + 8 * i, 8))
                fde = hdr_va + fde_rel
                length, cie_off = struct.unpack("<Ii", self.read(fde, 8))
                if not length or length == 0xFFFFFFFF:
                    continue
                cie = fde + 4 - cie_off
                enc = self._fde_encoding(cie)
                field_va = fde + 8
                if enc == 0x1B:
                    begin = field_va + struct.unpack("<i", self.read(field_va, 4))[0]
                    size = struct.unpack("<I", self.read(field_va + 4, 4))[0]
                elif enc == 0x03:
                    begin, size = struct.unpack("<II", self.read(field_va, 8))
                elif enc in (0x00, 0x04):
                    begin, size = struct.unpack("<QQ", self.read(field_va, 16))
                else:
                    continue
                if size and self.is_code(begin):
                    out.add((begin, begin + size))
        except (ValueError, struct.error):
            pass
        return out

    def _fde_encoding(self, cie):
        """FDE pointer encoding from the CIE augmentation ("zR" ...); 0x1b if not found."""
        data = self.read(cie, 64)
        aug_end = data.index(b"\0", 9)
        aug = data[9:aug_end].decode(errors="replace")
        if not aug.startswith("z"):
            return 0x00
        p = aug_end + 1

        def uleb(p):
            v = shift = 0
            while True:
                b = data[p]; p += 1
                v |= (b & 0x7F) << shift; shift += 7
                if b < 0x80:
                    return v, p
        _, p = uleb(p)                    # code alignment
        while data[p] & 0x80: p += 1      # data alignment (sleb)
        p += 1
        _, p = uleb(p)                    # return address register (CIE v1 is one byte, but < 0x80 here)
        _, p = uleb(p)                    # augmentation data length
        for c in aug[1:]:
            if c == "R":
                return data[p]
            if c == "P":
                enc = data[p]; p += 1 + {0x03: 4, 0x0B: 4, 0x1B: 4, 0x9B: 4, 0x00: 8, 0x04: 8}.get(enc & 0x7F, 4)
            elif c == "L":
                p += 1
        return 0x1B

    # ------------------------------------------------------------ common
    @property
    def size(self):
        return max(len(self.mapped), max(s.end for s in self.sections) - self.base)

    @property
    def end(self):
        """First address past everything the image maps (sections, segments, .bss)."""
        ends = [s.end for s in self.sections] + [s.vaddr + s.memsz for s in self.segments]
        return max(ends)

    def code_sections(self):
        return [s for s in self.sections if s.executable]

    def is_code(self, va):
        return any(s.executable and s.start <= va < s.end for s in self.sections)

    def read(self, va, n):
        off = va - self.base
        return bytes(self.mapped[off:off + n])

    def section_data(self, sec):
        if self.fmt == "pe":
            ps = next(s for s in self.pe.sections if self.base + s.VirtualAddress == sec.start)
            return ps.get_data()
        return self.read(sec.start, sec.end - sec.start)

    def file_offset(self, va):
        if self.fmt == "pe":
            return self.pe.get_offset_from_rva(va - self.base)
        for s in self.segments:
            if s.vaddr <= va < s.vaddr + s.filesz:
                return s.offset + va - s.vaddr
        raise ValueError(f"{va:#x} is not backed by file data")

    def function_of(self, va):
        i = bisect.bisect_right(self.functions, (va, float("inf"))) - 1
        if i >= 0 and self.functions[i][0] <= va < self.functions[i][1]:
            return self.functions[i]
        return None
