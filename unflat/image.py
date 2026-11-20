import bisect
import struct
from dataclasses import dataclass, field

import pefile

EXEC = 0x20000000


@dataclass
class Section:
    name: str
    start: int
    end: int
    executable: bool


@dataclass
class Image:
    path: str
    pe: pefile.PE
    base: int
    raw: bytearray
    mapped: bytes
    sections: list
    functions: list = field(default_factory=list)

    @classmethod
    def load(cls, path):
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
        img = cls(path, pe, base, bytearray(open(path, "rb").read()), pe.get_memory_mapped_image(), sections)
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

    @property
    def size(self):
        return max(len(self.mapped), max(s.end for s in self.sections) - self.base)

    def code_sections(self):
        return [s for s in self.sections if s.executable]

    def is_code(self, va):
        return any(s.executable and s.start <= va < s.end for s in self.sections)

    def read(self, va, n):
        off = va - self.base
        return bytes(self.mapped[off:off + n])

    def file_offset(self, va):
        return self.pe.get_offset_from_rva(va - self.base)

    def function_of(self, va):
        i = bisect.bisect_right(self.functions, (va, float("inf"))) - 1
        if i >= 0 and self.functions[i][0] <= va < self.functions[i][1]:
            return self.functions[i]
        return None
