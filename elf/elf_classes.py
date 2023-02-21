"""
This module contains data classes for the following elements of the ELF File Header:

Human Name                | Man page name
--------------------------+--------------------------------
Obj File Type             | e_type (len=2)
ISA                       | e_machine (len=2)
ELF Version               | e_version (len=4)
Entry Point               | e_entry (len=4/8)
Program Headers Table Ofs | e_phoff (len=4/8)
Section Headers Table Ofs | e_shoff (len=4/8)
Flags                     | e_flags (len=4)
ELF Header Size           | e_ehsize (len=2)
PH Table Ent Size         | e_phentsize (len=2)
Num of PH Table elements  | e_phnum (len=2)
SH Table Ent Size         | e_shentsize (len=2)
Num of SH Table elements  | e_shnum (len=2)
IDX of SN SH Table Entry  | e_shstrndx (len=2)

"""
from elf.elf_single_byte_classes import ELFHeaderElement
from typing import Literal


class ELFFileType(ELFHeaderElement):
    """
    This data class records the ELF File Type (at header offset 0x10 with length=2)

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x10
    HDR_LEN = 0x02
    # Lookup table for type strings based on int value
    TYPES: dict[int, str] = {
        0x00: "ET_NONE",
        0x01: "ET_REL",
        0x02: "ET_EXEC",
        0x03: "ET_DYN",
        0x04: "ET_CORE",
        0xFE00: "ET_LOOS",
        0xFEFF: "ET_HIOS",
        0xFF00: "ET_LOPROC",
        0xFFFF: "ET_HIPROC",
    }
    # Lookup table for type descriptions based on int value
    TYPE_DESCS: dict[int, str] = {
        0x00: "No file type",
        0x01: "Relocatable file",
        0x02: "Executable file",
        0x03: "Shared object file",
        0x04: "Core file",
        0xFE00: "Operating system-specific",
        0xFEFF: "Operating system-specific",
        0xFF00: "Processor-specific",
        0xFFFF: "Processor-specific",
    }
    __slots__ = ('type', 'type_str', 'type_desc_str',)

    def __init__(self, file_type_bytes: bytes, endianness: str, bitmode: int) -> None:
        _file_type_int = int.from_bytes(file_type_bytes, endianness, signed=False)

        assert 0x0 <= _file_type_int <= 0xFFFF
        self.type: int = _file_type_int
        try:
            self.type_str: str = self.TYPES[self.type]
            self.type_desc_str: str = self.TYPE_DESCS[self.type]
        except KeyError:
            # The first assert statement checks the general value range, then the attempted dict access works to check
            # that the value is valid. In case of KeyError being raised, we can raise AssertionError as the value
            # is within the expected range (0 -> 65535) but not one of the specific mapped values
            raise AssertionError(self.type)

        self.PLAIN_BYTES = file_type_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFMachine(ELFHeaderElement):
    """
    This data class records the Machine def (at header offset 0x12 with length=2)

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x12
    HDR_LEN = 0x02
    # Lookup table for type strings based on int value
    MACHINES: dict[int, str] = {
        0x00: "No specific instruction set",
        0x01: "AT&T WE 32100",
        0x02: "SPARC",
        0x03: "x86",
        0x04: "Motorola 68000 (M68k)",
        0x05: "Motorola 88000 (M88k)",
        0x06: "Intel MCU",
        0x07: "Intel 80860",
        0x08: "MIPS",
        0x09: "IBM System/370",
        0x0A: "MIPS RS3000 Little-endian",
        0x0B: "Reserved for future use",
        0x0C: "Reserved for future use",
        0x0D: "Reserved for future use",
        0x0E: "Hewlett-Packard PA-RISC",
        0x0F: "Reserved for future use",
        0x13: "Intel 80960",
        0x14: "PowerPC",
        0x15: "PowerPC (64-bit)",
        0x16: "S390, including S390x",
        0x17: "IBM SPU/SPC",
        0x18: "Reserved for future use",
        0x19: "Reserved for future use",
        0x1A: "Reserved for future use",
        0x1B: "Reserved for future use",
        0x1C: "Reserved for future use",
        0x1D: "Reserved for future use",
        0x1E: "Reserved for future use",
        0x1F: "Reserved for future use",
        0x20: "Reserved for future use",
        0x21: "Reserved for future use",
        0x22: "Reserved for future use",
        0x23: "Reserved for future use",
        0x24: "NEC V800",
        0x25: "Fujitsu FR20",
        0x26: "TRW RH-32",
        0x27: "Motorola RCE",
        0x28: "Arm (up to Armv7/AArch32)",
        0x29: "Digital Alpha",
        0x2A: "SuperH",
        0x2B: "SPARC Version 9",
        0x2C: "Siemens TriCore embedded processor",
        0x2D: "Argonaut RISC Core",
        0x2E: "Hitachi H8/300",
        0x2F: "Hitachi H8/300H",
        0x30: "Hitachi H8S",
        0x31: "Hitachi H8/500",
        0x32: "IA-64",
        0x33: "Stanford MIPS-X",
        0x34: "Motorola ColdFire",
        0x35: "Motorola M68HC12",
        0x36: "Fujitsu MMA Multimedia Accelerator",
        0x37: "Siemens PCP",
        0x38: "Sony nCPU embedded RISC processor",
        0x39: "Denso NDR1 microprocessor",
        0x3A: "Motorola Star*Core processor",
        0x3B: "Toyota ME16 processor",
        0x3C: "STMicroelectronics ST100 processor",
        0x3D: "Advanced Logic Corp. TinyJ embedded processor family",
        0x3E: "AMD x86-64",
        0x3F: "Sony DSP Processor",
        0x40: "Digital Equipment Corp. PDP-10",
        0x41: "Digital Equipment Corp. PDP-11",
        0x42: "Siemens FX66 microcontroller",
        0x43: "STMicroelectronics ST9+ 8/16 bit microcontroller",
        0x44: "STMicroelectronics ST7 8-bit microcontroller",
        0x45: "Motorola MC68HC16 Microcontroller",
        0x46: "Motorola MC68HC11 Microcontroller",
        0x47: "Motorola MC68HC08 Microcontroller",
        0x48: "Motorola MC68HC05 Microcontroller",
        0x49: "Silicon Graphics SVx",
        0x4A: "STMicroelectronics ST19 8-bit microcontroller",
        0x4B: "Digital VAX",
        0x4C: "Axis Communications 32-bit embedded processor",
        0x4D: "Infineon Technologies 32-bit embedded processor",
        0x4E: "Element 14 64-bit DSP Processor",
        0x4F: "LSI Logic 16-bit DSP Processor",
        0x8C: "TMS320C6000 Family",
        0xAF: "MCST Elbrus e2k",
        0xB7: "Arm 64-bits (Armv8/AArch64)",
        0xDC: "Zilog Z80",
        0xF3: "RISC-V",
        0xF7: "Berkeley Packet Filter",
        0x101: "WDC 65C816",
    }
    __slots__ = ('machine', 'machine_str',)

    def __init__(self, machine_bytes: bytes, endianness: str, bitmode: int) -> None:
        _machine_int = int.from_bytes(machine_bytes, endianness, signed=False)
        assert 0x0 <= _machine_int <= 0x101
        self.machine: int = _machine_int
        try:
            self.machine_str: str = self.MACHINES[self.machine]
        except KeyError:
            # The first assert statement checks the general value range, then the attempted dict access works to check
            # that the value is valid. In case of KeyError being raised, we can raise AssertionError as the value
            # is within the expected range (0 -> 0x101) but not one of the specific mapped values
            raise AssertionError(self.machine)

        self.PLAIN_BYTES = machine_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFLongVersion(ELFHeaderElement):
    """
    This data class records the specified ELF version in a 4-byte space

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x14
    HDR_LEN = 0x04

    __slots__ = ('version',)

    def __init__(self, version_bytes: bytes, endianness: str, bitmode: int) -> None:
        _version_int = int.from_bytes(version_bytes, endianness, signed=False)
        assert _version_int in [0, 1]
        self.version: int = _version_int

        self.PLAIN_BYTES = version_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFEntryPoint(ELFHeaderElement):
    """
    This data class records the specified entry point (4 or 8 byte address) for the ELF program

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x18
    HDR_LEN = 0x04

    __slots__ = ('entry_point_addr',)

    def __init__(
            self,
            entry_point_bytes: bytes,
            endianness: str,
            bitmode: int
    ) -> None:
        assert bitmode in [32, 64], f"Unexpected bitmode found: {bitmode}bit"
        self.HDR_LEN = bitmode // 8
        assert self.HDR_LEN in [0x04, 0x08], f"Unexpected header length after length " \
                                             f"inference from bit mode: {self.HDR_LEN}"
        _entry_point_addr_int = int.from_bytes(entry_point_bytes, endianness, signed=False)
        assert 0 <= _entry_point_addr_int <= (pow(2, bitmode) - 1)
        self.entry_point_addr: int = _entry_point_addr_int

        self.PLAIN_BYTES = entry_point_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFProgramHeaderTableAddr(ELFHeaderElement):
    """
    This data class records the specified program header table address (4 or 8 byte address) for the ELF program.
    The position and length of this table in the headers changes depending on the bit mode of the ELF file.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x1C
    HDR_LEN = 0x04

    __slots__ = ('ph_table_addr',)

    def __init__(
            self,
            ph_table_addr_bytes: bytes,
            endianness: str,
            bitmode: int
    ) -> None:
        assert bitmode in [32, 64], f"Unexpected bitmode found: {bitmode}bit"
        self.HDR_LEN = bitmode // 8
        self.HDR_OFS = {32: 0x1C, 64: 0x20}[bitmode]
        assert self.HDR_LEN in [0x04, 0x08], f"Unexpected header length after length " \
                                             f"inference from bit mode: {self.HDR_LEN}"
        _ph_table_addr_int = int.from_bytes(ph_table_addr_bytes, endianness, signed=False)
        assert 0 <= _ph_table_addr_int <= (pow(2, bitmode) - 1)
        self.ph_table_addr: int = _ph_table_addr_int

        self.PLAIN_BYTES = ph_table_addr_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFSectionHeaderTableAddr(ELFHeaderElement):
    """
    This data class records the specified section header table address (4 or 8 byte address) for the ELF program.
    The position and length of this table in the headers changes depending on the bit mode of the ELF file.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x20
    HDR_LEN = 0x04

    __slots__ = ('sh_table_addr',)

    def __init__(
            self,
            sh_table_addr_bytes: bytes,
            endianness: str,
            bitmode: int
    ) -> None:
        assert bitmode in [32, 64], f"Unexpected bitmode found: {bitmode}bit"
        self.HDR_LEN = bitmode // 8
        self.HDR_OFS = {32: 0x20, 64: 0x28}[bitmode]
        assert self.HDR_LEN in [0x04, 0x08], f"Unexpected header length after length " \
                                             f"inference from bit mode: {self.HDR_LEN}"
        _sh_table_addr_int = int.from_bytes(sh_table_addr_bytes, endianness, signed=False)
        assert 0 <= _sh_table_addr_int <= (pow(2, bitmode) - 1)
        self.sh_table_addr: int = _sh_table_addr_int

        self.PLAIN_BYTES = sh_table_addr_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFFlags(ELFHeaderElement):
    """
    This data class stores the target architecture specific flags in bitstring form

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x24
    HDR_LEN = 0x04

    __slots__ = ('flags',)

    def __init__(
            self,
            flag_bytes: bytes,
            endianness: str,
            bitmode: int
    ) -> None:
        assert bitmode in [32, 64], f"Unexpected bitmode found: {bitmode}bit"
        self.HDR_OFS = {32: 0x24, 64: 0x30}[bitmode]

        _flag_int = int.from_bytes(flag_bytes, endianness, signed=False)
        assert 0 <= _flag_int <= 4294967295
        flag_bitstring = format(_flag_int, "032b")

        self.flags: str = flag_bitstring

        self.PLAIN_BYTES = flag_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFHeaderSize(ELFHeaderElement):
    """
    This data class stores the size the ELF header (usually 64 bytes for 64bit, and 52 bytes for 32bit).

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x28
    HDR_LEN = 0x02

    __slots__ = ('header_size',)

    def __init__(
            self,
            header_size_bytes: bytes,
            endianness: str,
            bitmode: int
    ) -> None:
        assert bitmode in [32, 64], f"Unexpected bitmode found: {bitmode}bit"
        self.HDR_OFS = {32: 0x28, 64: 0x34}[bitmode]

        _header_size_int = int.from_bytes(header_size_bytes, endianness, signed=False)
        assert 0 <= _header_size_int <= (pow(2, 16) - 1)

        self.header_size: int = _header_size_int

        self.PLAIN_BYTES = header_size_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFProgramHeaderTableEntSize(ELFHeaderElement):
    """
    This data class stores the size of an entry from the program header table.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x2A
    HDR_LEN = 0x02

    __slots__ = ('ph_ent_size',)

    def __init__(
            self,
            ph_ent_size_bytes: bytes,
            endianness: str,
            bitmode: int
    ) -> None:
        assert bitmode in [32, 64], f"Unexpected bitmode found: {bitmode}bit"
        self.HDR_OFS = {32: 0x2A, 64: 0x36}[bitmode]

        _ph_ent_size_int = int.from_bytes(ph_ent_size_bytes, endianness, signed=False)
        assert 0 <= _ph_ent_size_int <= (pow(2, 16) - 1)

        self.ph_ent_size: int = _ph_ent_size_int

        self.PLAIN_BYTES = ph_ent_size_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFProgramHeaderTableEntNum(ELFHeaderElement):
    """
    This data class stores the number of entries in the program header table.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x2C
    HDR_LEN = 0x02

    __slots__ = ('ph_ent_num',)

    def __init__(
            self,
            ph_ent_num_bytes: bytes,
            endianness: str,
            bitmode: int
    ) -> None:
        assert bitmode in [32, 64], f"Unexpected bitmode found: {bitmode}bit"
        self.HDR_OFS = {32: 0x2C, 64: 0x38}[bitmode]

        _ph_ent_num_int = int.from_bytes(ph_ent_num_bytes, endianness, signed=False)
        assert 0 <= _ph_ent_num_int <= (pow(2, 16) - 1)

        self.ph_ent_num: int = _ph_ent_num_int

        self.PLAIN_BYTES = ph_ent_num_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFSectionHeaderTableEntSize(ELFHeaderElement):
    """
    This data class stores the size of an entry from the section header table.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x2E
    HDR_LEN = 0x02

    __slots__ = ('sh_ent_size',)

    def __init__(
            self,
            sh_ent_size_bytes: bytes,
            endianness: str,
            bitmode: int
    ) -> None:
        assert bitmode in [32, 64], f"Unexpected bitmode found: {bitmode}bit"
        self.HDR_OFS = {32: 0x2E, 64: 0x3A}[bitmode]

        _sh_ent_size_int = int.from_bytes(sh_ent_size_bytes, endianness, signed=False)
        assert 0 <= _sh_ent_size_int <= (pow(2, 16) - 1)

        self.sh_ent_size: int = _sh_ent_size_int

        self.PLAIN_BYTES = sh_ent_size_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFSectionHeaderTableEntNum(ELFHeaderElement):
    """
    This data class stores the number of entries in the section header table.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x30
    HDR_LEN = 0x02

    __slots__ = ('sh_ent_num',)

    def __init__(
            self,
            sh_ent_num_bytes: bytes,
            endianness: str,
            bitmode: int
    ) -> None:
        assert bitmode in [32, 64], f"Unexpected bitmode found: {bitmode}bit"
        self.HDR_OFS = {32: 0x30, 64: 0x3C}[bitmode]

        _sh_ent_num_int = int.from_bytes(sh_ent_num_bytes, endianness, signed=False)
        assert 0 <= _sh_ent_num_int <= (pow(2, 16) - 1)

        self.sh_ent_num: int = _sh_ent_num_int

        self.PLAIN_BYTES = sh_ent_num_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode


class ELFSectionNamesSectionHeaderTableIndex(ELFHeaderElement):
    """
    This data class stores the index of the section names entry in the section header table.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x32
    HDR_LEN = 0x02

    __slots__ = ('section_names_idx_sh_table',)

    def __init__(
            self,
            section_names_idx_sh_table_bytes: bytes,
            endianness: str,
            bitmode: int
    ) -> None:
        assert bitmode in [32, 64], f"Unexpected bitmode found: {bitmode}bit"
        self.HDR_OFS = {32: 0x32, 64: 0x3E}[bitmode]

        _section_names_idx_sh_table_bytes_int = int.from_bytes(
            section_names_idx_sh_table_bytes,
            endianness,
            signed=False
        )
        assert 0 <= _section_names_idx_sh_table_bytes_int <= (pow(2, 16) - 1)

        self.section_names_idx_sh_table: int = _section_names_idx_sh_table_bytes_int

        self.PLAIN_BYTES = section_names_idx_sh_table_bytes
        self.ENDIANNESS = endianness
        self.BIT_MODE = bitmode
