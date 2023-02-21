"""
This module contains data classes for the following elements of the ELF File Header:

Human Name    | Man page name
--------------+--------------------------------
Magic Bytes   | e_ident[EI_MAG0] -> e_ident[EI_MAG3]
Bit Format    | e_ident[EI_CLASS]
Endianness    | e_ident[EI_DATA]
ELF Version   | e_ident[EI_VERSION]
OS ABI Target | e_ident[EI_OSABI]
ABI Version   | e_ident[EI_ABIVERSION]
Padding       | e_ident[EI_PAD]
"""
from abc import ABC
from typing import Any


class ELFHeaderElement(ABC):
    """
    Abstract ELF Header Element class with dummy HDR_OFS (Header Offset) and HDR_LEN (Header Length) vars
    for collecting data on the position (offset) and size (length) of a given bit of information in the ELF Header.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x00
    HDR_LEN = 0x00

    ENDIANNESS: str = None
    BIT_MODE: int = None
    PLAIN_BYTES: bytes

    def get_slot(self, slot_idx: int) -> Any:
        return self.__slots__[slot_idx]


class MagicBytes(ELFHeaderElement):
    """
    NOTE: This 4 byte long data element is included in the single byte classes list because it always exists in the one
    order, regardless of the file endianness.

    The data class that records the magic bytes header in the first four bytes (0x00 -> 0x03) of the ELF header
    Offers a 'valid' var that indicates whether this is a valid ELF magic-bytes header.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x00
    HDR_LEN = 0x04
    CORRECT_HEADER: bytes = b'\x7fELF'
    __slots__ = ('is_valid', 'header', )

    def __init__(self, magic_bytes: bytes, **kwargs) -> None:
        assert magic_bytes == self.CORRECT_HEADER
        self.is_valid: bool = magic_bytes == self.CORRECT_HEADER
        self.header: bytes = magic_bytes

        self.PLAIN_BYTES = magic_bytes
        self.BIT_MODE = kwargs['bitmode']
        self.ENDIANNESS = kwargs['endianness']


class ELFBitFormat(ELFHeaderElement):
    """
    The data-class (record) for the bit format of an ELF executable (either 32bit or 64bit)
    The bit format is specified by a single byte at position 0x04 of the ELF header
    A 1 here implies the binary is a 32bit ELF executable, where a 2 indicates 64bit

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x04
    HDR_LEN = 0x01
    __slots__ = ('bit_format',)

    def __init__(self, bit_format_byte: int, **kwargs) -> None:
        assert bit_format_byte in [1, 2]
        self.bit_format: int = 32 * bit_format_byte

        self.PLAIN_BYTES = int.to_bytes(bit_format_byte, 1, 'little')
        self.BIT_MODE = kwargs['bitmode']
        self.ENDIANNESS = kwargs['endianness']


class Endianness(ELFHeaderElement):
    """
    The data class that records endianness of the ELF executable, indicated by the single byte at offset
    0x05 of the ELF file header. 1 signifies little endian, 2 for big endian.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x05
    HDR_LEN = 0x01
    __slots__ = ('endianness',)

    def __init__(self, endianness_byte: int, **kwargs) -> None:
        assert endianness_byte in [1, 2]
        self.endianness: str = ['little', 'big'][endianness_byte-1]

        self.PLAIN_BYTES = int.to_bytes(endianness_byte, 1, 'little')
        self.BIT_MODE = kwargs['bitmode']
        self.ENDIANNESS = kwargs['endianness']


class EVersion(ELFHeaderElement):
    """
    The data class that records the specified version of the ELF format as specified by the byte at offset
    0x06 of the ELF File Header. 0 indicates NONE, 1 indicates Original.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x06
    HDR_LEN = 0x01
    __slots__ = ('version', 'version_str',)

    def __init__(self, version_byte: int, **kwargs) -> None:
        assert version_byte in [0, 1]
        self.version: int = version_byte
        self.version_str: str = ['none', 'original'][version_byte]

        self.PLAIN_BYTES = int.to_bytes(version_byte, 1, 'little')
        self.BIT_MODE = kwargs['bitmode']
        self.ENDIANNESS = kwargs['endianness']


class TargetOSABI(ELFHeaderElement):
    """
    The data class that records the specified target OS application binary interface (ABI)
    of the ELF executable as specified by the byte at offset 0x07 of the ELF File Header

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x07
    HDR_LEN = 0x01
    ABI_NAMES: list[str] = [
        "System V", "HP-UX", "NetBSD", "Linux", "GNU Hurd", "Solaris", "AIX (Monterey)",
        "IRIX", "FreeBSD", "Tru64", "Novell Modesto", "OpenBSD", "OpenVMS", "NonStop Kernel",
        "AROS", "FenixOS", "Nuxi CloudABI", "Stratus Technologies OpenVOS"
    ]
    __slots__ = ('os_abi', 'os_abi_str',)

    def __init__(self, os_abi_byte: int, **kwargs) -> None:
        assert os_abi_byte in range(0x0, 0x12)
        self.os_abi_str: str = self.ABI_NAMES[os_abi_byte]
        self.os_abi: int = os_abi_byte

        self.PLAIN_BYTES = int.to_bytes(os_abi_byte, 1, 'little')
        self.BIT_MODE = kwargs['bitmode']
        self.ENDIANNESS = kwargs['endianness']


class ABIVersion(ELFHeaderElement):
    """
    The data class that records the requested ABI version. The interpretation of this byte is dependent
    on the chosen ABI (see class@TargetOSABI). This byte is at offset 0x08 of the ELF File Header.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x08
    HDR_LEN = 0x01

    __slots__ = ('abi_ver',)

    def __init__(self, abi_ver_byte: int, **kwargs) -> None:
        self.abi_ver: int = abi_ver_byte

        self.PLAIN_BYTES = int.to_bytes(abi_ver_byte, 1, 'little')
        self.BIT_MODE = kwargs['bitmode']
        self.ENDIANNESS = kwargs['endianness']


class ELFHeaderPadding(ELFHeaderElement):
    """
    NOTE: This class is included here as it doesn't actually matter the endianness of the file to interpret these bytes

    This is a null class to use as a dummy token to represent the padding bytes built into the ELF Header starting
    at offset 0x09 and proceeding for 7 bytes.

    Spec (KA): https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    """
    HDR_OFS = 0x09
    HDR_LEN = 0x07

    __slots__ = ('padding',)

    def __init__(self, padding_bytes: bytes, **kwargs) -> None:
        assert padding_bytes == b'\x00'*7
        self.padding = padding_bytes

        self.PLAIN_BYTES = padding_bytes
        self.BIT_MODE = kwargs['bitmode']
        self.ENDIANNESS = kwargs['endianness']

