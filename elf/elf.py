from threading import Lock
from typing import Callable
from elf.elf_single_byte_classes import MagicBytes, ELFBitFormat, Endianness, EVersion, TargetOSABI, ABIVersion, \
    ELFHeaderPadding
from elf.elf_classes import ELFFileType, ELFMachine, ELFLongVersion, ELFEntryPoint, ELFProgramHeaderTableAddr, \
    ELFSectionHeaderTableAddr, ELFFlags, ELFHeaderSize, ELFProgramHeaderTableEntSize, ELFProgramHeaderTableEntNum, \
    ELFSectionHeaderTableEntSize, ELFSectionHeaderTableEntNum, ELFSectionNamesSectionHeaderTableIndex
from modules.logging import LoggingColours
from tabulate import tabulate


class FactorySingletonManager(type):
    """
    Singleton metaclass for managing the factory singleton. Do not attempt to directly instantiate,
    reference or otherwise use this class. Its function is autonomous.

    We use a singleton for our factories to enforce that only 1 factory is ever instantiated (created via
    `ELFHeaderEntityFactory()`) because there is no functional reason to creating multiple factories, and this
    wastes memory, but more importantly it does not align with the ideology we have visualised for this program,
    and thus we enforce it in code.

    This pythonic singleton will return a reference to the already instantiated factory if another call is made to
    `ELFHeaderEntityFactory()`, thus this allows us to pass references to this one factory around different files
    without having to pass it is a parameter or import the variable.

    E.G:

    >>> ELFHeaderEntityFactory()
    <'ELFHeaderEntityFactory' object at 0x123fakeaddress>
    >>> ELFHeaderEntityFactory()
    <'ELFHeaderEntityFactory' object at 0x123fakeaddress> #  (<--- note that the address is the same!)

    So further calls to ELFHeaderEntityFactory() after the first will just return the original object.
    """
    _instances = {}

    # Locks add thread safety (i.e. this singleton will work in multithread/multiprocess applications
    _lock: Lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                instance = super().__call__(*args, **kwargs)
                cls._instances[cls] = instance
        return cls._instances[cls]


class ELFHeader:
    VALUE_DESCRIPTIONS: list[str] = [
        "Header Magic Bytes (Indicates the start of an ELF File Header)",
        "The bit format of the file (1 = 32bit, 2=64bit)",
        "The endianness of the file (1 = little, 2 = big)",
        "The version of the ELF specification (0 = None, 1 = Original/Current)",
        "The target OSABI (operating system application binary interface)",
        "The version of the targeted ABI",
        "Reserved/padding bytes (should be all 0)",
        "The object file type",
        "The target ISA (instruction set architecture)",
        "The file version (functionally identical to the previous version value)",
        "The program entry point (address to start execution at)",
        "The offset of the start of the program header table",
        "The offset of the start of the section header table",
        "Flags (target architecture dependent)",
        "The size of this ELF header",
        "The size of an entry in the program header table",
        "The number of entries in the program header table",
        "The size of an entry in the section header table",
        "The number of entries in the section header table",
        "The index of the section header table entry that contains the section names"
    ]

    def __init__(self) -> None:
        self.magic_bytes: MagicBytes | None = None
        self.bit_format: ELFBitFormat | None = None
        self.endianness: Endianness | None = None
        self.short_version: EVersion | None = None
        self.target_os_abi: TargetOSABI | None = None
        self.abi_version: ABIVersion | None = None
        self.padding: ELFHeaderPadding | None = None
        self.type: ELFFileType | None = None
        self.machine: ELFMachine | None = None
        self.long_version: ELFLongVersion | None = None
        self.entry_point: ELFEntryPoint | None = None
        self.ph_table_addr: ELFProgramHeaderTableAddr | None = None
        self.sh_table_addr: ELFSectionHeaderTableAddr | None = None
        self.flags: ELFFlags | None = None
        self.header_size: ELFHeaderSize | None = None
        self.ph_table_entry_size: ELFProgramHeaderTableEntSize | None = None
        self.sh_table_entry_size: ELFSectionHeaderTableEntSize | None = None
        self.ph_table_entry_num: ELFProgramHeaderTableEntNum | None = None
        self.sh_table_entry_num: ELFSectionHeaderTableEntNum | None = None
        self.section_names_sh_table_index: ELFSectionNamesSectionHeaderTableIndex | None = None

    @property
    def magic_bytes(self) -> MagicBytes:
        return self._magic_bytes

    @property
    def bit_format(self) -> ELFBitFormat:
        return self._bit_format

    @property
    def endianness(self) -> Endianness:
        return self._endianness

    @property
    def short_version(self) -> EVersion:
        return self._short_version

    @property
    def target_os_abi(self) -> TargetOSABI:
        return self._target_os_abi

    @property
    def abi_version(self) -> ABIVersion:
        return self._abi_version

    @property
    def padding(self) -> ELFHeaderPadding:
        return self._padding

    @property
    def type(self) -> ELFFileType:
        return self._type

    @property
    def machine(self) -> ELFMachine:
        return self._machine

    @property
    def long_version(self) -> ELFLongVersion:
        return self._long_version

    @property
    def entry_point(self) -> ELFEntryPoint:
        return self._entry_point

    @property
    def ph_table_addr(self) -> ELFProgramHeaderTableAddr:
        return self._ph_table_addr

    @property
    def sh_table_addr(self) -> ELFSectionHeaderTableAddr:
        return self._sh_table_addr

    @property
    def flags(self) -> ELFFlags:
        return self._flags

    @property
    def header_size(self) -> ELFHeaderSize:
        return self._header_size

    @property
    def ph_table_entry_size(self) -> ELFProgramHeaderTableEntSize:
        return self._ph_table_entry_size

    @property
    def sh_table_entry_size(self) -> ELFSectionHeaderTableEntSize:
        return self._sh_table_entry_size

    @property
    def ph_table_entry_num(self) -> ELFProgramHeaderTableEntNum:
        return self._ph_table_entry_num

    @property
    def sh_table_entry_num(self) -> ELFSectionHeaderTableEntNum:
        return self._sh_table_entry_num

    @property
    def section_names_sh_table_index(self) -> ELFSectionNamesSectionHeaderTableIndex:
        return self._section_names_sh_table_index

    @magic_bytes.setter
    def magic_bytes(self, value: MagicBytes):
        self._magic_bytes: MagicBytes = value

    @bit_format.setter
    def bit_format(self, value: ELFBitFormat):
        self._bit_format: ELFBitFormat = value

    @endianness.setter
    def endianness(self, value: Endianness):
        self._endianness: Endianness = value

    @short_version.setter
    def short_version(self, value: EVersion):
        self._short_version: EVersion = value

    @target_os_abi.setter
    def target_os_abi(self, value: TargetOSABI):
        self._target_os_abi: TargetOSABI = value

    @abi_version.setter
    def abi_version(self, value: ABIVersion):
        self._abi_version: ABIVersion = value

    @padding.setter
    def padding(self, value: ELFHeaderPadding):
        self._padding: ELFHeaderPadding = value

    @type.setter
    def type(self, value: ELFFileType):
        self._type: ELFFileType = value

    @machine.setter
    def machine(self, value: ELFMachine):
        self._machine: ELFMachine = value

    @long_version.setter
    def long_version(self, value: ELFLongVersion):
        self._long_version: ELFLongVersion = value

    @entry_point.setter
    def entry_point(self, value: ELFEntryPoint):
        self._entry_point: ELFEntryPoint = value

    @ph_table_addr.setter
    def ph_table_addr(self, value: ELFProgramHeaderTableAddr):
        self._ph_table_addr: ELFProgramHeaderTableAddr = value

    @sh_table_addr.setter
    def sh_table_addr(self, value: ELFSectionHeaderTableAddr):
        self._sh_table_addr: ELFSectionHeaderTableAddr = value

    @flags.setter
    def flags(self, value: ELFFlags):
        self._flags: ELFFlags = value

    @header_size.setter
    def header_size(self, value: ELFHeaderSize):
        self._header_size: ELFHeaderSize = value

    @ph_table_entry_size.setter
    def ph_table_entry_size(self, value: ELFProgramHeaderTableEntSize):
        self._ph_table_entry_size: ELFProgramHeaderTableEntSize = value

    @sh_table_entry_size.setter
    def sh_table_entry_size(self, value: ELFSectionHeaderTableEntSize):
        self._sh_table_entry_size: ELFSectionHeaderTableEntSize = value

    @ph_table_entry_num.setter
    def ph_table_entry_num(self, value: ELFProgramHeaderTableEntNum):
        self._ph_table_entry_num: ELFProgramHeaderTableEntNum = value

    @sh_table_entry_num.setter
    def sh_table_entry_num(self, value: ELFSectionHeaderTableEntNum):
        self._sh_table_entry_num: ELFSectionHeaderTableEntNum = value

    @section_names_sh_table_index.setter
    def section_names_sh_table_index(self, value: ELFSectionNamesSectionHeaderTableIndex):
        self._section_names_sh_table_index: ELFSectionNamesSectionHeaderTableIndex = value

    @staticmethod
    def _add_colour(colour: str, message: str) -> str:
        return colour + message + LoggingColours.reset

    def print_colour_coded_header_bytes(self) -> None:
        _col_rotation = [
            LoggingColours.strong_red,
            LoggingColours.strong_green,
            LoggingColours.strong_cyan,
            LoggingColours.strong_yellow,
            LoggingColours.strong_magenta,
            LoggingColours.strong_blue
        ]
        _objs = [
            self.magic_bytes,
            self.bit_format,
            self.endianness,
            self.short_version,
            self.target_os_abi,
            self.abi_version,
            self.padding,
            self.type,
            self.machine,
            self.long_version,
            self.entry_point,
            self.ph_table_addr,
            self.sh_table_addr,
            self.flags,
            self.header_size,
            self.ph_table_entry_size,
            self.ph_table_entry_num,
            self.sh_table_entry_size,
            self.sh_table_entry_num,
            self.section_names_sh_table_index,
        ]
        _bytes = []
        _table_headers = ['Offset', 'Value', 'Description']
        _s_addr, _header_bytes = [], []
        for i in _objs:
            _bytes.append(i.PLAIN_BYTES.hex())
            _s_addr.append(hex(i.HDR_OFS))

        for idx, b_str in enumerate(_bytes):
            _header_bytes.append(
                (  # This is a tuple declaration
                    _s_addr[idx],
                    self._add_colour(_col_rotation[idx % len(_col_rotation)], '0x' + b_str),
                    self.VALUE_DESCRIPTIONS[idx]
                )
            )
            # _header_bytes.append('0x' + b_str)
        print(LoggingColours.strong_green + LoggingColours.underline,
              "ELF Header - Basic Details:",
              LoggingColours.reset)
        print(tabulate(tabular_data=_header_bytes, headers=_table_headers, tablefmt='rounded_outline'))
        # print(' '.join(_header_bytes))


class ELFHeaderEntityFactory(metaclass=FactorySingletonManager):
    """
    Parses the ELF header of an ELF file and instantiates the necessary objects to represent that header

    An ELF file is a standard executable file format for Linux, like a Windows EXE file. ELF stands for
    'Executable and Linkable Format'. It is linkable because the file can reference external libraries (like glibc)
    for necessary code functions without having to build the library into the executable itself.

    See the ELF Header spec at: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
                            or: https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html

    Factories, metaclasses and Singletons are all components of the Object-Oriented Programming (OOP) patterns,
    typically you see them expressed in enterprise Java programs, but I used them here to enforce good coding style
    on my behalf.
    """
    FIELD_BYTE_LENGTHS: dict[int, list[int]] = {
        32: [4, 1, 1, 1, 1, 1, 7, 2, 2, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2],
        64: [4, 1, 1, 1, 1, 1, 7, 2, 2, 4, 8, 8, 8, 4, 2, 2, 2, 2, 2, 2]
    }
    FIELD_ORDER: list[tuple[Callable, str]] = [
        (MagicBytes, 'magic_bytes'),
        (ELFBitFormat, 'bit_format'),
        (Endianness, 'endianness'),
        (EVersion, 'short_version'),
        (TargetOSABI, 'target_os_abi'),
        (ABIVersion, 'abi_version'),
        (ELFHeaderPadding, 'padding'),
        (ELFFileType, 'type'),
        (ELFMachine, 'machine'),
        (ELFLongVersion, 'long_version'),
        (ELFEntryPoint, 'entry_point'),
        (ELFProgramHeaderTableAddr, 'ph_table_addr'),
        (ELFSectionHeaderTableAddr, 'sh_table_addr'),
        (ELFFlags, 'flags'),
        (ELFHeaderSize, 'header_size'),
        (ELFProgramHeaderTableEntSize, 'ph_table_entry_size'),
        (ELFProgramHeaderTableEntNum, 'ph_table_entry_num'),
        (ELFSectionHeaderTableEntSize, 'sh_table_entry_size'),
        (ELFSectionHeaderTableEntNum, 'sh_table_entry_num'),
        (ELFSectionNamesSectionHeaderTableIndex, 'section_names_sh_table_index'),
    ]
    instances: list[ELFHeader] = None

    def __init__(self):
        if self.instances is None:
            self.instances = []

    def feed(self, header_bytes: bytes) -> ELFHeader:
        _new_inst = ELFHeader()
        _bit_mode = 32
        _endianness = 'big'
        _hb = header_bytes
        for idx, func_attr_tup in enumerate(self.FIELD_ORDER):
            # Remember that `func_attr_tup` is a tuple (indicated by the suffix _tup) of a function (Callable type)
            # and a string (the name of the variable we want to store the result in for that particular class object)
            func, attr = func_attr_tup
            # We use _hb like a stream of bytes, stripping what we need off of the front based on our lookup table based
            # on the bitmode of the binary
            _cb, _hb = _hb[:self.FIELD_BYTE_LENGTHS[_bit_mode][idx]], _hb[self.FIELD_BYTE_LENGTHS[_bit_mode][idx]:]
            if len(_cb) == 1:
                _cb = int.from_bytes(_cb, _endianness, signed=False)

            _sinst = func(_cb, endianness=_endianness, bitmode=_bit_mode)
            # We use setattr because this allows us to define the value of a class variable by the variables name
            # i.e. the `attr` string contains the name of the variable inside the `_new_inst` class object, and
            # _sinst is the value we are assigning to that object.variable pair
            setattr(_new_inst, attr, _sinst)

            # By the time the bit mode and endianness of the binary is actually relevant to reading values out of the
            # header, we have already fallen through these if statements and updated the values to their correct values
            if type(_sinst) == ELFBitFormat:
                _bit_mode = _sinst.bit_format
            if type(_sinst) == Endianness:
                _endianness = _sinst.endianness

        # A factory should store all the instances it produces
        # But we also return a reference to the instance for chaining reasons
        self.instances.append(_new_inst)
        return _new_inst
