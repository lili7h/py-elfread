from elf.elf import ELFHeaderEntityFactory
import sys
from pathlib import Path


if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <elf file>")
    sys.exit(1)

_fh = Path(sys.argv[1])

with open(_fh, 'rb') as h:
    _fd = h.read(64)

factory = ELFHeaderEntityFactory()
res = factory.feed(_fd)
for key in res.__dict__.keys():
    _var_name = res.__dict__[key].get_slot(0)
    _var_value = getattr(res.__dict__[key], _var_name)
    print(res.__dict__[key].__class__.__name__, " :: ", _var_name, " --> ", _var_value)
