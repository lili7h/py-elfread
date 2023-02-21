#!/usr/bin/env python3
from elf.elf import ELFHeaderEntityFactory
from pathlib import Path
import argparse

# Use python argparse to specify commandline arguments
# Ref: https://docs.python.org/3/library/argparse.html
parser = argparse.ArgumentParser(
    prog='elfread',
    description='Reads ELF files to extract the ELF header (and in future, sections and tables)',
    epilog='In Dev - v0.1.1a'
)
parser.add_argument('filename', help='The name of the ELF file to open (i.e. one of hte files in ./test_files/)')
args = parser.parse_args()

# Load ELF file specified by commandline args
filepath = Path(args.filename)
with open(filepath, 'rb') as h:
    # Read the first 64 bytes into `_fd_header_bytes` then the remaining bytes into `_fd_rest`
    # note: this will error out if the file contains less than 64 bytes
    _fd_header_bytes = h.read(64)
    _fd_rest = h.read()

# Feed the Factory instance the bytes for the header
# Currently we just ignore the rest of the bytes from the file (_fd_rest)
factory = ELFHeaderEntityFactory()
res = factory.feed(_fd_header_bytes)

# Coloured coded console output
# Uses ANSII escape codes for colour coding and formatting - may break if the terminal you are using
# does not support advanced ANSII escape sequences
# Note: Pycharm supports the colour codes in its built in terminal, but changes the colours a bit
res.print_colour_coded_header_bytes()
