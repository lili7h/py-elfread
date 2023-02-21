# py-elfread
A basic [ELF File](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) Header reader written in Python as an example program. In dev.

Attempts to use some OOP (Object Oriented Programming) techniques to enforce good style, if confused please research OOP principles/design patterns such as Classes, Objects, Singletons, Factories.

The main runnable is `./elfread.py`, which references files in the `./elf/` and `./modules/` directories. Most of the code is implemented in `./elf/elf.py`.

Run a test using something like:

`$ ./elfread.py test_files/1337`

(obvs don't put the '$' in your command). There are a couple other test files which (im pretty certain) are also ELF files.
