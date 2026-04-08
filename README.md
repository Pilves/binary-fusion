# Binary Fusion

A CLI tool that takes two ELF executables and merges them into a single binary that runs both programs sequentially. 

```
$ python -m binary_fusion demo/jules demo/vincent
-> vincent fused into jules

$ ./fused_jules
What do they call it?
They call it a Royale with Cheese.
```

## Approach

I went with an embedded executable + loader stub design. Instead of merging sections from both ELFs directly (which would mean fixing relocations, merging symbol tables, GOT/PLT — basically rewriting a linker), I keep both binaries fully intact and bundle them inside a small C launcher.

Steps the fuser takes:

1. Parses and validates both inputs with LIEF — checks architecture, ELF class, and file type
2. Compiles a small C stub (the loader). This becomes the entry point of the fused binary.
3. Glues everything together: `stub + host + guest + trailer`
4. Writes a 40-byte trailer at the end with offsets and sizes so the stub knows where each binary lives

When you run the fused binary, the stub:

- reads itself via `/proc/self/exe`
- finds the trailer at the end of the file
- extracts both binaries to temp files in `/tmp`
- runs the host with `fork()` + `execve()`, waits for it to finish
- runs the guest the same way
- cleans up

## Setup

You need Python 3.12+, gcc, and uv.

```bash
uv sync
bash demo/build_fixtures.sh
```

The stub gets compiled automatically the first time you run a fusion.

## Usage

```bash
python -m binary_fusion demo/jules demo/vincent
./fused_jules
```

Options:

- `-o PATH` — choose the output filename (default is `fused_<host>`)
- `-v` — verbose mode, prints ELF headers and section permissions for both inputs
- `-c` — compress the guest binary with zlib

## Output redirection

The host writes to stdout and the guest writes to stderr. The stub does this by `dup2`-ing the guest's stdout onto fd 2 before the second `execve`. So you can split each program's output with normal shell redirection:

```bash
./fused_jules > host.txt 2> guest.txt
cat host.txt    # What do they call it?
cat guest.txt   # They call it a Royale with Cheese.
```

## What it accepts

Both inputs need to be ELF executables (`ET_EXEC` or `ET_DYN`). Object files (`.o`) and core dumps get rejected. Architecture and ELF class have to match — you can't fuse a 32-bit with a 64-bit, or x86_64 with ARM. Mixing static and dynamic binaries is allowed but prints a warning.

## Files

```
binary_fusion/
  main.py       CLI argument parsing
  analyzer.py   ELF parsing and validation with LIEF
  fuser.py      fusion logic, stub compilation, trailer building
stub/
  stub.c        the C loader that runs both embedded binaries at runtime
demo/           sample inputs (jules.c, vincent.c) and a build script
```
