# Binary Fusion

Merges two ELF executables into a single binary that runs both programs sequentially.

## How it works

Uses the "embedded executable + loader stub" approach (same idea as self-extracting archives and binary packers like UPX):

1. Both input ELFs are validated using [LIEF](https://lief-project.github.io/) — checks architecture, type, compatibility
2. A small C "stub" program gets compiled — this is the loader
3. The fused binary is assembled by concatenating: `stub + host binary + guest binary + trailer`
4. The trailer (at the end of the file) stores offsets and sizes so the stub knows where each binary lives

At runtime, the stub reads itself via `/proc/self/exe`, finds the trailer, extracts both binaries to temp files, and runs them with `fork()` + `execve()`.

### Why not merge ELF sections directly?

That would mean remapping sections, fixing relocations, merging symbol tables, handling GOT/PLT... basically reimplementing a linker. The embedded approach sidesteps all of this — each program runs in its own process with a clean address space, so there are no conflicts.

### Fused binary layout

```
[Stub ELF]  [Host binary bytes]  [Guest binary bytes]  [Trailer]  [Trailer size]
```

The trailer contains: host offset, host size, guest offset, guest size, flags (compression), and a `FUSE` magic marker.

## Setup

Needs: Python 3.12+, gcc, uv

```bash
uv sync
bash demo/build_fixtures.sh
```

The stub compiles automatically on first run.

## Usage

```bash
python -m binary_fusion jules vincent          # creates fused_jules
python -m binary_fusion jules vincent -o out   # custom output name
python -m binary_fusion jules vincent -v       # verbose ELF analysis
python -m binary_fusion jules vincent -c       # compress guest with zlib

./fused_jules
# What do they call it?
# They call it a Royale with Cheese.
```

### Output redirection

Host stdout goes to stdout, guest stdout is redirected to stderr in the stub:

```bash
./fused_jules > host.txt 2> guest.txt
```

## Project structure

```
src/binary_fusion/
  main.py       - CLI (argparse)
  analyzer.py   - ELF parsing and validation with LIEF
  fuser.py      - fusion logic, trailer building, stub compilation
stub/
  stub.c        - C loader that extracts and runs both embedded programs
demo/           - sample inputs (jules.c, vincent.c, etc.) and build script
notes/          - task spec, testing criteria, video script
```

## ELF format notes

- **Magic:** `\x7fELF` at the start of every ELF file
- **Types:** `ET_EXEC` (traditional executable), `ET_DYN` (PIE executable, gcc default)
- **Entry point:** address where execution starts
- **Sections:** `.text` (code), `.data` (initialized data), `.rodata` (constants), `.bss` (zeroed data)
- **Segments:** what the OS actually loads into memory (`PT_LOAD`, `PT_INTERP`, etc.)
- **GOT/PLT:** used for dynamic linking — GOT holds resolved addresses, PLT provides the call trampolines
