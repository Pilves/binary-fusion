import lief
import sys


def parse_elf(path):
    binary = lief.parse(path)
    if binary is None or not isinstance(binary, lief.ELF.Binary):
        print(f"Error: '{path}' is not a valid ELF file", file=sys.stderr)
        sys.exit(1)
    return binary


def validate_binary(path):
    binary = parse_elf(path)
    elf_type = binary.header.file_type

    # modern gcc compiles as PIE by default which shows up as DYN, not EXEC
    # so we need to accept both ET_EXEC and ET_DYN
    if elf_type not in (lief.ELF.Header.FILE_TYPE.EXEC, lief.ELF.Header.FILE_TYPE.DYN):
        print(f"Error: '{path}' is not an executable (type: {elf_type.name})", file=sys.stderr)
        sys.exit(1)

    return binary


def check_compatible(host_path, guest_path):
    host = validate_binary(host_path)
    guest = validate_binary(guest_path)

    if host.header.machine_type != guest.header.machine_type:
        print(f"Error: architecture mismatch - {host_path} is {host.header.machine_type.name}, "
              f"{guest_path} is {guest.header.machine_type.name}", file=sys.stderr)
        sys.exit(1)

    if host.header.identity_class != guest.header.identity_class:
        print(f"Error: ELF class mismatch - {host_path} is {host.header.identity_class.name}, "
              f"{guest_path} is {guest.header.identity_class.name}", file=sys.stderr)
        sys.exit(1)

    # not a hard error but good to know
    host_static = not host.interpreter
    guest_static = not guest.interpreter
    if host_static != guest_static:
        print("Warning: mixing static and dynamic binaries", file=sys.stderr)

    return host, guest


def print_elf_info(path):
    binary = parse_elf(path)
    h = binary.header

    print(f"\n--- {path} ---")
    print(f"  Class:       {h.identity_class.name}")
    print(f"  Data:        {h.identity_data.name}")
    print(f"  Type:        {h.file_type.name}")
    print(f"  Machine:     {h.machine_type.name}")
    print(f"  Entry point: 0x{h.entrypoint:x}")
    print(f"  Segments:    {len(binary.segments)}")
    print(f"  Sections:    {len(binary.sections)}")
    if binary.interpreter:
        print(f"  Interpreter: {binary.interpreter}")
        print(f"  Linking:     dynamic")
    else:
        print(f"  Interpreter: none")
        print(f"  Linking:     static")

    # show sections that actually have content
    print()
    for s in binary.sections:
        if s.size > 0:
            # some section types are just ints that lief doesnt recognize
            stype = s.type
            name = stype.name if hasattr(stype, 'name') else hex(int(stype))
            print(f"  {s.name:20s}  {name:16s}  {s.size:>8} bytes  @ 0x{s.offset:x}")
    print()
