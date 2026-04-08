import os
import struct
import subprocess
import sys
import zlib

from .analyzer import check_compatible, print_elf_info, get_section_permissions, format_rwx, parse_elf

# the trailer sits at the end of the fused binary so the stub
# can find where the host and guest binaries are embedded
# format: host_offset, host_size, guest_offset, guest_size, flags, magic("FUSE")
# followed by trailer_size (uint64) as the very last thing in the file
TRAILER_FMT = "<QQQQI4s"
TRAILER_SIZE = struct.calcsize(TRAILER_FMT)  # 40
FLAG_COMPRESSED = 1
ALIGN = 8  # align embedded binaries to 8-byte boundaries for efficient access


def align_up(offset, alignment):
    return (offset + alignment - 1) & ~(alignment - 1)


def compile_stub(stub_dir, with_zlib=False):
    name = "stub_zlib" if with_zlib else "stub"
    stub_bin = os.path.join(stub_dir, name)
    stub_src = os.path.join(stub_dir, "stub.c")

    # dont recompile if we already have it and source hasnt changed
    if os.path.exists(stub_bin) and os.path.getmtime(stub_src) <= os.path.getmtime(stub_bin):
        return stub_bin

    cmd = ["gcc", "-O2"]
    if with_zlib:
        cmd += ["-DUSE_ZLIB"]
    cmd += ["-o", stub_bin, stub_src]
    if with_zlib:
        cmd += ["-lz"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Failed to compile stub:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    return stub_bin


def fuse(host_path, guest_path, output_path, compress=False, verbose=False):
    check_compatible(host_path, guest_path)

    if verbose:
        print_elf_info(host_path)
        print_elf_info(guest_path)

    # capture section permissions before fusion for verification
    host_bin = parse_elf(host_path)
    guest_bin = parse_elf(guest_path)
    host_perms = get_section_permissions(host_bin)
    guest_perms = get_section_permissions(guest_bin)

    with open(host_path, "rb") as f:
        host_data = f.read()
    with open(guest_path, "rb") as f:
        guest_data = f.read()

    print(f"Host: {host_path} ({len(host_data)} bytes)")
    print(f"Guest: {guest_path} ({len(guest_data)} bytes)")

    if verbose:
        print(f"\nSection permissions preserved:")
        for name, p in host_perms.items():
            print(f"  host  {name:20s} [{format_rwx(p)}]")
        for name, p in guest_perms.items():
            print(f"  guest {name:20s} [{format_rwx(p)}]")

    if compress:
        orig = len(guest_data)
        guest_data = zlib.compress(guest_data, 9)
        print(f"Compressed guest: {orig} -> {len(guest_data)} bytes")

    # find and compile the stub (the C program that actually runs both binaries)
    stub_dir = os.path.join(os.path.dirname(__file__), "..", "stub")
    stub_path = compile_stub(stub_dir, with_zlib=compress)
    with open(stub_path, "rb") as f:
        stub_data = f.read()

    # layout: stub + padding + host + padding + guest + trailer + trailer_size
    # align embedded binaries to 8-byte boundaries for efficient read access
    host_offset = align_up(len(stub_data), ALIGN)
    host_pad = host_offset - len(stub_data)

    guest_offset = align_up(host_offset + len(host_data), ALIGN)
    guest_pad = guest_offset - (host_offset + len(host_data))

    total_pad = host_pad + guest_pad

    flags = FLAG_COMPRESSED if compress else 0
    trailer = struct.pack(TRAILER_FMT,
                          host_offset, len(host_data),
                          guest_offset, len(guest_data),
                          flags, b"FUSE")
    trailer += struct.pack("<Q", TRAILER_SIZE)

    fused = (stub_data + b'\x00' * host_pad +
             host_data + b'\x00' * guest_pad +
             guest_data + trailer)

    with open(output_path, "wb") as f:
        f.write(fused)
    os.chmod(output_path, 0o755)

    overhead = total_pad + len(trailer)
    print(f"Layout: {ALIGN}-byte aligned, {total_pad} bytes padding, {overhead} bytes total overhead")
    print(f"Output: {output_path} ({len(fused)} bytes)")
