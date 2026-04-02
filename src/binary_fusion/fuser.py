import os
import struct
import subprocess
import sys
import zlib

from .analyzer import check_compatible, print_elf_info

# the trailer sits at the end of the fused binary so the stub
# can find where the host and guest binaries are embedded
# format: host_offset, host_size, guest_offset, guest_size, flags, magic("FUSE")
# followed by trailer_size (uint64) as the very last thing in the file
TRAILER_FMT = "<QQQQI4s"
TRAILER_SIZE = struct.calcsize(TRAILER_FMT)  # 40
FLAG_COMPRESSED = 1


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

    with open(host_path, "rb") as f:
        host_data = f.read()
    with open(guest_path, "rb") as f:
        guest_data = f.read()

    print(f"Host: {host_path} ({len(host_data)} bytes)")
    print(f"Guest: {guest_path} ({len(guest_data)} bytes)")

    if compress:
        orig = len(guest_data)
        guest_data = zlib.compress(guest_data, 9)
        print(f"Compressed guest: {orig} -> {len(guest_data)} bytes")

    # find and compile the stub (the C program that actually runs both binaries)
    stub_dir = os.path.join(os.path.dirname(__file__), "..", "..", "stub")
    stub_path = compile_stub(stub_dir, with_zlib=compress)
    with open(stub_path, "rb") as f:
        stub_data = f.read()

    # the fused binary is just: stub + host + guest + trailer + trailer_size
    # the stub reads itself at runtime and uses the trailer to find the embedded binaries
    host_offset = len(stub_data)
    guest_offset = host_offset + len(host_data)

    flags = FLAG_COMPRESSED if compress else 0
    trailer = struct.pack(TRAILER_FMT,
                          host_offset, len(host_data),
                          guest_offset, len(guest_data),
                          flags, b"FUSE")
    trailer += struct.pack("<Q", TRAILER_SIZE)

    fused = stub_data + host_data + guest_data + trailer

    with open(output_path, "wb") as f:
        f.write(fused)
    os.chmod(output_path, 0o755)

    print(f"Output: {output_path} ({len(fused)} bytes)")
