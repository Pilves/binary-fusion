import argparse
import os
import sys

from .fuser import fuse


def main():
    parser = argparse.ArgumentParser(description="Merge two ELF executables into one")
    parser.add_argument("host_binary", help="primary executable")
    parser.add_argument("guest_binary", help="executable to inject")
    parser.add_argument("-o", "--output", help="output path")
    parser.add_argument("-c", "--compress", action="store_true", help="compress guest with zlib")
    parser.add_argument("-v", "--verbose", action="store_true", help="show ELF details")
    args = parser.parse_args()

    for p in (args.host_binary, args.guest_binary):
        if not os.path.isfile(p):
            print(f"Error: '{p}' not found", file=sys.stderr)
            sys.exit(1)

    output = args.output or f"fused_{os.path.basename(args.host_binary)}"

    fuse(args.host_binary, args.guest_binary, output,
         compress=args.compress, verbose=args.verbose)
    print(f"-> {os.path.basename(args.guest_binary)} fused into {os.path.basename(args.host_binary)}")


if __name__ == "__main__":
    main()
