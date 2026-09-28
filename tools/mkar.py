#!/usr/bin/env python3

###
# Creates a GNU-style static archive (.a) from object files.
# No symbol index is written; this is only for packaging the built objects.
#
# Usage:
#   python3 tools/mkar.py out/ip.a build/release/ip/IP.o build/release/ip/IPArp.o ...
###

import sys
from pathlib import Path


def member_header(name: str, size: int) -> bytes:
    header = (
        f"{name:<16}"  # file identifier
        f"{0:<12}"  # timestamp
        f"{0:<6}"  # owner id
        f"{0:<6}"  # group id
        f"{0o644:<8o}"  # file mode
        f"{size:<10}"  # file size
        "`\n"
    )
    assert len(header) == 60
    return header.encode("ascii")


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: mkar.py <out.a> [objects...]", file=sys.stderr)
        sys.exit(1)

    out = Path(sys.argv[1])
    objects = [Path(p) for p in sys.argv[2:]]

    # GNU long-name table for names that don't fit in 15 chars + '/'
    long_names = b""
    names = []
    for obj in objects:
        name = obj.name
        if len(name) > 15:
            names.append(f"/{len(long_names)}")
            long_names += name.encode("ascii") + b"/\n"
        else:
            names.append(name + "/")

    data = bytearray(b"!<arch>\n")
    if long_names:
        data += member_header("//", len(long_names))
        data += long_names
        if len(long_names) % 2:
            data += b"\n"

    for obj, name in zip(objects, names):
        content = obj.read_bytes()
        data += member_header(name, len(content))
        data += content
        if len(content) % 2:
            data += b"\n"

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(data))


if __name__ == "__main__":
    main()
