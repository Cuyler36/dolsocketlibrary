#!/usr/bin/env python3

###
# Rewrites an mwcc -MD dependency file into a form ninja understands:
# forward slashes, paths relative to the project root where possible,
# and wibo/wine "Z:" style paths mapped back to host paths.
#
# Usage:
#   python3 tools/transform_dep.py build/debug/ip/IPArp.d build/debug/ip/IPArp.d
###

import argparse
import os
from pathlib import Path
from platform import uname

wineprefix = os.path.join(os.environ["HOME"], ".wine") if "HOME" in os.environ else ""
if "WINEPREFIX" in os.environ:
    wineprefix = os.environ["WINEPREFIX"]
winedevices = os.path.join(wineprefix, "dosdevices")


def in_wsl() -> bool:
    return "microsoft-standard" in uname().release


def import_d_file(in_file: str) -> str:
    out_text = ""

    with open(in_file) as file:
        for idx, line in enumerate(file):
            if idx == 0:
                if line.endswith(" \\\n"):
                    out_text += line[:-3].replace("\\", "/") + " \\\n"
                else:
                    out_text += line.replace("\\", "/")
            else:
                suffix = ""
                if line.endswith(" \\\n"):
                    suffix = " \\"
                    path = line.lstrip()[:-3]
                else:
                    path = line.strip()
                # lowercase drive letter
                path = path[0].lower() + path[1:]
                if path[0] == "z":
                    # shortcut for z:
                    path = path[2:].replace("\\", "/")
                elif in_wsl():
                    path = path[0:1] + path[2:]
                    path = os.path.join("/mnt", path.replace("\\", "/"))
                elif os.name != "nt" and os.path.isdir(winedevices):
                    # use $WINEPREFIX/dosdevices to resolve path
                    path = os.path.realpath(os.path.join(winedevices, path.replace("\\", "/")))
                else:
                    path = path.replace("\\", "/")
                try:
                    rel = os.path.relpath(path)
                    if not rel.startswith(".."):
                        path = rel.replace("\\", "/")
                except ValueError:
                    pass  # different drive on Windows
                out_text += "\t" + path.replace(" ", "\\ ") + suffix + "\n"

    return out_text


def main() -> None:
    parser = argparse.ArgumentParser(description="Transform a .d file from Wine paths to normal paths")
    parser.add_argument("d_file", help="Dependency file in")
    parser.add_argument("d_file_out", help="Dependency file out")
    args = parser.parse_args()

    output = import_d_file(args.d_file)

    with open(args.d_file_out, "w", encoding="UTF-8") as f:
        f.write(output)


if __name__ == "__main__":
    main()
