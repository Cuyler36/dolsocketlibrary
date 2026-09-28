#!/usr/bin/env python3

###
# Extracts the original objects from baserom/<lib>.a and baserom/<lib>D.a
# into baserom/{release,debug}/<lib>/, and optionally writes disassembly and
# DWARF dumps next to each object.
#
# Usage:
#   python3 tools/extract.py [--dtk build/tools/dtk] [--dump]
###

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT))
from configure import CONFIGS, LIBS  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    default_dtk = ROOT / "build" / "tools" / ("dtk.exe" if os.name == "nt" else "dtk")
    parser.add_argument("--dtk", type=Path, default=default_dtk, help="path to decomp-toolkit")
    parser.add_argument("--dump", action="store_true", help="also write <unit>.s and <unit>_DWARF.c dumps")
    args = parser.parse_args()

    if not args.dtk.exists():
        sys.exit(f"dtk not found at {args.dtk} (run `ninja build/tools/dtk{'.exe' if os.name == 'nt' else ''}` first)")

    for lib in LIBS:
        for cfg, info in CONFIGS.items():
            archive = ROOT / "baserom" / f"{lib}{info['suffix']}.a"
            if not archive.is_file():
                print(f"skipping {archive.relative_to(ROOT)} (not found)")
                continue
            dest = ROOT / "baserom" / cfg / lib
            dest.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory() as tmp:
                subprocess.run([str(args.dtk), "ar", "extract", str(archive), "--out", tmp], check=True)
                # Flatten whatever directory layout the archive used.
                for obj in Path(tmp).rglob("*.o"):
                    shutil.move(str(obj), dest / obj.name)
            print(f"extracted {archive.relative_to(ROOT)} -> {dest.relative_to(ROOT)}")

            if args.dump:
                for obj in sorted(dest.glob("*.o")):
                    subprocess.run([str(args.dtk), "elf", "disasm", str(obj), str(obj.with_suffix(".s"))], check=True)
                    subprocess.run(
                        [str(args.dtk), "dwarf", "dump", str(obj), "-o", str(obj.with_name(obj.stem + "_DWARF.c"))],
                        check=False,  # release objects may have no DWARF
                    )


if __name__ == "__main__":
    main()
