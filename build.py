"""
Build the Windows executable for the DeniableCipher Web UI.

The launcher (app.py) is pure stdlib, so the resulting onefile exe is small
and contains no third-party crypto library — all cryptography runs in the
browser (WebCrypto), and the web assets are bundled as data files.

Requirements:
    pip install -i https://pypi.org/simple pyinstaller

Usage:
    python build.py             # onefile (no console window) → dist/DeniableCipher.exe
    python build.py --dir       # onedir build instead            → dist/DeniableCipher/
    python build.py --console   # keep a console window (debugging)
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

WEBUI = Path(__file__).resolve().parent
DATA = ["app.html", "app.js", "crypto.js"]


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the DeniableCipher Windows exe.")
    ap.add_argument("--name", default="DeniableCipher", help="output executable name")
    ap.add_argument("--dir", action="store_true", help="onedir build (default: onefile)")
    ap.add_argument("--console", action="store_true",
                    help="keep a console window (default: --noconsole)")
    args = ap.parse_args()

    cmd = [sys.executable, "-m", "PyInstaller",
           "--noconfirm", "--clean",
           "--onedir" if args.dir else "--onefile"]
    if not args.console:
        cmd.append("--noconsole")
    cmd += ["--name", args.name]
    for f in DATA:
        cmd += ["--add-data", f"{f}{os.pathsep}."]
    cmd.append(str(WEBUI / "app.py"))

    print("> " + " ".join(cmd))
    subprocess.run(cmd, cwd=WEBUI, check=True)

    exe = WEBUI / "dist" / (args.name + (".exe" if os.name == "nt" else ""))
    if exe.exists():
        size = exe.stat().st_size
        print(f"\nBuilt: {exe}")
        print(f"Size : {size/1024/1024:.2f} MiB")
    else:
        print(f"\nBuild finished; expected output at {exe} not found. Check the PyInstaller log.")


if __name__ == "__main__":
    main()
