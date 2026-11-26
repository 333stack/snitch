#!/usr/bin/env python3
# Required Notice: Copyright 2026 STACK (https://github.com/333stack/snitch). Licensed under PolyForm Noncommercial 1.0.0, see LICENSE.md.
"""Install Google's offline carrier-prefix data without sending phone numbers."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
from urllib.request import urlopen

RELEASE = "v9.0.44"
SOURCE = f"https://codeload.github.com/google/libphonenumber/tar.gz/refs/tags/{RELEASE}"
CARRIER_FILE = re.compile(r"[^/]+/resources/carrier/en/[0-9]+\.txt")


def install(archive, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    staged = None
    try:
        with tarfile.open(fileobj=archive, mode="r:gz") as bundle:
            files = [member for member in bundle.getmembers()
                     if member.isfile() and CARRIER_FILE.fullmatch(member.name)]
            if not files:
                raise ValueError("archive contains no English carrier-prefix files")
            license_path = files[0].name.split("/", 1)[0] + "/LICENSE"
            with bundle.extractfile(license_path) as license_file:
                license_text = license_file.read().decode("utf-8")

            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                             prefix=".carrier-", delete=False) as output:
                staged = Path(output.name)
                output.write("# Derived from Google libphonenumber English carrier data\n")
                output.write("# Source: https://github.com/google/libphonenumber\n")
                root = files[0].name.split("/", 1)[0]
                version = root.removeprefix("libphonenumber-")
                if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
                    version = "version unspecified"
                newest = max(member.mtime for member in files)
                archive_date = f"archive {datetime.fromtimestamp(newest, timezone.utc):%Y-%m-%d}; " if newest > 0 else ""
                output.write(f"# Dataset: libphonenumber {version} ({archive_date}imported {datetime.now(timezone.utc):%Y-%m-%d} UTC)\n")
                for line in license_text.splitlines():
                    output.write(f"# {line}\n")
                count = 0
                for member in files:
                    with bundle.extractfile(member) as source:
                        for raw in source:
                            line = raw.decode("utf-8").rstrip("\r\n")
                            if line.startswith("#"):
                                output.write(line + "\n")
                                continue
                            prefix, sep, carrier = line.partition("|")
                            if sep and prefix.isascii() and prefix.isdecimal():
                                output.write(f"{prefix}|{carrier}\n")
                                count += bool(carrier.strip())
                if not count:
                    raise ValueError("archive contains no usable carrier records")
        staged.replace(destination)
        print(f"Installed {count:,} carrier prefixes to {destination}")
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="use a local Google libphonenumber source tar.gz")
    parser.add_argument("--output", type=Path, default=Path(os.environ.get(
        "MARK47_DATA", str(Path(__file__).resolve().parents[1] / "data"))) / "carrier-prefixes.txt")
    args = parser.parse_args()
    try:
        if args.archive:
            with args.archive.open("rb") as archive:
                install(archive, args.output)
        else:
            with tempfile.TemporaryFile() as archive, urlopen(SOURCE, timeout=30) as download:
                shutil.copyfileobj(download, archive)
                archive.seek(0)
                install(archive, args.output)
    except (OSError, KeyError, UnicodeError, ValueError, OverflowError, tarfile.TarError) as error:
        parser.exit(1, f"Carrier data import failed: {error}\n")


if __name__ == "__main__":
    main()
