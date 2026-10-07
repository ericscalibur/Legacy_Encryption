#!/usr/bin/env python3
"""
Strip host metadata from the boot (FAT16) partition of a SeedSigner image.

`build.sh --inject` mounts the image read-write with macOS `mount`, and macOS
writes `.fseventsd/` (and can write `.Spotlight-V100`, `.Trashes`, `._*`,
`.DS_Store`) onto any volume it mounts. None of that belongs on a signing
device's image. This script, run after the image is unmounted:

  1. deletes those entries with mtools (no mount, so nothing new is written),
  2. zeroes the contents of deleted directory entries (keeping the 0xE5
     marker), stale bytes after each directory's end marker, and every free
     cluster, so no deleted names or data remain recoverable,
  3. verifies: no metadata names left, both FAT copies agree, and every live
     file is byte-identical to before.

Usage:  python3 scrub_image.py <image.img>
Needs:  mtools (brew install mtools)
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile

METADATA = (".fseventsd", ".Spotlight-V100", ".Trashes", ".TemporaryItems", ".DS_Store")


def mtool(name):
    for d in os.environ.get("PATH", "").split(":") + ["/opt/homebrew/bin", "/usr/local/bin"]:
        p = os.path.join(d, name)
        if d and os.access(p, os.X_OK):
            return p
    sys.exit(f"ERROR: {name} not found. Install mtools: brew install mtools")


def run(tool, *args, check=True):
    env = dict(os.environ, MTOOLS_SKIP_CHECK="1")
    return subprocess.run([mtool(tool), *args], env=env, capture_output=True, text=True, check=check)


def partition_offset(path):
    with open(path, "rb") as f:
        mbr = f.read(512)
    assert mbr[510:512] == b"\x55\xaa", "no MBR signature"
    return struct.unpack_from("<I", mbr, 446 + 8)[0] * 512


def list_paths(img):
    out = run("mdir", "-/", "-b", "-a", "-i", img, "::/").stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


def is_metadata(path):
    base = path.rstrip("/").rsplit("/", 1)[-1]
    return base in METADATA or base.startswith("._")


def snapshot(img, dest):
    run("mcopy", "-s", "-n", "-m", "-i", img, "::/", dest)


def scrub(path, off):
    f = open(path, "r+b")
    f.seek(off)
    bs = f.read(512)
    if bs[54:62] != b"FAT16   ":
        sys.exit(f"ERROR: boot partition is {bs[54:62]!r}, this script only handles FAT16")
    bps, spc = struct.unpack_from("<H", bs, 11)[0], bs[13]
    reserved, nfats = struct.unpack_from("<H", bs, 14)[0], bs[16]
    root_entries = struct.unpack_from("<H", bs, 17)[0]
    fatsz = struct.unpack_from("<H", bs, 22)[0]
    totsec = struct.unpack_from("<H", bs, 19)[0] or struct.unpack_from("<I", bs, 32)[0]
    csize = bps * spc
    fat_off = off + reserved * bps
    root_off = fat_off + nfats * fatsz * bps
    root_len = root_entries * 32
    root_secs = (root_len + bps - 1) // bps
    data_off = root_off + root_secs * bps
    nclusters = (totsec - reserved - nfats * fatsz - root_secs) // spc
    f.seek(fat_off)
    fat = f.read(fatsz * bps)
    for i in range(1, nfats):
        f.seek(fat_off + i * fatsz * bps)
        if f.read(fatsz * bps) != fat:
            sys.exit("ERROR: FAT copies differ; refusing to modify the image")

    def nxt(c):
        return struct.unpack_from("<H", fat, c * 2)[0]

    def coff(c):
        return data_off + (c - 2) * csize

    def chain(c):
        out = []
        while 2 <= c < 0xFFF8:
            out.append(c)
            c = nxt(c)
        return out

    stats = {"deleted": 0, "tail": 0, "free": 0}

    def scrub_dir(regions, seen):
        ended = False
        subdirs = []
        for offset, length in regions:
            f.seek(offset)
            buf = bytearray(f.read(length))
            assert len(buf) == length
            dirty = False
            for i in range(0, length, 32):
                e = buf[i:i + 32]
                if ended or e[0] == 0x00:          # 0x00 ends the whole directory
                    ended = True
                    if any(e):
                        buf[i:i + 32] = bytes(32)
                        dirty = True
                        stats["tail"] += 1
                    continue
                if e[0] == 0xE5:                   # deleted: keep marker, wipe rest
                    if any(e[1:]):
                        buf[i + 1:i + 32] = bytes(31)
                        dirty = True
                        stats["deleted"] += 1
                    continue
                if e[11] == 0x0F:                  # live long-filename fragment
                    continue
                if e[11] & 0x10 and bytes(e[0:11]) not in (b".          ", b"..         "):
                    cl = struct.unpack_from("<H", e, 26)[0]
                    if cl and cl not in seen:
                        seen.add(cl)
                        subdirs.append(cl)
            if dirty:
                f.seek(offset)
                f.write(buf)
        for s in subdirs:
            scrub_dir([(coff(c), csize) for c in chain(s)], seen)

    scrub_dir([(root_off, root_len)], set())
    zero = bytes(csize)
    for c in range(2, nclusters + 2):
        if nxt(c) == 0:
            f.seek(coff(c))
            if f.read(csize) != zero:
                f.seek(coff(c))
                f.write(zero)
                stats["free"] += 1
    f.close()
    return stats


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    off = partition_offset(path)
    img = f"{path}@@{off}"

    work = tempfile.mkdtemp()
    try:
        before = os.path.join(work, "before")
        after = os.path.join(work, "after")
        os.mkdir(before)
        os.mkdir(after)

        meta = [p for p in list_paths(img) if is_metadata(p)]
        # Delete top-most entries only (a subtree goes with its parent).
        tops = [p for p in meta if not any(p != q and p.startswith(q.rstrip("/") + "/") for q in meta)]
        snapshot(img, before)
        for p in tops:
            r = run("mdeltree", "-i", img, p, check=False)
            if r.returncode != 0:
                run("mdel", "-i", img, p)
            print(f"  removed {p}")

        stats = scrub(path, off)

        left = [p for p in list_paths(img) if is_metadata(p)]
        if left:
            sys.exit(f"ERROR: metadata still present: {left}")
        snapshot(img, after)
        for p in tops:
            rel = p.lstrip(":").lstrip("/")
            target = os.path.join(before, rel)
            if os.path.isdir(target):
                shutil.rmtree(target)
            elif os.path.exists(target):
                os.remove(target)
        diff = subprocess.run(["diff", "-r", before, after], capture_output=True, text=True)
        if diff.returncode != 0:
            sys.exit("ERROR: live files changed during scrub:\n" + diff.stdout)
        print(f"  scrubbed {stats['deleted']} deleted entries, {stats['tail']} stale entries, "
              f"{stats['free']} free clusters; all live files unchanged")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
