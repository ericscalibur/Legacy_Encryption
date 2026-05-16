#!/usr/bin/env bash
# Flash the Legacy Encryption image to an SD card.
# Usage: sudo ./flash.sh
#        sudo ./flash.sh /dev/disk4   (if it auto-detects the wrong disk)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="${SCRIPT_DIR}/build/seedsigner-os/images/seedsigner_os.legacy-encryption.pi0.img"

if [ ! -f "$IMG" ]; then
    echo "[ERROR] Image not found: $IMG"
    echo "        Run ./build.sh --github-user YOUR_USERNAME first."
    exit 1
fi

# Auto-detect SD card (external FDisk disk that is NOT the boot drive)
if [ -n "${1:-}" ]; then
    DISK="$1"
else
    DISK=$(diskutil list | awk '/external, physical/{dev=$1} /Windows_FAT|FDisk/{if(dev) print dev; dev=""}' | head -1)
    if [ -z "$DISK" ]; then
        echo "[ERROR] Could not auto-detect SD card."
        echo "        Run: diskutil list   and pass the disk as an argument, e.g.:"
        echo "        sudo ./flash.sh /dev/disk4"
        exit 1
    fi
fi

IMG_MB=$(( $(stat -f%z "$IMG") / 1024 / 1024 ))
echo ""
echo "  Image : $IMG  (${IMG_MB} MB)"
echo "  Target: $DISK"
echo ""
diskutil list "$DISK"
echo ""
echo "  WARNING: This will ERASE everything on $DISK"
echo "  Press Enter to continue, Ctrl-C to cancel."
read -r

diskutil unmountDisk force "$DISK"
echo ""
echo "  Flashing..."
dd if="$IMG" of="${DISK/disk/rdisk}" bs=4m
sync
diskutil eject "$DISK"
echo ""
echo "  Done — you can remove the SD card."
