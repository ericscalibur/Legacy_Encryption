#!/usr/bin/env bash
# ============================================================================
# Legacy Encryption — SeedSigner Image Builder
#
# Clones SeedSigner, patches in Legacy Encryption, builds a flashable .img
# for the Raspberry Pi Zero 1.3.
#
# Prerequisites:
#   - Docker (Docker Desktop on macOS/Windows, or docker + docker-compose on Linux)
#   - Git
#   - ~25 GB free disk space
#   - ~30 min to 2.5 hrs build time depending on your machine
#
# Usage:
#   ./build.sh                      # Full build (clone, patch, build image)
#   ./build.sh --patch-only         # Just clone + patch seedsigner (no image build)
#   ./build.sh --build-only         # Just build image (assumes already patched)
#   ./build.sh --board pi02w        # Build for Pi Zero 2 W instead of Pi Zero 1.3
#
# Output:
#   ./build/images/seedsigner_os.legacy-encryption.pi0.img
#
# This script does NOT modify any files in the Legacy_Encryption repo.
# Everything happens inside ./build/ (created by this script).
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
SEEDSIGNER_DIR="${BUILD_DIR}/seedsigner"
SEEDSIGNER_OS_DIR="${BUILD_DIR}/seedsigner-os"
BOARD="${BOARD:-pi0}"
BRANCH_NAME="legacy-encryption"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No color

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ============================================================================
# Parse arguments
# ============================================================================
PATCH_ONLY=false
BUILD_ONLY=false
INJECT_ONLY=false
GITHUB_USER="${GITHUB_USER:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --patch-only)      PATCH_ONLY=true ;;
        --build-only)      BUILD_ONLY=true ;;
        --inject)          INJECT_ONLY=true ;;
        --board)           shift; BOARD="$1" ;;
        --board=*)         BOARD="${1#*=}" ;;
        --github-user)     shift; GITHUB_USER="$1" ;;
        --github-user=*)   GITHUB_USER="${1#*=}" ;;
        --help|-h)
            echo "Usage: $0 [--patch-only] [--build-only] [--inject] [--board pi0|pi02w|pi2|pi4] [--github-user USERNAME]"
            echo "  --inject  Fast path: patch Python files directly into the .img (no Docker needed)"
            exit 0
            ;;
        *)
            error "Unknown argument: $1"
            exit 1
            ;;
    esac
    shift
done

# ============================================================================
# Step 1: Clone SeedSigner app and create legacy-encryption branch
# ============================================================================
clone_seedsigner() {
    info "Cloning SeedSigner app repo..."
    mkdir -p "$BUILD_DIR"

    if [ -d "$SEEDSIGNER_DIR" ]; then
        warn "SeedSigner directory already exists at $SEEDSIGNER_DIR"
        warn "Pulling latest and resetting branch..."
        cd "$SEEDSIGNER_DIR"
        git checkout -f dev 2>/dev/null || git checkout -f main
        git reset --hard HEAD
        git pull --ff-only
        git branch -D "$BRANCH_NAME" 2>/dev/null || true
    else
        git clone --recurse-submodules https://github.com/SeedSigner/seedsigner.git "$SEEDSIGNER_DIR"
        cd "$SEEDSIGNER_DIR"
    fi

    # Make sure submodules are initialized (translations, screenshots, etc.)
    info "Initializing git submodules..."
    git submodule update --init --recursive

    # Create the legacy-encryption branch from the latest release tag
    LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "dev")
    info "Branching from: $LATEST_TAG"
    git checkout -b "$BRANCH_NAME" "$LATEST_TAG" 2>/dev/null || git checkout -b "$BRANCH_NAME"

    # Re-init submodules on the new branch (tag may have different submodule refs)
    git submodule update --init --recursive

    ok "SeedSigner cloned and branch '$BRANCH_NAME' created (with submodules)"
}

# ============================================================================
# Step 2: Patch in Legacy Encryption files
# ============================================================================
patch_seedsigner() {
    info "Patching Legacy Encryption into SeedSigner..."
    cd "$SEEDSIGNER_DIR"

    # --- 2a. Copy the crypto module into helpers/ ---
    cp "$SCRIPT_DIR/legacy_encryption.py" src/seedsigner/helpers/legacy_encryption.py
    ok "Copied legacy_encryption.py → src/seedsigner/helpers/"

    # --- 2b. Copy the views into views/ ---
    cp "$SCRIPT_DIR/views/legacy_views.py" src/seedsigner/views/legacy_views.py
    ok "Copied legacy_views.py → src/seedsigner/views/"

    # --- 2b2. Replace camera.py to add first-frame watchdog ---
    # On Pi Zero, a second PiCamera open can silently fail — capture_continuous
    # blocks forever in the background thread, hanging the UI with no recovery.
    # Our camera.py detects this within 5 s and raises RuntimeError instead.
    cp "$SCRIPT_DIR/views/camera.py" src/seedsigner/hardware/camera.py
    ok "Copied camera.py → src/seedsigner/hardware/"

    # --- 2c. Ensure BIP-39 wordlist is accessible to the crypto module ---
    # SeedSigner bundles the wordlist; create a symlink so our module can find it
    WORDLIST_SRC=""
    for candidate in \
        src/seedsigner/models/seed_storage/wordlist/english.txt \
        src/seedsigner/resources/english.txt \
        src/seedsigner/helpers/wordlist/english.txt; do
        if [ -f "$candidate" ]; then
            WORDLIST_SRC="$candidate"
            break
        fi
    done

    if [ -n "$WORDLIST_SRC" ]; then
        # Make a relative symlink from helpers/ to wherever the wordlist lives
        WORDLIST_REL=$(python3 -c "import os.path; print(os.path.relpath('$WORDLIST_SRC', 'src/seedsigner/helpers/'))")
        ln -sf "$WORDLIST_REL" src/seedsigner/helpers/english.txt 2>/dev/null || \
            cp "$WORDLIST_SRC" src/seedsigner/helpers/english.txt
        ok "Linked BIP-39 wordlist: $WORDLIST_SRC"
    else
        warn "BIP-39 wordlist not found in expected locations"
        warn "The module will search at runtime — make sure english.txt is accessible"
    fi

    # --- 2d. Patch the main menu to add Legacy Encryption entry ---
    patch_main_menu

    # --- 2d2. Patch the Controller to wipe legacy_session on Home ---
    if [ -f src/seedsigner/controller.py ]; then
        python3 "$SCRIPT_DIR/patch_controller.py" src/seedsigner/controller.py || \
            warn "Controller auto-patch failed — legacy_session won't be wiped on Home"
    else
        warn "controller.py not found — skipping legacy_session Home-wipe patch"
    fi

    # --- 2e. Commit the changes ---
    cd "$SEEDSIGNER_DIR"
    git add -A
    git commit -m "feat: add Legacy Encryption dual-key seed phrase encryption

Adds air-gapped encrypt/decrypt for BIP-39 seed phrases using
AES-256-GCM + PBKDF2 dual-key scheme. Output format is compatible
with Legacy-offline.html (browser version).

Files added:
  - src/seedsigner/helpers/legacy_encryption.py (crypto core)
  - src/seedsigner/views/legacy_views.py (UI views)
  - src/seedsigner/hardware/camera.py (persistent stream + 500ms flush + 1fps park)
  - Main menu patched to include Legacy Encryption entry
  - controller.py patched to wipe legacy_session (seed/keys) on Home"

    ok "Changes committed to branch '$BRANCH_NAME'"
}

# ============================================================================
# Step 2d: Patch the Tools menu to add Legacy Encryption
# ============================================================================
patch_main_menu() {
    info "Patching Tools menu..."

    # Find tools_views.py — location varies by SeedSigner version
    MENU_FILE=""
    for candidate in \
        src/seedsigner/views/tools_views.py \
        src/seedsigner/views/tools_menu_views.py; do
        if [ -f "$candidate" ] && grep -q "ToolsMenuView\|VERIFY_ADDRESS\|Address Explorer" "$candidate"; then
            MENU_FILE="$candidate"
            break
        fi
    done

    if [ -z "$MENU_FILE" ]; then
        warn "Could not auto-detect tools_views.py"
        warn "You'll need to manually add the Legacy Encryption menu entry"
        warn "See INTEGRATION.md for instructions"
        return
    fi

    info "Found Tools menu in: $MENU_FILE"

    # Run the standalone Python patch script
    python3 "$SCRIPT_DIR/patch_menu.py" "$MENU_FILE" || \
        warn "Auto-patch failed — see INTEGRATION.md for manual menu wiring"
}

# ============================================================================
# Step 3: Clone seedsigner-os and build the image
# ============================================================================
clone_and_build_os() {
    info "Cloning seedsigner-os (Buildroot image builder)..."

    if [ -d "$SEEDSIGNER_OS_DIR" ]; then
        warn "seedsigner-os directory already exists, pulling latest..."
        cd "$SEEDSIGNER_OS_DIR"
        git pull --ff-only
    else
        git clone https://github.com/SeedSigner/seedsigner-os.git "$SEEDSIGNER_OS_DIR"
        cd "$SEEDSIGNER_OS_DIR"
    fi

    # Patch opt/build.sh to guard the font-subsetting block so builds succeed
    # when the seedsigner-translations submodule doesn't include a fonts/ dir
    # (this is the case for seedsigner 0.8.6 and later).
    info "Patching seedsigner-os font guard..."
    python3 - <<'PYEOF'
import re, sys
path = "opt/build.sh"
try:
    with open(path) as f:
        text = f.read()
    if 'if [ -d "${ss_translations_repo}/fonts"' in text:
        print("  Font guard already present — skipping")
        sys.exit(0)
    old_marker = '  # rename source NotoSans*ttf files to include "Original" in the name'
    new_marker = '  # rename source NotoSans*ttf files (skip if fonts/ dir absent)\n  if [ -d "${ss_translations_repo}/fonts" ]; then'
    text = text.replace(old_marker, new_marker, 1)
    old_cleanup = '  rm -f ${ss_translations_repo}/fonts/NotoSans*Regular-Original*ttf'
    new_cleanup = '  rm -f ${ss_translations_repo}/fonts/NotoSans*Regular-Original*ttf\n  fi'
    text = text.replace(old_cleanup, new_cleanup, 1)
    with open(path, "w") as f:
        f.write(text)
    print("  Font guard patched into opt/build.sh")
except Exception as e:
    print(f"  Warning: could not patch font guard: {e}", file=sys.stderr)
PYEOF

    ok "seedsigner-os ready"
}

# ============================================================================
# Step 4: Push patched seedsigner to YOUR fork + build the OS image
#
# IMPORTANT: There are TWO separate repos involved:
#
#   1. YOUR Legacy Encryption repo (Deploy-Deadman-Switch)
#      → This is where your original HTML/JS code lives.
#      → The seedsigner-port/ folder lives here as source code.
#      → You do NOT build from this repo.
#
#   2. A FORK of github.com/SeedSigner/seedsigner
#      → This is SeedSigner's Python app.
#      → The build script clones it, patches your Legacy code INTO it,
#        and pushes the patched version to YOUR fork of seedsigner.
#      → The OS image builder pulls from THIS repo to build the .img.
#
# You need to create the fork FIRST:
#   → Go to https://github.com/SeedSigner/seedsigner
#   → Click "Fork" → creates github.com/YOUR_USERNAME/seedsigner
# ============================================================================
push_and_build() {
    echo ""
    echo "============================================================"
    echo "  STEP 4: Push patched code + build the flashable image"
    echo "============================================================"
    echo ""
    echo "  Two repos are involved — read carefully:"
    echo ""
    echo "  ┌──────────────────────────────────────────────────────┐"
    echo "  │ YOUR Legacy Encryption repo                          │"
    echo "  │   → Your original HTML/JS encryption code            │"
    echo "  │   → Has seedsigner-port/ with the Python source      │"
    echo "  │   → NOT used for building the SeedSigner image       │"
    echo "  └──────────────────────────────────────────────────────┘"
    echo ""
    echo "  ┌──────────────────────────────────────────────────────┐"
    echo "  │ YOUR fork of SeedSigner/seedsigner  ← BUILD FROM    │"
    echo "  │   → A SEPARATE repo you fork on GitHub               │"
    echo "  │   → This script patches Legacy code INTO it          │"
    echo "  │   → The OS builder pulls from HERE to make the .img  │"
    echo "  └──────────────────────────────────────────────────────┘"
    echo ""

    # Use --github-user arg / GITHUB_USER env var; only prompt if still unset
    if [ -z "$GITHUB_USER" ]; then
        echo -n "  Your GitHub username (e.g. ericscalibur): "
        read -r GITHUB_USER
    fi

    if [ -z "$GITHUB_USER" ]; then
        error "GitHub username is required — pass it with: ./build.sh --github-user YOUR_USERNAME"
        exit 1
    fi

    info "Using GitHub username: $GITHUB_USER"

    FORK_URL="https://github.com/${GITHUB_USER}/seedsigner.git"

    echo ""
    info "Checking if fork exists at ${FORK_URL}..."
    if ! git ls-remote "$FORK_URL" &>/dev/null; then
        echo ""
        error "Fork not found at: $FORK_URL"
        echo ""
        echo "  You need to fork SeedSigner first:"
        echo "    1. Go to https://github.com/SeedSigner/seedsigner"
        echo "    2. Click the 'Fork' button (top right)"
        echo "    3. This creates github.com/${GITHUB_USER}/seedsigner"
        echo "    4. Re-run this script"
        echo ""
        exit 1
    fi

    ok "Fork found at ${FORK_URL}"

    # Add the fork as a remote and push the patched branch
    cd "$SEEDSIGNER_DIR"
    git remote remove myfork 2>/dev/null || true
    git remote add myfork "$FORK_URL"

    info "Pushing branch '${BRANCH_NAME}' to your fork..."
    git push -f myfork "$BRANCH_NAME"
    ok "Pushed to ${FORK_URL} branch '${BRANCH_NAME}'"

    # Now build the OS image
    echo ""
    echo "============================================================"
    echo "  Building the OS image via Docker..."
    echo "  This takes 30 min to 2.5 hours depending on your machine."
    echo "============================================================"
    echo ""

    cd "$SEEDSIGNER_OS_DIR"
    export DOCKER_DEFAULT_PLATFORM=linux/amd64
    export SS_ARGS="--${BOARD} --app-repo=${FORK_URL} --app-branch=${BRANCH_NAME}"

    info "SS_ARGS = $SS_ARGS"
    info "Starting Docker build..."
    echo ""

    docker compose up --force-recreate --build

    IMG="${SEEDSIGNER_OS_DIR}/images/seedsigner_os.${BRANCH_NAME}.${BOARD}.img"
    if [ ! -f "$IMG" ] || [ "$IMG" -ot "${SEEDSIGNER_OS_DIR}/opt/build.sh" ]; then
        error "Docker build did not produce a new image — check the Docker output above"
        error "Expected: $IMG"
        exit 1
    fi

    echo ""
    echo "============================================================"
    echo "  BUILD COMPLETE"
    echo "============================================================"
    echo ""
    echo "  Your flashable image is at:"
    echo "    ${SEEDSIGNER_OS_DIR}/images/seedsigner_os.${BRANCH_NAME}.${BOARD}.img"
    echo ""
    echo "  Flash it to a microSD card:"
    echo ""
    echo "    macOS:"
    echo "      diskutil list                    # find your SD (e.g. /dev/disk4)"
    echo "      diskutil unmountDisk /dev/disk4"
    echo "      sudo dd if=${SEEDSIGNER_OS_DIR}/images/seedsigner_os.${BRANCH_NAME}.${BOARD}.img of=/dev/rdisk4 bs=4m"
    echo "      diskutil eject /dev/disk4"
    echo ""
    echo "    Linux:"
    echo "      sudo dd if=${SEEDSIGNER_OS_DIR}/images/seedsigner_os.${BRANCH_NAME}.${BOARD}.img of=/dev/sdX bs=4M status=progress"
    echo "      sync"
    echo ""
    echo "    Or just use: Raspberry Pi Imager / balenaEtcher"
    echo ""
    echo "  Plug the microSD into your Pi Zero 1.3, power on,"
    echo "  and 'Legacy Encryption' will appear in the main menu."
    echo "============================================================"
}

# ============================================================================
# Fast inject: patch Python files directly into .img via overlay initramfs
# No Docker required — takes ~5 seconds instead of 30+ minutes.
#
# How it works:
#   The SeedSigner rootfs is a CPIO initramfs baked into the kernel (zImage).
#   The Pi bootloader supports loading a SECOND initramfs overlay from the
#   FAT partition ("followkernel" in config.txt). Linux unpacks it on top of
#   the built-in rootfs, so our files win on any path conflict.
# ============================================================================
inject_files() {
    IMG="${SEEDSIGNER_OS_DIR}/images/seedsigner_os.${BRANCH_NAME}.${BOARD}.img"

    if [ ! -f "$IMG" ]; then
        error "No image found at: $IMG"
        error "Run a full build first: ./build.sh --github-user YOUR_USERNAME"
        exit 1
    fi

    info "Injecting updated Python files into $IMG ..."

    # Mount the FAT partition (macOS uses hdiutil + mount)
    DISK=$(hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount "$IMG" 2>/dev/null \
        | head -1 | awk '{print $1}')
    if [ -z "$DISK" ]; then
        error "Could not attach image — is another process using it?"
        exit 1
    fi

    MOUNT_POINT=$(mktemp -d)
    if ! mount -t msdos "${DISK}s1" "$MOUNT_POINT" 2>/dev/null; then
        hdiutil detach "$DISK" 2>/dev/null || true
        error "Could not mount FAT partition"
        exit 1
    fi

    # Build a minimal CPIO overlay containing our Python files
    OVERLAY_DIR=$(mktemp -d)
    OVERLAY_CPIO="$MOUNT_POINT/legacy_patch.cpio.gz"

    # Paths inside the rootfs: /opt/ is where the SeedSigner app lives
    python3 - "$SCRIPT_DIR" "$OVERLAY_DIR" "$SEEDSIGNER_DIR" <<'PYEOF'
import sys, os, shutil

script_dir  = sys.argv[1]   # Legacy_Encryption/seedsigner-port/
overlay_dir = sys.argv[2]   # temp dir we populate
seedsigner_dir = sys.argv[3]  # build/seedsigner (has patched tools_views.py)

# Each entry: (source_path_relative_to_script_dir, dest_path_in_rootfs)
files = [
    ("legacy_encryption.py",          "opt/src/seedsigner/helpers/legacy_encryption.py"),
    # No-op shim: overrides the file logger baked into older images so nothing
    # can ever write to the SD card, even if a stale module still imports it.
    ("helpers/legacy_log.py",         "opt/src/seedsigner/helpers/legacy_log.py"),
    ("views/legacy_views.py",         "opt/src/seedsigner/views/legacy_views.py"),
    ("views/camera.py",               "opt/src/seedsigner/hardware/camera.py"),
    ("views/pivideostream.py",        "opt/src/seedsigner/hardware/pivideostream.py"),
]

# The patched tools_views.py (with Legacy Encryption in the Tools menu)
# lives in the seedsigner build dir after the patch step runs
extra_files = [
    (os.path.join(seedsigner_dir, "src/seedsigner/views/tools_views.py"),
     "opt/src/seedsigner/views/tools_views.py"),
    # Patched controller (wipes legacy_session on Home) — produced by patch step
    (os.path.join(seedsigner_dir, "src/seedsigner/controller.py"),
     "opt/src/seedsigner/controller.py"),
]

injected = []
for rel_src, dest_path in files:
    src = os.path.join(script_dir, rel_src)
    if not os.path.exists(src):
        print(f"  [WARN] Not found, skipping: {src}")
        continue
    dst = os.path.join(overlay_dir, dest_path)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    injected.append(dest_path)

for src, dest_path in extra_files:
    if not os.path.exists(src):
        print(f"  [WARN] Not found, skipping: {src}")
        continue
    dst = os.path.join(overlay_dir, dest_path)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    injected.append(dest_path)

for p in injected:
    print(f"  + {p}")
PYEOF

    # Pack the overlay into a gzip-compressed CPIO archive
    (cd "$OVERLAY_DIR" && find . | cpio -o -H newc 2>/dev/null | gzip -9 > "$OVERLAY_CPIO")
    rm -rf "$OVERLAY_DIR"

    OVERLAY_KB=$(du -k "$OVERLAY_CPIO" | awk '{print $1}')
    ok "Overlay CPIO created (${OVERLAY_KB} KB)"

    # Patch config.txt — add initramfs overlay directive if not already there
    # Use printf to guarantee a leading newline (file may lack a trailing one)
    CONFIG="$MOUNT_POINT/config.txt"
    if grep -q "legacy_patch" "$CONFIG" 2>/dev/null; then
        info "config.txt already has legacy_patch initramfs line"
    else
        printf '\ninitramfs legacy_patch.cpio.gz followkernel\n' >> "$CONFIG"
        ok "Patched config.txt to load overlay initramfs"
    fi

    # Unmount cleanly
    umount "$MOUNT_POINT"
    hdiutil detach "$DISK" 2>/dev/null || true
    rm -rf "$MOUNT_POINT"

    echo ""
    ok "Inject complete — image is ready to flash."
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║   Legacy Encryption — SeedSigner Image Builder          ║"
    echo "║   Air-gapped dual-key seed phrase encryption            ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    info "Board target: $BOARD"
    info "Build directory: $BUILD_DIR"
    echo ""

    # Check prerequisites
    if ! command -v git &>/dev/null; then
        error "git is required but not installed"
        exit 1
    fi

    if ! command -v python3 &>/dev/null; then
        error "python3 is required but not installed"
        exit 1
    fi

    if [ "$INJECT_ONLY" = true ]; then
        inject_files
        echo ""
        ok "All done!"
        exit 0
    fi

    if [ "$BUILD_ONLY" = false ]; then
        clone_seedsigner
        patch_seedsigner
    fi

    if [ "$PATCH_ONLY" = true ]; then
        echo ""
        ok "Patch complete. Patched SeedSigner is at: $SEEDSIGNER_DIR"
        ok "Run './build.sh --build-only' when ready to build the OS image."
        exit 0
    fi

    clone_and_build_os

    if ! command -v docker &>/dev/null; then
        echo ""
        warn "Docker not found — cannot build OS image automatically"
        echo ""
        echo "  Install Docker Desktop (https://docker.com/products/docker-desktop)"
        echo "  and re-run:  ./build.sh --build-only"
        echo ""
        exit 0
    fi

    push_and_build

    echo ""
    ok "All done!"
}

main "$@"
