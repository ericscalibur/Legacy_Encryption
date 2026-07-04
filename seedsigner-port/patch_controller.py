#!/usr/bin/env python3
"""
Patches SeedSigner's Controller so the Legacy Encryption secret store is wiped
whenever the app returns Home.

The Legacy flow keeps the in-progress seed phrase and both keys in a single
`controller.legacy_session` object (see views/legacy_views.py). The Legacy views
clear it at their own flow boundaries, but a power/home button press can jump
straight to MainMenuView from anywhere. SeedSigner already wipes its transient
secrets (psbt_seed, etc.) at exactly that point, so we hook the same block.

Called by build.sh — not meant to be run directly.

Usage: python3 patch_controller.py <path_to_controller.py>
"""

import re
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 patch_controller.py <controller_file>")
        sys.exit(1)

    controller_file = sys.argv[1]

    with open(controller_file, "r") as f:
        content = f.read()

    # Already patched?
    if "legacy_session" in content:
        print("  Already patched — skipping")
        sys.exit(0)

    # The Home-wipe block clears each transient secret with `self.<name> = None`.
    # Anchor on psbt_seed (the last/most-sensitive entry) and add ours after it,
    # preserving the original indentation.
    anchor = re.compile(r'^([ \t]*)self\.psbt_seed\s*=\s*None\s*$', re.MULTILINE)
    m = anchor.search(content)
    if not m:
        print("  Could not find Home-wipe block (self.psbt_seed = None) — "
              "clear controller.legacy_session manually; see INTEGRATION.md")
        sys.exit(1)

    indent = m.group(1)
    insertion = (
        f"\n{indent}# Legacy Encryption: wipe in-progress seed/keys on Home\n"
        f"{indent}self.legacy_session = None"
    )
    content = content[:m.end()] + insertion + content[m.end():]

    with open(controller_file, "w") as f:
        f.write(content)
    print("  Controller patched: legacy_session cleared on Home")


if __name__ == "__main__":
    main()
