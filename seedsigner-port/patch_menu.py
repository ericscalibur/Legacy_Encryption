#!/usr/bin/env python3
"""
Patches SeedSigner's main menu to add a Legacy Encryption entry.
Called by build.sh — not meant to be run directly.

Usage: python3 patch_menu.py <path_to_menu_view_file>
"""

import re
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 patch_menu.py <menu_view_file>")
        sys.exit(1)

    menu_file = sys.argv[1]

    with open(menu_file, "r") as f:
        content = f.read()

    # Already patched?
    if "LegacyMainMenuView" in content or "Legacy Encryption" in content:
        print("  Already patched — skipping")
        sys.exit(0)

    patched = False

    # --- Add import ---
    import_line = "from seedsigner.views.legacy_views import LegacyMainMenuView"
    last_import = 0
    for m in re.finditer(
        r"^(from seedsigner|import seedsigner).*$", content, re.MULTILINE
    ):
        last_import = m.end()

    if last_import > 0:
        content = content[:last_import] + "\n" + import_line + content[last_import:]
    else:
        content = import_line + "\n" + content

    # --- Add menu button after "Tools" entry ---
    button_patterns = [
        r'(\(\s*"Tools"[^)]*\)\s*,)',
        r'("Tools"\s*,)',
    ]
    for pattern in button_patterns:
        match = re.search(pattern, content)
        if match:
            insert_pos = match.end()
            new_entry = '\n            ("Legacy Encryption", FontAwesomeIconConstants.LOCK),'
            content = content[:insert_pos] + new_entry + content[insert_pos:]

            # --- Add selection handler after Tools handler ---
            handler_pattern = r'(if\s+.*["\']Tools["\'].*:.*\n\s+return\s+Destination\([^)]+\))'
            hmatch = re.search(handler_pattern, content)
            if hmatch:
                handler_pos = hmatch.end()
                new_handler = (
                    "\n\n"
                    '        if button_data[selected_menu_num] == "Legacy Encryption":\n'
                    "            return Destination(LegacyMainMenuView)"
                )
                content = content[:handler_pos] + new_handler + content[handler_pos:]
                patched = True
            break

    if patched:
        with open(menu_file, "w") as f:
            f.write(content)
        print("  Main menu patched successfully")
    else:
        print("  Could not auto-patch menu — see INTEGRATION.md for manual instructions")
        sys.exit(1)


if __name__ == "__main__":
    main()
