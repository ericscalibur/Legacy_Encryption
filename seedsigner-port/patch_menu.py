#!/usr/bin/env python3
"""
Patches SeedSigner's Tools menu to add a Legacy Encryption entry.
Called by build.sh — not meant to be run directly.

Usage: python3 patch_menu.py <path_to_tools_views_file>
"""

import re
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 patch_menu.py <tools_views_file>")
        sys.exit(1)

    menu_file = sys.argv[1]

    with open(menu_file, "r") as f:
        content = f.read()

    # Already patched?
    if "LegacyMainMenuView" in content or "Legacy Encryption" in content:
        print("  Already patched — skipping")
        sys.exit(0)

    patched = False

    # ------------------------------------------------------------------ #
    # ToolsMenuView uses ButtonOption class-constants (SeedSigner >= 0.8) #
    # Look for VERIFY_ADDRESS and insert LEGACY after it.                 #
    # ------------------------------------------------------------------ #
    verify_const_pattern = re.compile(
        r'(VERIFY_ADDRESS\s*=\s*ButtonOption\([^\)]+\))'
    )
    m = verify_const_pattern.search(content)
    if m:
        # 1. Add LEGACY constant after VERIFY_ADDRESS constant
        legacy_const = '\n    LEGACY = ButtonOption("Legacy Encryption", FontAwesomeIconConstants.LOCK)'
        content = content[:m.end()] + legacy_const + content[m.end():]

        # 2. Add self.LEGACY to button_data list
        btn_data_pattern = re.compile(
            r'(button_data\s*=\s*\[[^\]]+\])'
        )
        bm = btn_data_pattern.search(content)
        if bm:
            old_list = bm.group(1)
            new_list = old_list.rstrip(']') + ', self.LEGACY]'
            content = content[:bm.start()] + new_list + content[bm.end():]

        # 3. Add handler after the VERIFY_ADDRESS elif block
        handler_pattern = re.compile(
            r'(elif\s+button_data\[selected_menu_num\]\s*==\s*self\.VERIFY_ADDRESS\s*:.*?'
            r'return\s+Destination\([^\)]+\))',
            re.DOTALL
        )
        hm = handler_pattern.search(content)
        if hm:
            new_handler = (
                "\n\n"
                "        elif button_data[selected_menu_num] == self.LEGACY:\n"
                "            return Destination(LegacyMainMenuView)"
            )
            content = content[:hm.end()] + new_handler + content[hm.end():]
            patched = True

    if not patched:
        print("  Could not auto-patch Tools menu — see INTEGRATION.md for manual instructions")
        sys.exit(1)

    # Add LegacyMainMenuView import
    import_line = "from seedsigner.views.legacy_views import LegacyMainMenuView"
    last_import = 0
    for mo in re.finditer(r"^(from seedsigner|import seedsigner).*$", content, re.MULTILINE):
        last_import = mo.end()

    if last_import > 0:
        content = content[:last_import] + "\n" + import_line + content[last_import:]
    else:
        content = import_line + "\n" + content

    with open(menu_file, "w") as f:
        f.write(content)
    print("  Tools menu patched successfully")


if __name__ == "__main__":
    main()
