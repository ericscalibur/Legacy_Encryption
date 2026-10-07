# Legacy Encryption → SeedSigner Integration Guide

## What This Is

A port of the Legacy Encryption dual-key seed phrase encryption system to run on SeedSigner hardware (Raspberry Pi Zero + camera + LCD + buttons). Fully air-gapped. The Python crypto module produces output that is byte-compatible with the browser version (Legacy-offline.html) — encrypt on SeedSigner, decrypt in the browser, or vice versa.

## Hardware You Need

- Raspberry Pi Zero v1.3 (**not** the W — no WiFi for true air-gap)
- Waveshare 1.3" 240×240 LCD HAT (includes joystick + 3 buttons)
- OV5647 camera module (Pi Zero ribbon cable version)
- MicroSD card (4GB minimum)
- USB micro power cable

Total cost: ~$50

## Repository Structure

```
seedsigner-port/
├── legacy_encryption.py          # Core crypto module (standalone, no SeedSigner deps)
├── test_cross_compat.py          # Test suite (Python ↔ Node.js cross-compat)
├── views/
│   └── legacy_views.py           # SeedSigner View classes for the UI flow
└── INTEGRATION.md                # This file
```

## Step-by-Step Integration

### 1. Fork SeedSigner

```bash
git clone https://github.com/SeedSigner/seedsigner.git
cd seedsigner
git checkout -b legacy-encryption
```

### 2. Install the Crypto Module

Copy `legacy_encryption.py` into SeedSigner's helpers directory:

```bash
cp legacy_encryption.py src/seedsigner/helpers/legacy_encryption.py
```

The module depends on the `cryptography` Python package, which SeedSigner's Buildroot image already includes (it's used for PSBT signing). If building from source you may need to add it to the Buildroot config.

### 3. Install the Views

Copy the view file:

```bash
cp views/legacy_views.py src/seedsigner/views/legacy_views.py
```

### 4. Wire Into the Tools Menu

Edit `src/seedsigner/views/tools_views.py` — the entry goes in the **Tools**
menu, not the main menu. See the warning below for why.

Add the button option to `ToolsMenuView`:

```python
from seedsigner.views.legacy_views import LegacyMainMenuView

    LEGACY = ButtonOption("Legacy Encryption", FontAwesomeIconConstants.LOCK)
```

Add it to the button list:

```python
button_data = [self.IMAGE, self.DICE, self.KEYBOARD, self.ADDRESS_EXPLORER, self.VERIFY_ADDRESS, self.LEGACY]
```

And handle the selection:

```python
        elif button_data[selected_menu_num] == self.LEGACY:
            return Destination(LegacyMainMenuView)
```

`build.sh` does exactly this automatically via `patch_menu.py`; the steps
above are only needed if you are patching by hand.

> **Do not add the entry to the main menu.** `MainMenuView` renders through
> `MainMenuScreen`, which extends `LargeButtonScreen` — a fixed 2×2 grid with
> no pagination. Its `__post_init__` raises
> `"LargeButtonScreen only supports 2 or 4 buttons"` on any other count, and
> `MainMenuScreen` does not override it. The main menu already has four
> entries (Scan, Seeds, Tools, Settings), so adding a fifth means the
> controller catches that exception and the device boots to an error screen
> instead of a menu. Released images are built by `build.sh` and are not
> affected.

Resulting path on the device: **Tools → Legacy Encryption → Decrypt Seed
Phrase**.

### 5. Ensure BIP-39 Wordlist Is Accessible

The crypto module looks for `english.txt` (one word per line, 2048 words). SeedSigner already bundles this. Verify the path in `legacy_encryption.py` matches your fork's wordlist location, or create a symlink:

```bash
ln -s src/seedsigner/resources/english.txt src/seedsigner/helpers/english.txt
```

### 6. Build the OS Image

Follow SeedSigner's build process:

```bash
# Clone the OS builder
git clone https://github.com/SeedSigner/seedsigner-os.git
cd seedsigner-os

# Point it at your fork (edit the config to use your repo URL + branch)
# Then build via Docker:
docker build -t seedsigner-os-builder .
docker run --rm -v $(pwd)/output:/output seedsigner-os-builder
```

The output is a `.img` file you flash to microSD.

### 7. Flash and Boot

```bash
# On macOS:
diskutil list                          # find your SD card (e.g., /dev/disk4)
diskutil unmountDisk /dev/disk4
sudo dd if=output/seedsigner.img of=/dev/rdisk4 bs=4m
diskutil eject /dev/disk4

# On Linux:
sudo dd if=output/seedsigner.img of=/dev/sdX bs=4M status=progress
sync
```

Insert the microSD into the Pi Zero, power on, and "Legacy Encryption" appears in the **Tools** menu.

## User Flow

### Encrypting a Seed Phrase

1. Boot SeedSigner → **Tools** → **Legacy Encryption** → **Encrypt Seed Phrase**
2. Scan your seed phrase as a SeedQR (use another device to generate the SeedQR, or use SeedSigner's built-in seed tools first)
3. Enter the **benefactor key** using the on-screen keyboard (joystick to navigate, button to select characters)
4. Enter the **beneficiary key**
5. Confirm → device shows "Encrypting..." for ~15-30 seconds (PBKDF2 on Pi Zero)
6. A QR code appears on screen containing the encrypted payload
7. Photograph the QR with your phone — this is your encrypted backup
8. The encrypted QR can be decrypted with Legacy-offline.html in any browser, or on another SeedSigner running this firmware

### Decrypting

1. Boot → **Tools** → **Legacy Encryption** → **Decrypt Seed Phrase**
2. Scan the encrypted QR code
3. Enter benefactor key, then beneficiary key
4. Device decrypts and shows the recovered seed words on screen
5. Option to export as SeedQR for loading into a signing device

## Performance Notes

- **PBKDF2 at 600K iterations on Pi Zero 1.3**: expect 10-30 seconds per operation. This is by design — the high iteration count is what makes brute-force attacks infeasible. A loading screen is shown during this time.
- **Memory**: The Pi Zero has 512MB RAM. The encryption module uses negligible memory beyond the crypto library itself.
- **After boot**: SeedSigner runs entirely from RAM. You can remove the microSD card after the splash screen appears — the device is fully air-gapped with no persistent storage.

## Security Model

- **Air-gapped**: Pi Zero 1.3 has no WiFi, Bluetooth, or networking hardware
- **No persistent storage**: Runs from RAM after boot; removing power erases all state
- **Dual-key**: Both the benefactor and beneficiary passwords are required — neither alone can decrypt
- **Compatible**: Encrypted output works with Legacy-offline.html in any browser
- **Auditable**: All crypto operations use standard primitives (PBKDF2-SHA256 + AES-256-GCM) from the well-audited `cryptography` library

## Testing Without Hardware

You can test the crypto module on any machine with Python 3.10+:

```bash
pip install cryptography
python legacy_encryption.py           # Quick smoke test
python test_cross_compat.py           # Full test suite (needs Node.js for cross-compat)
```

## Customization Ideas

- **Iteration count**: fixed at 600,000 by the format (payloads carry no parameters), so it cannot be made configurable without breaking compatibility.
- **Direct seed entry**: Add a word-by-word BIP-39 entry flow instead of requiring SeedQR scan
- **Multiple encryption layers**: Encrypt once for storage, scan back to encrypt again with different keys
- **Compact QR**: Use SeedSigner's compact SeedQR encoding for smaller QR codes
