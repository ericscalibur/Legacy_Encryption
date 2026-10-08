SeedSigner firmware with **Legacy Encryption** — dual-key seed phrase
encryption and decryption on a fully air-gapped device.

Based on upstream SeedSigner **0.8.6**, plus Legacy Encryption
(fork commit `04c9978`, matching Legacy_Encryption `e823d09`).

**New to this? Follow the step-by-step setup guide:
https://ericscalibur.github.io/Legacy_Encryption/seedsigner.html** — it covers
the hardware, checking the download, and flashing with a graphical app
(balenaEtcher or Raspberry Pi Imager) instead of the terminal.

## If you were sent here by a Deploy message

You can decrypt the seed phrase you received without it ever touching a
computer. That requires the hardware below. If you do not have it, you can
instead decrypt in a browser using the Legacy Decryption tool linked in the
message you received — prefer its downloadable offline version, on a
computer you can erase afterwards.

## Hardware required

- Raspberry Pi Zero **v1.3** — *not* the W. The W has WiFi; the point of
  this device is that it has no networking hardware at all.
- Waveshare 1.3" 240×240 LCD HAT (joystick + buttons)
- OV5647 camera module (Pi Zero ribbon version)
- MicroSD card, 4 GB or larger

## Verify before flashing

```bash
# Checksum (macOS: shasum -a 256 -c ...)
sha256sum -c seedsigner_os.legacy-encryption.pi0.img.gz.sha256

# Signature: import the signing key attached to this release, then verify
gpg --import legacy-signing-key.asc
gpg --verify seedsigner_os.legacy-encryption.pi0.img.gz.asc \
            seedsigner_os.legacy-encryption.pi0.img.gz
```

Signing key fingerprint:

```
F367D8D8 778504D9 DDAFAD9F B7E466E3 2305FE1B
```

Both checks must pass. If the signature does not verify, do not flash it.

## Flash

**Recommended:** balenaEtcher or Raspberry Pi Imager ("Use custom"), which
write the `.img.gz` directly, verify the write, and only offer removable
drives. In Raspberry Pi Imager, answer **No** to OS customisation.

From a terminal instead:

```bash
gunzip seedsigner_os.legacy-encryption.pi0.img.gz

# macOS — confirm the disk number first with: diskutil list
diskutil unmountDisk /dev/diskN
sudo dd if=seedsigner_os.legacy-encryption.pi0.img of=/dev/rdiskN bs=4m
diskutil eject /dev/diskN

# Linux — confirm the device first with: lsblk
sudo dd if=seedsigner_os.legacy-encryption.pi0.img of=/dev/sdX bs=4M status=progress
sync
```

`dd` overwrites the target completely. Check the device name twice.

## Decrypting a seed phrase

1. Boot the device and choose **Tools → Legacy Encryption → Decrypt Seed Phrase**
2. Scan the encrypted QR code
3. Enter the **benefactor key**, then the **beneficiary key**
4. The recovered seed words appear on the device screen
5. Optionally export as a SeedQR for a signing device

Both keys are required; neither alone decrypts anything. Decryption takes
10–30 seconds on a Pi Zero — that delay is the PBKDF2 work factor, and it is
deliberate.

## Notes

- Runs entirely from RAM after boot. You can remove the microSD once the
  splash screen appears; powering off erases all state.
- Final Legacy format (see `PROTOCOL-SPEC.md`). Payloads carry no marker:
  they look like random data. Payloads from earlier test builds (including
  `LE2.`-prefixed ones) are no longer accepted.
- When encrypting, each key is entered twice and must match, and the device
  decrypts its own output before showing the QR.
- Output is byte-compatible with `Legacy-offline.html`, so a payload can be
  encrypted on the device and decrypted in the browser, or the reverse.
- This firmware removes SD-card logging and keeps secrets in a single
  session cleared at flow boundaries. Do not use builds predating `04c9978`:
  earlier builds cannot read the final payload format.
