# Bitcoin Beach Podcast — Legacy Encryption Live Demo

**Host:** Mike Peterson · **Format:** live full round trip (encrypt → capture → decrypt)
**Flow proven:** SeedSigner screen → Photo Booth (laptop webcam) → display QR full-screen → SeedSigner scans laptop. No phone, no printer. ~1 min when smooth.

---

## T‑30 min — pre-show checklist
- [ ] Card flashed from the **fixed** image, SeedSigner booted, sitting on **Tools** menu
- [ ] Did a full dry-run round trip in the **last hour** — it worked
- [ ] Photo Booth open and tested; you know how to snap + view the photo full-screen
- [ ] Preview/browser ready to show the captured QR **large** (fills the screen, white border around it)
- [ ] Laptop brightness **max**, auto-brightness **off**, screen wiped (no glare on the QR)
- [ ] No glare on the SeedSigner screen either — angle it before you start
- [ ] Demo seed + both keys written on a card in front of you
- [ ] **FALLBACK ASSETS** ready (see bottom): pre-recorded clean run in a tab + a pre-captured known-good encrypted QR saved, ready to open full-screen
- [ ] Laptop notifications **off** (Do Not Disturb), phone on silent

## Demo assets (throwaway — say so on air)
- **Seed:** `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
  *(the canonical BIP‑39 test vector — recognizable as a non-real seed; reinforces "never use a real seed in a demo")*
- **Benefactor key:** `bitcoin`
- **Beneficiary key:** `beach`
  *(short, all-lowercase = fast and error-free on the SeedSigner keypad, and on-brand for the show. Note out loud: real keys must be long & strong — these are demo-easy on purpose.)*

---

## The run — DO (left) / SAY (right)

### Part 1 — Encrypt (the setup)
**DO:** Tools → Legacy Encryption → **Encrypt** → **Enter Manually** → type the 12 words (autocomplete: `aban`→abandon, `abou`→about) → **Benefactor key** `bitcoin` → **Beneficiary key** `beach` → **Confirm**.
**SAY:** "This is the inheritance scenario. I'm the benefactor; my heir is the beneficiary. The seed gets encrypted **twice** — once with my key, once with theirs. Neither of us alone can ever recover it." → while the `Encrypting… Ns` counter ticks: "That counter is the device doing 600,000 rounds of key-stretching, twice, on a single CPU core — the wait is the security."

### Part 2 — Capture (the air-gap money shot)
**DO:** SeedSigner shows the encrypted QR → snap it with **Photo Booth** → open the photo **full-screen** on the laptop.
**SAY:** "Watch — the device never touched the internet. It only ever emits light and reads light; no bytes cross a wire in or out. And this QR is **public ciphertext** — I could post it on Twitter right now and it's useless without both keys."

### Part 3 — Decrypt (the payoff)
**DO:** SeedSigner → back to menu → **Decrypt** → point camera at the laptop's QR → hold steady ~arm's length → both keys (`bitcoin`, then `beach`) → `Decrypting… Ns` → seed reappears.
**SAY:** "Now I scan that public QR back in, supply **both** keys in order — and there's my original seed. Benefactor's key alone: nothing. Beneficiary's key alone: nothing. Both, together: inheritance unlocked."

---

## If something wobbles (calm cues — never narrate panic)
- **Scan won't lock in ~10s:** pull the device back slightly, steady your hand, make the QR bigger on screen / raise brightness. Still failing → "Let me pull up one I prepared earlier" → open the **pre-captured known-good QR** full-screen and scan that. Identical math; audience can't tell.
- **Hard freeze (shouldn't happen on the fixed card):** "These run on a $15 chip — quick reboot." Power-cycle is ~5s. Or cut to the **pre-recorded run**.
- **"Wrong key" error:** that's the feature working. "See — wrong key, no seed. That's exactly the point." Re-enter correctly.
- **Golden rule:** if you're 20+ seconds into any stall, switch to the recording/known-good asset. A smooth recorded finish beats a live struggle every time.

## Timing reality
Smooth = ~1 min. The two PBKDF2 counters are your built-in talking windows — fill them with the "why this matters" story, not silence.

---

# Q&A — likely questions + tight answers

**Spine to memorize:** *Advanced* Encryption Standard, 256-bit, **one** AES-256-GCM pass on a key that's **two keys combined**, each rinsed through **600,000 rounds** of PBKDF2 (key-stretching). Public QR holds only **salt, nonce, ciphertext** — never a key.

### "How does the encryption actually work?"
> "Both keys are joined and rinsed together through 600,000 rounds of PBKDF2 — key-stretching, technically — into a single AES-256 key, and the seed is encrypted once with AES-256-GCM. Miss either key, or get the order wrong, and you can't reproduce that key, so you can't decrypt. The public QR has nothing but salt, nonce, and ciphertext — the keys never leave your head."
*(Do NOT say "two layers" or "nested" — it's two keys combined into one password, a single encryption pass.)*

### "How is that reversible after 600,000 rounds of SHA?"
> "The hashing never touches the seed — it only turns your keys into the encryption key, and that's deterministic: same keys in, same key out, every time. The seed itself is encrypted with AES, which *is* reversible — but only with that derived key. The 600,000 rounds aren't there to be undone; they're there to make *guessing* your key 600,000 times more expensive."

### "What would it take to crack this?"
> "Nobody breaks the AES — that's mathematically out of reach. They'd have to guess your key, and every guess costs them 600,000 rounds of hashing. With a strong passphrase that's millions of years on the best hardware on earth. The math is bulletproof; the only real job is choosing keys that aren't guessable — and keeping them in two different people's heads."
*Backup detail if pressed:* even a 1,000-GPU rig does ~15M guesses/sec against this; a single dictionary word falls in seconds, but 6 random words outlasts the age of the universe. The 600k rounds add ~19 bits of strength — your key supplies the rest.

### "Isn't it weak that your demo keys are so short?"
> "For the demo, yes — `bitcoin`/`beach` would crack in seconds, on purpose, so we're not waiting around. In real use each key is a long passphrase. And here's the subtle part: because the keys combine, if one person's key ever leaks, the *other* key alone is carrying all the security — so each key has to be independently strong. 'Two keys' isn't 'double safe' by default; it's 'two strong secrets, two people.'"

### "Is it really safe to post the encrypted QR publicly?"
> "Completely. That QR is ciphertext — without both keys it's noise. The whole design assumes it's public: print it, engrave it, put it in your will, post it on Twitter. The security is in the two keys held by two people, not in hiding the QR. That's what makes it an *inheritance* tool instead of just another thing to lose."

### "What if a key is lost?"
> "Then the seed is gone — by design. There's no backdoor, no recovery service, no 'forgot password.' That's the trade-off for having no company in the middle: you and your heir are the only two points of failure, and the only two points of trust. So the real-world advice is to back up each key the same way you'd back up anything irreplaceable — and ideally the benefactor briefs the beneficiary ahead of time."

### "Why two keys instead of one password?"
> "Because inheritance is a two-party problem. One password means one person can act alone — and one person can lose it alone. Two keys means neither the benefactor nor the beneficiary can move the coins by themselves while you're alive, and it splits the responsibility. It's a human-trust model expressed in cryptography."

### "What actually happens when you die — how does the heir use this?"
> "While you're alive, nobody can decrypt it — you each hold one key. When you pass, your heir already has their key and gets access to yours (through your estate, a lawyer, a letter, however you arrange it), scans the public encrypted QR, enters both keys, and the seed comes back. No third party, no custodian, no court needs to be in the loop with the actual coins."

### "Is AES American / could it be backdoored?"
> "AES is *Advanced* Encryption Standard, not American — the algorithm's actually Belgian-designed, then adopted as the U.S. standard through an open public competition in 2001. It's the most analyzed cipher on earth and protects classified data worldwide. Same with the code here: it's open-source and runs entirely on an air-gapped device, so there's nothing to trust on faith — you can read every line."

### "Why not just use multisig / a hardware wallet's built-in tools?"
> "Different job. Multisig is great for *spending* security; this is for *inheritance* — getting a seed to a specific person, later, without a custodian and without either party being able to act alone today. It's complementary: you can absolutely put a multisig seed through this."

### Hard-question escape hatch (use without shame)
> "Happy to nerd out on the cryptography after the show — but the part that matters for everyone listening is dead simple: two keys, two people, and neither one can do it alone."
