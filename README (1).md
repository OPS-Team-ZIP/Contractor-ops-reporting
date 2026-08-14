# Password gate for the Ops reporting dashboard

Wraps a self-contained HTML report in a password screen. The published file
contains **only ciphertext** — 8 KB of gate UI plus an encrypted blob. The
readable report is never committed, so the repo can be public without exposing
the report.

- **KDF:** PBKDF2-SHA256, 600,000 iterations (OWASP 2023 guidance)
- **Cipher:** AES-256-GCM, random 16-byte salt and 12-byte IV per build
- **Decryption:** in the browser via WebCrypto. No server, no build step at runtime.

Because GCM is authenticated, a wrong password *fails* rather than rendering
garbage. Unlock costs ~0.3–1s of key derivation, which is intentional.

## Layout

```
source/dashboard.html    the readable report — NEVER commit this
tools/encrypt.js         the encryptor
tools/gate-template.html the gate page (edit styling here)
dist/index.html          what you publish
.gitignore               keeps source/ out of git
```

## Build

```bash
GATE_PASSWORD='<the shared password>' node tools/encrypt.js \
  --in  source/dashboard.html \
  --out dist/index.html \
  --title "H1 2026 Executive Summary"
```

Pass the password by environment variable, not as an argument — arguments land
in your shell history. The script verifies it can decrypt its own output before
writing, so a corrupt build never ships.

Options: `--title` (the text shown on the gate), `--iterations` (default
600000), `--template`.

## Publish

Copy `dist/index.html` to the repo root and push. GitHub Pages serves it over
https, which WebCrypto requires.

To test locally, `crypto.subtle` needs a secure context — opening the file
directly via `file://` will not work:

```bash
cd dist && python3 -m http.server 8000   # then visit localhost:8000
```

## Changing the password or updating the report

Re-run the build and push the new `dist/index.html`. Every build uses a fresh
salt and IV, so the old ciphertext is unrelated to the new one.

One caveat: **git history is forever.** If you push a build encrypted with
password A and later switch to password B, anyone who clones the repo can check
out the old commit and open it with A. If you need a rotation to actually
revoke access, rewrite history (`git filter-repo`) or start a fresh repo.

## What this does and doesn't protect against

**It does protect against:** search engines, casual link-sharing, and anyone who
browses or clones the repo. Without the password they get ciphertext, and no
amount of reading the page source changes that. This is real encryption, not a
JavaScript `if (password === ...)` check that can be bypassed by opening
DevTools.

**The limit is password strength.** Anyone who has the ciphertext can guess
offline at their own pace. At 600k iterations a high-end GPU manages roughly
15–20k guesses/second, so a *random* 10-character password is far out of reach.
The realistic risk is a targeted guess. A short password built from
predictable, company-flavoured tokens is exactly what a hand-built wordlist
finds; a 4–5 word passphrase removes that risk entirely and is no harder to
paste into Slack. Never record the password in this repo.

**Two other things worth knowing:**

- Once someone unlocks the page, the decrypted report is in their browser and
  they can save it. A gate controls access, not redistribution.
- Everyone shares one password, so there's no audit trail and no per-person
  revocation.

**If the report contains anything you'd not want outside Zip, make the repo
private instead.** That's free, it removes the offline-guessing problem
completely, and you get per-person access and an audit trail. Encryption on a
public repo is the right tool when you need to hand a link to people who don't
have GitHub accounts — it is a weaker choice than private hosting, not a
stronger one. For internal-only readers, Pages on a private repo (or Zip's
normal internal hosting) beats this.
