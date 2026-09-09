# Fixtures — App A baseline + RP harness

**Requires an Apple Developer account.** Unlike `aaoracled`/`OracledDCPatch`
itself (which needs no app install, no Apple ID sign-in, and no developer
account at all), App A here is signed with a genuine Apple Development
identity and a real provisioning profile, because its entire purpose is to
demonstrate the *legitimate, unforged* control case — see step 3 below.
Skip this whole directory if you only want to run aaoracled.

Two pieces that establish the **Row A control** (a genuine, legitimately
provisioned App Attest round trip) before any oracle/forgery work:

- `harness/` — the relying-party server: hands out challenges, validates
  attestations against Apple's App Attest Root CA, validates assertions.
- `appa/` — a minimal theos ObjC app (bundle id `xyz.regulad.oracled.appone`)
  that runs `generateKey → attestKey → generateAssertion` against the harness.

The device talks to the harness over an **SSH reverse tunnel** — the harness
stays bound to the laptop's loopback and is never exposed on the network.

## 1. Start the harness (laptop)

```bash
uv run fixtures/harness/server.py      # resolves cbor2 + cryptography via PEP-723
# listens on http://127.0.0.1:8080
```

Config via env: `ORACLED_PORT`, `ORACLED_APP_ID`, `ORACLED_ENV`
(default expects `67QDNMUGFA.xyz.regulad.oracled.appone`, `development`).
It is strict on chain/nonce/keyId (proves a genuine SEP key) and reports the
observed `rpIdHash` / `app_id` / `aaguid` (the M3.5 detection surface).

## 2. Open the reverse tunnel (device → laptop harness)

```bash
ssh -R 8080:127.0.0.1:8080 <device-alias>
# now http://127.0.0.1:8080 ON THE DEVICE reaches the laptop harness
```

## 3. Build + sign App A

On Linux/macOS, run the script directly. On Windows, run it inside WSL (see
`SETUP.md` step 9 for the generic build toolchain setup):

```bash
wsl -d <your-distro> -e bash -lc '/mnt/c/path/to/oracled/fixtures/appa/build_and_sign.sh'
```

This builds `appa.app` with theos, embeds `artifacts/appone.mobileprovision`,
signs with the genuine Apple Development identity via `rcodesign` (theos'
ldid pseudo-signing is disabled — App Attest needs the real team signature),
and packages `fixtures/appa/build/appa.ipa`.

## 4. Install + run

```bash
ios install --path=fixtures/appa/build/appa.ipa      # go-ios over USB
# or open appa.ipa in TrollStore on the device
```

Launch appa; it auto-runs on start (and via the "Run App Attest" button).
Watch the harness log — a genuine Row A result looks like:

```
ATTEST keyId=... genuine=True app_id=67QDNMUGFA.xyz.regulad.oracled.appone rp_match=True
ASSERT keyId=... ok=True counter=1
```

That confirmed baseline is the control the M3 oracle and the M3.5 A–E matrix
build on.

## Notes

- WSL commands must use a **login shell** (`bash -lc`): the profile sets the
  ssh-agent socket and puts `rcodesign`/theos on PATH.
- `artifacts/` (cert, key, profiles, `.p12`) is gitignored — never commit it.
