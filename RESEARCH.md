# RESEARCH.md — App Attest wire and certificate analysis

Findings from direct observation of Apple's App Attest registration flow on
a jailbroken device, via `aaoracled` + Frida. This file records *measured
results* and the exact conditions they were measured under. Methodology that
is reusable lives in `AGENTS.md`; the project's thesis and mitigation
guidance live in `README.md`.

**All data in this document was collected on 2026-10-10.** That date is
load-bearing — see "Dating caveat" under finding 2.

## Collection environment

| | |
|---|---|
| Device | iPad mini 4, `iPad5,1`, A8 / `T7000` |
| OS | iPadOS 15.8.8, build `19H422` (`Darwin Kernel 21.6.0`, `xnu-8020.241.44~1`) |
| Jailbreak | roothide; jbroot `/var/containers/Bundle/Application/.jbroot-7C5E5CFEA302A584` |
| Installed | `xyz.regulad.aaoracled` 0.2.0 (`ii`) |
| Device serial | `F9FWTPQ3GHKJ` |
| ECID | `607025087643686` (`0x000228160AB80026`) |
| Identity used | `67QDNMUGFA.xyz.regulad.oracled.apptwo` (App B) |
| Host | Windows 11; `frida-tools` 16.7.0; `frida-server` at `/usr/sbin/frida-server` |
| Transport | `ssh -L 27042` (frida) and `ssh -L 8181` (aaoracled REST) |

Device started the session with **zero** App Attest keys resident. Every key
analysed below was minted during this session under Parker's own team and
bundle IDs. Nothing produced here was sent to any relying party other than
the local harness.

## 1. The public `DeviceCheck` API surface

Taken from the theos iPhoneOS16.5 SDK, not from the device — see AGENTS.md
"Reading the DeviceCheck SDK surface" for the method. Recorded here because
it bounds what a stub framework must implement.

`DeviceCheck.tbd` exports **five** ObjC classes and **two** error domains:

- `_DCErrorDomain`, `_DCBAASignerErrorDomain`
- `DCAppAttestService`, `DCContext`, `DCDevice`,
  `DCDeviceMetadataDaemonConnection`, `DCDeviceMetadataInterface`

Only `DCAppAttestService`, `DCDevice` and `DCErrorDomain` are declared in
headers. The other three classes and `_DCBAASignerErrorDomain` are linkable
but undeclared; the SDK carries no code for them, so characterizing them
requires the on-device binary out of the dyld shared cache.

`DCError` is an `NS_ERROR_ENUM`, so its codes are implicitly 0-based in
declaration order: `UnknownSystemFailure` 0, `FeatureUnsupported` 1,
`InvalidInput` 2, `InvalidKey` 3, `ServerUnavailable` 4.

Two documented behaviours worth recording because the current REST contract
contradicts the first:

- `attestKey:` operates on a key "you previously generated", and on
  `DCErrorServerUnavailable` the header instructs retrying "using the same
  key and client data hash later ... Retrying with the same inputs helps to
  preserve the risk metric for a given device." Delayed attestation of an
  already-minted key is therefore the documented flow, not an edge case.
- `DCErrorInvalidKey` is documented for attesting an already-attested key
  *and* for asserting with an unattested one.

## 2. The credCert leaf carries an undocumented OS version field

Two keys were minted and their attestation objects fully decoded — one
development, one production, otherwise identical inputs.

Extensions present on the **x5c leaf** (the credCert), identical in both
environments:

| OID | Size | Contents |
|---|---|---|
| `2.5.29.19` | — | `BasicConstraints ca=False` |
| `2.5.29.15` | — | `KeyUsage` |
| `2.5.29.37` | — | `ExtendedKeyUsage [1.2.840.113635.100.4.24]` |
| `1.2.840.113635.100.8.5` | 118 B | the App ID string |
| `1.2.840.113635.100.8.7` | 50 B | **device metadata — see below** |
| `1.2.840.113635.100.8.2` | 38 B | the challenge nonce |

Extension `1.2.840.113635.100.8.7`, decoded from DER by hand:

```
SEQUENCE (48 bytes)
  [1400] OCTET STRING  "15.8.8"            <- the device's exact OS version
  [1104] INTEGER       0x00FFFFFFFF  (4294967295)
  [1401] OCTET STRING  "1.0.248"           <- unidentified; see finding 6
  [1404] OCTET STRING  (empty)
  [1405] OCTET STRING  (empty)
```

`15.8.8` is this device's exact OS version, matching build `19H422`. The two
empty fields and the all-ones integer suggest the extension has a wider
schema than this device/OS populates.

Per-sample detail:

| | development | production |
|---|---|---|
| `keyId` | `AyiKfDNaC+7s9b9MvDiGHxeWvMfbNPuEZVvuBp5Hd9E=` | `Yk4DZqM8vPrRBq9iv5UjwbDlx8KoqKxbxEUA/EXi58Y=` |
| `aaguid` | `appattestdevelop` | `appattest` + 7 NULs |
| cert validity | 2026-10-09T21:04:14Z .. 2026-10-12T21:04:14Z | 2026-10-09T21:05:27Z .. 2026-10-12T21:05:27Z |
| `…8.7` strings | `15.8.8`, `1.0.248` | `15.8.8`, `1.0.248` |

So this is **not** a sandbox/development artifact; it is present in
production attestations too. Both strings also appear in the Apple-signed
receipt.

Independently verified on the same samples, with a **forged** App ID active:

- `rpIdHash == SHA256(appId)` — true, for the forged identity
- `credId == keyId` — true
- `keyId == base64(SHA256(uncompressed public key point))` — true
- `counter == 0`

### Consequence for `README.md`

`README.md` originally stated that App Attest keys carry "no device-specific
metadata — no OS version and no hardware model string," and built the
minimum-OS-floor argument on that. The OS version half is **false as
measured**: a version string is present in the leaf, in both environments.

Be careful about what that licenses. The claim this data supports is only
that **the field reports a version the minting device's hardware is capable
of running.** It does *not* establish that the field reflects the OS
actually running at attestation time, for two independent reasons:

1. **The device never sends it.** There is no software/OS version field
   anywhere in the registration request (finding 3 — `RKProperties` has 13
   keys and none of them is a version). So the value's provenance is
   outside anything this research decoded: Apple's own records for the
   unit, or the opaque `RKCertification` blob.
2. **The reference device sits on its terminal release.** `15.8.8` is the
   final iPadOS build shipped for `iPad5,1`. A single sample therefore
   cannot distinguish "the running OS" from "the newest OS this hardware
   supports" from "the newest OS Apple ever shipped for this model" —
   all three are `15.8.8` here. Rolling this device back to a much older
   release may still yield `15.8.8` in the certificate. Untested.

Consequently a relying-party check on this field raises a **hardware**
floor — it excludes units that cannot reach the required release, which is
exactly the sockpuppet case — but it has not been shown to detect a current
device downgraded to an old, vulnerable OS. See finding 5 for the separate
fail-open hazard.

The "no hardware model string" half still holds for what the relying party
receives — but see finding 4: Apple itself receives considerably more.

**Caveat on that mitigation:** see finding 5. `…8.7`'s presence is requested
by the device, so an RP check must treat a *missing* extension as failure or
it fails open.

### Dating caveat — why 2026-10-10 is recorded

A credential certificate is minted fresh by Apple's live CA during
`attestKey`; it is not read out of the device's OS image. The contents of
extension `…8.7` therefore reflect **Apple's CA behaviour on the date of
issuance**, and say nothing directly about the device's firmware vintage.

Every certificate analysed in this document was issued on **2026-10-10**.

This research establishes only that these fields are present on that date.
It does **not** establish when they first appeared, and no attestation
object predating 2026-10-10 was available in this repository to compare
against. Prior inspection of leaf certificates in this project did not
record these fields, and the repo's own verifier
(`fixtures/harness/server.py`) parses only the nonce extension `…8.2` — it
never reads `…8.5` or `…8.7` — so their absence from earlier notes is
equally consistent with their not having been looked for.

The decisive test, if the timeline ever matters: decode extension
`1.2.840.113635.100.8.7` out of any archived attestation object issued
before this date. A single older sample settles it. None is currently held.

`README.md` records that this research was disclosed to Apple as Security
Research submission `#OE1107928141015`, and that the submission was allowed
to close before publication. **No causal relationship between that
submission and the presence of these fields is established or claimed
here.** The date is recorded so that the question remains answerable.

## 3. Anatomy of the registration request

Captured from inside `devicecheckd` by hooking Network.framework
(`nw_connection_send`), with `dispatch_data_create_map` to read the payload.
`devicecheckd` makes the connection itself — confirmed by `getaddrinfo` for:

```
register-development.appattest.apple.com      (development)
```

The production endpoint was not captured; by symmetry it is presumably
`register.appattest.apple.com`, but that is unverified.

Transport is JSON over HTTP/2. Send sequence per attestation: 258 B
(headers), **4782 B (the JSON body)**, 9 B, 17 B, then a NULL content send.

Top-level JSON, seven fields:

| Field | Value / content |
|---|---|
| `appID` | `67QDNMUGFA.xyz.regulad.oracled.apptwo` — plaintext, **forged** |
| `chipIDECID` | base64 of `00007000-000228160AB80026` — ChipID + ECID |
| `authenticatorData` | base64; carries the AAGUID |
| `clientDataHash` | base64, 32 bytes |
| `environment` | `development` |
| `requestOrigin` | `appattestation` |
| `attUIKtoBIK` | base64 XML plist, below |

`attUIKtoBIK` decodes to a 3-key plist:

- `RKCertification` — 872 B DER, `SEQUENCE { INTEGER 2, SEQUENCE { … } }`
- `RKProperties` — 1134 B, itself an XML plist (below)
- `RKPropertiesSignature` — 71 B DER signature over `RKProperties`

`RKProperties`, 13 keys:

```
AppID               '67QDNMUGFA.xyz.regulad.oracled.apptwo'
BoardId             8
CACert              0
CertType            0
ChipID              28672                       (0x7000, T7000)
OIDSToInclude       ['1.2.840.113635.100.8.5',
                     '1.2.840.113635.100.8.7',
                     '1.2.840.113635.100.8.2']
RKCertificationPub  <65 bytes>                  (EC P-256 uncompressed point)
SIKPub              <65 bytes>                  (Secure Identity Key public)
SecurityDomain      1
SerialNumber        'F9FWTPQ3GHKJ'
UniqueChipID        607025087643686             (the ECID)
Validity            1440
scrtAttestation     0
```

Note the identifiers are formatted decimal/hex **strings inside two layers
of base64**, which is why byte-pattern searches for the raw integers over
the wire bytes find nothing. Search the decoded plists, not the wire.

## 4. Apple receives a per-unit hardware fingerprint; the RP does not

During one attestation, `devicecheckd` queries MobileGestalt for:

| Key | Value | Transmitted? |
|---|---|---|
| `UniqueChipID` | `607025087643686` | **yes** (twice) |
| `ChipID` | `28672` | **yes** (twice) |
| `SerialNumber` | `F9FWTPQ3GHKJ` | **yes** |
| `BoardId` | `8` | **yes** |
| `SecurityDomain` | `1` | **yes** |
| `HasPKA` | `false` | no |
| `s7nuHoZIYNoOHCqT9iyZkQ` | `false` | no |

Both untransmitted keys returned `false` and appear to drive local
branching. Everything else reaches Apple on every attestation.

Neither `IORegistryEntryCreateCFProperty` nor `sysctlbyname` contributed any
value that appears in the request.

So the asymmetry is: **Apple can identify the exact physical unit behind
every App Attest registration; the relying party cannot.** That is a
different statement from "App Attest carries no device metadata," and
`README.md` should distinguish RP-visible from Apple-visible.

## 5. The forgery enters signed data, and the device picks its own extensions

Two findings from the same structure, both consequential.

**The forgery propagates into signed data.** `RKProperties` contains
`AppID`, and `RKPropertiesSignature` covers `RKProperties`. The forged
identity is therefore not merely a plaintext JSON field Apple could
cross-check — it is inside the signed blob Apple validates, and Apple
issues a certificate for it regardless. This is the clearest direct
evidence yet of the project's central claim, observed on the wire rather
than inferred from the resulting certificate.

**The device chooses its own certificate extensions.** `OIDSToInclude` is a
request parameter naming exactly the three extensions that appear in the
issued leaf — including `…8.7`, the OS-version one. Since `AppID` in that
same signed blob is demonstrably forgeable by this tweak, the same
mechanism plausibly permits requesting that `…8.7` be **omitted**.

If that works, any relying-party minimum-OS check built on `…8.7` fails
open unless the RP treats a missing extension as a hard failure.

**This is untested.** It is the highest-value next experiment, and it must
be resolved before `README.md` recommends reading `…8.7` as a mitigation.

## 6. `1.0.248` is unidentified

Field `[1401]` of extension `…8.7`. Everything below is a negative result;
the value's meaning remains unknown.

Ruled out:

- **Not a string literal on the device.** `Memory.scanSync` across all
  **292** modules loaded in `devicecheckd` — zero hits. (`15.8.8` is absent
  too, as a control, confirming both are runtime-composed rather than
  stored.)
- **Not from the metadata providers.** `MGCopyAnswer`,
  `IORegistryEntryCreateCFProperty` and `sysctlbyname` hooked across a live
  attestation; no queried key returns it.
- **Not a framework bundle version.**
  `/System/Library/PrivateFrameworks/AppAttestInternal.framework/` does not
  exist on disk; on iOS 15 the frameworks live only in the dyld shared
  cache, so there is no `Info.plist` carrying a version.
- **Not in the IPSW.** `iPad_64bit_TouchID_15.8.8_19H422_Restore.ipsw`
  (5,046,203,202 bytes, ZIP64, 53 entries) was read via HTTP range requests
  — central directory first, then only the needed members, ~11 MB total
  instead of 5 GB. Searched `BuildManifest.plist` (574 KB),
  `Restore.plist`, and all four `sep-firmware.{j81,j82,j96,j97}.RELEASE.im4p`
  (2,724,094 bytes each, byte-identical sizes) for the ASCII string and the
  byte triple `01 00 f8`. No hits. `BuildManifest` component versions look
  nothing like it (`iBoot-7459.140.15~66`).
- **Not recoverable from SEP firmware.** The IM4P is type `sepi`; its
  description field is a hex-encoded nested IMG4 property set
  (`impl`, `arms=0`, `tz0s=0x00BD0000`), i.e. payload placement metadata,
  not a version. The 2,723,840-byte payload is encrypted — 116-byte KBAG
  trailer, 256/256 distinct byte values in the tail. So the IPSW negative
  is **not** evidence against a SEP-version hypothesis; the firmware is
  simply opaque without the device GID key.
- **Not transmitted by the device.** Searched every layer of the captured
  request — raw wire, outer plist, `RKCertification`, `RKProperties`,
  `RKPropertiesSignature`, `authenticatorData`, `SIKPub`,
  `RKCertificationPub` — for both strings as ASCII and as binary triples
  (`0f 08 08`, `01 00 f8`, and reversed forms). Zero hits anywhere.

**Inference, not a finding:** both `15.8.8` and `1.0.248` are composed
Apple-side. Apple can do this because the device hands over the ECID and
serial number (finding 4), so the CA can stamp values from its own records
for that specific unit.

This is an inference about *provenance only*. It does not tell us what
either value semantically refers to. In particular it does not establish
that `15.8.8` is the running OS rather than the maximum OS this hardware
supports — see the two confounds under finding 2. Do not upgrade this to
"Apple attests the device's OS version"; the data does not reach that.

**Caveat:** `RKCertification` is 872 bytes of nested DER parsed only one
level deep here. A version encoded in a non-obvious form could still be
inside it. "The device does not send it" is well-supported but not airtight.

**What would settle it:** one additional OS build or device model
discriminates in a single mint — if the value moves with the OS version it
is an OS-coupled component; if it tracks the SoC, SEP firmware; if constant
across both, a format or protocol version. Failing that, Ghidra on
`AppAttestInternal` to find what feeds tag `[1401]`.

## 7. A key can be attested more than once, contradicting `DCError.h`

`DCError.h` documents `DCErrorInvalidKey` as the result of calling
`attestKey:clientDataHash:completionHandler:` for "a key that's already been
attested". That is not what this device does.

Measured through aaoracled 0.3.0's split endpoints (which is what made the
test possible at all — the fused `POST /keys` always minted a fresh key, so
it could never re-attest one), development environment, App B:

1. `POST /keys` minted `ss4fYwJuq3g74AjvLxWNFyIzfDjFwoIG+ZFttnaGnlE=`.
2. `POST /keys/{keyId}/attest` → **HTTP 200**, valid attestation.
3. The same endpoint, same `keyId`, a *different* `clientDataHash` →
   **HTTP 200**, a second valid attestation.

The two are separate issuances over the same key, not a cached response: the
leaf certificates carry validity windows one second apart
(`261009230621Z`..`261012230621Z` versus `261009230622Z`..`261012230622Z`)
and differ from each other starting in the certificate serial field, while
sharing an identical subject CN —
`b2ce1f63026eab783be008ef2f158d1722337c38c5c28206f9916db676869e51`, which is
the hex of that same keyId. Apple's CA issued a fresh certificate for an
already-attested key rather than refusing.

**Strength of this result: weak, deliberately stated as such.** One
observation, one device, one OS build, one environment. A planned three-call
repeat was not run. Production was not tested. Nothing here establishes
whether re-attestation is unlimited, bounded, or rate-limited, nor whether
Apple's own risk metric treats it differently from a fresh key. The contract
(`openapi.yaml`) therefore documents re-attest as **undefined behaviour in
both directions** — Apple documents a failure, this measured a success — and
does not let callers rely on either.

**Why it is worth chasing.** `README.md` notes that Apple "may rate-limit
attestation key creation attempts per device", and that limit is the main
natural brake on an oracle like this one: if every relying-party challenge
needs its own key, throughput is capped by key creation. If a single key can
instead be re-attested over arbitrarily many fresh challenges, that brake is
much weaker than it appears, and the per-key `generateKey` limit is no longer
the binding constraint. Establishing whether re-attest is actually unbounded
is the difference between an interesting inconsistency and a materially
larger finding.

## Open questions

1. Does omitting `1.2.840.113635.100.8.7` from `OIDSToInclude` produce a
   certificate without it? Blocks the finding-2 mitigation guidance.
2. **Does the reported OS version track the running OS or the maximum
   supported OS?** Downgrade the reference device well below `15.8.8` and
   re-mint. If the certificate still says `15.8.8`, the field describes
   hardware capability, not running software, and every min-OS mitigation
   built on it is weaker than it looks. This is the highest-value
   experiment in this list after (1), and the reference device being on its
   terminal release is precisely why it has not been answered.
3. What is `1.0.248`? Needs a second OS build or device.
4. When did `…8.7` first appear in issued leaf certificates? Needs one
   archived pre-2026-10-10 attestation object.
5. What are `[1104]`, `[1404]`, `[1405]` in `…8.7`, and what populates them
   on newer platforms?
6. What is inside `RKCertification`'s 872 bytes?
7. Is `register.appattest.apple.com` the production endpoint?
8. Does a delayed `attestKey` succeed across two separate forge windows?
   **Answered 2026-10-10: yes.** A key minted by one `POST /keys` request
   attests successfully from a later `POST /keys/{keyId}/attest`, with the
   forge file verified absent between the two. This is what makes the 0.3.0
   split viable.
9. **Is re-attestation bounded?** Finding 7 observed it succeeding once.
   Repeat it n times on one key, and in the production environment, and
   watch for a rate limit or a refusal. This determines whether the
   per-device key-creation limit is a real constraint on an oracle.
10. Does `attestKey` read the App ID at all, or only record it at
    `generateKey`? The keychain label embeds `SHA256(appId)` from creation,
    but whether a mismatched attest is rejected, honours the creation-time
    identity, or honours the attest-time identity is untested. Documented as
    undefined behaviour in `openapi.yaml` rather than resolved.

## Appendix A — raw artifacts

Everything below was captured on **2026-10-10** under the conditions in
"Collection environment". Base64 and hex are deliberately **unwrapped**
(single logical line per blob) so they can be copied and re-verified
without rejoining. All identities are Parker's own team and bundle IDs.

### A.1 Development attestation

- `appId` — `67QDNMUGFA.xyz.regulad.oracled.apptwo` (**forged**; this process is unentitled)
- `environment` — `development`
- `keyId` — `AyiKfDNaC+7s9b9MvDiGHxeWvMfbNPuEZVvuBp5Hd9E=`
- `clientDataHash` — `01IfFJ3217oKUIAhep7VH+mryjW5zUCNmWJDrkiKKOY=`
- attestation object — 5373 bytes CBOR, 7164 chars base64
- leaf validity — `2026-10-09 21:04:14+00:00` .. `2026-10-12 21:04:14+00:00`
- leaf subject CN — `ST=California,O=Apple Inc.,OU=AAA Certification,CN=03288a7c335a0beeecf5bf4cbc38861f1796bcc7db34fb84655bee069e4777d1`

authData (164 bytes), parsed:

```
rpIdHash   81e916f6fb2aed60c7737c69f223ff484a1940aeb705c3674fa84452b4b9a64d
flags      0x40
counter    0
aaguid     b'appattestdevelop'
credId     AyiKfDNaC+7s9b9MvDiGHxeWvMfbNPuEZVvuBp5Hd9E=
```

- `rpIdHash == SHA256(appId)` → **True**
- recomputed nonce `SHA256(authData || clientDataHash)` → `bfbfecab6388b7be76270430a7ab2f8b5a6a06f46da35fe1985d09f4d0bc728a`

Leaf credCert extensions (raw `extnValue` bytes, hex):

```
1.2.840.113635.100.8.5  (App ID, 118 bytes)
  3074a40302010abf893003020100bf893103020100bf893203020100bf893303020100bf8934270425363751444e4d554746412e78797a2e726567756c61642e6f7261636c65642e61707074776fbf893603020104bf893703020100bf893903020100bf893a03020100bf893b03020100aa03020100
1.2.840.113635.100.8.7  (device metadata (OS version + 1.0.248), 50 bytes)
  3030bf8a7808040631352e382e38bf885007020500ffffffffbf8a79090407312e302e323438bf8a7c020400bf8a7d020400
1.2.840.113635.100.8.2  (challenge nonce, 38 bytes)
  3024a1220420bfbfecab6388b7be76270430a7ab2f8b5a6a06f46da35fe1985d09f4d0bc728a
```

Full attestation object, base64 (the exact `attestation` field from
`POST /keys`):

```
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
```

Leaf credCert, DER base64 (re-verifiable against Apple's App Attest
Root CA; `x5c[1]` is Apple's public intermediate and is omitted):

```
MIIDLDCCArGgAwIBAgIGAaEnoXKOMAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTI2MTAwOTIxMDQxNFoXDTI2MTAxMjIxMDQxNFowgZExSTBHBgNVBAMMQDAzMjg4YTdjMzM1YTBiZWVlY2Y1YmY0Y2JjMzg4NjFmMTc5NmJjYzdkYjM0ZmI4NDY1NWJlZTA2OWU0Nzc3ZDExGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/8KkTNXY9J/PVRZ2wCAlbX2CabxSW/jwzznEtv9QwRlndko2iYxcNzscnWW8aYr9CawEnbBJWFSY69SSvviRd6OCATQwggEwMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMBQGA1UdJQQNMAsGCSqGSIb3Y2QEGDCBgwYJKoZIhvdjZAgFBHYwdKQDAgEKv4kwAwIBAL+JMQMCAQC/iTIDAgEAv4kzAwIBAL+JNCcEJTY3UUROTVVHRkEueHl6LnJlZ3VsYWQub3JhY2xlZC5hcHB0d2+/iTYDAgEEv4k3AwIBAL+JOQMCAQC/iToDAgEAv4k7AwIBAKoDAgEAMD8GCSqGSIb3Y2QIBwQyMDC/ingIBAYxNS44Lji/iFAHAgUA/////7+KeQkEBzEuMC4yNDi/inwCBAC/in0CBAAwMwYJKoZIhvdjZAgCBCYwJKEiBCC/v+yrY4i3vnYnBDCnqy+LWmoG9G2jX+GYXQn00LxyijAKBggqhkjOPQQDAgNpADBmAjEA+o+VeG8zsn3et9YbuHhb4a7LKWreF2Z2ydhzKJ1nfvfP4KH70gJvQa+MfOUy1StMAjEA90eJPDdBP/mPHbLbaMmLRi97sCslEDJkxkCjtDSJRxiaclWXS4NKqF5Lho4fO0wD
```

### A.2 Production attestation

- `appId` — `67QDNMUGFA.xyz.regulad.oracled.apptwo` (**forged**; this process is unentitled)
- `environment` — `production`
- `keyId` — `Yk4DZqM8vPrRBq9iv5UjwbDlx8KoqKxbxEUA/EXi58Y=`
- `clientDataHash` — not recorded at mint time
- attestation object — 5378 bytes CBOR, 7172 chars base64
- leaf validity — `2026-10-09 21:05:27+00:00` .. `2026-10-12 21:05:27+00:00`
- leaf subject CN — `ST=California,O=Apple Inc.,OU=AAA Certification,CN=624e0366a33cbcfad106af62bf9523c1b0e5c7c2a8a8ac5bc44500fc45e2e7c6`

authData (164 bytes), parsed:

```
rpIdHash   81e916f6fb2aed60c7737c69f223ff484a1940aeb705c3674fa84452b4b9a64d
flags      0x40
counter    0
aaguid     b'appattest\x00\x00\x00\x00\x00\x00\x00'
credId     Yk4DZqM8vPrRBq9iv5UjwbDlx8KoqKxbxEUA/EXi58Y=
```

- `rpIdHash == SHA256(appId)` → **True**

Leaf credCert extensions (raw `extnValue` bytes, hex):

```
1.2.840.113635.100.8.5  (App ID, 118 bytes)
  3074a40302010abf893003020100bf893103020100bf893203020100bf893303020100bf8934270425363751444e4d554746412e78797a2e726567756c61642e6f7261636c65642e61707074776fbf893603020104bf893703020100bf893903020100bf893a03020100bf893b03020100aa03020100
1.2.840.113635.100.8.7  (device metadata (OS version + 1.0.248), 50 bytes)
  3030bf8a7808040631352e382e38bf885007020500ffffffffbf8a79090407312e302e323438bf8a7c020400bf8a7d020400
1.2.840.113635.100.8.2  (challenge nonce, 38 bytes)
  3024a122042061858ac87ca6154c8211c1befdaf6318cbfe422bff6cfb3257beb52b1c1880e1
```

Full attestation object, base64 (the exact `attestation` field from
`POST /keys`):

```
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
```

Leaf credCert, DER base64 (re-verifiable against Apple's App Attest
Root CA; `x5c[1]` is Apple's public intermediate and is omitted):

```
MIIDLDCCArGgAwIBAgIGAaEnoo6EMAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTI2MTAwOTIxMDUyN1oXDTI2MTAxMjIxMDUyN1owgZExSTBHBgNVBAMMQDYyNGUwMzY2YTMzY2JjZmFkMTA2YWY2MmJmOTUyM2MxYjBlNWM3YzJhOGE4YWM1YmM0NDUwMGZjNDVlMmU3YzYxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEodwc4wIVHlfw7DLc/czwL47G5W9R8XphCdIPKH8vKL0dWEekfOd6z0yj2QRmFVbiucvURIKJfXT75FxpfhHLZqOCATQwggEwMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMBQGA1UdJQQNMAsGCSqGSIb3Y2QEGDCBgwYJKoZIhvdjZAgFBHYwdKQDAgEKv4kwAwIBAL+JMQMCAQC/iTIDAgEAv4kzAwIBAL+JNCcEJTY3UUROTVVHRkEueHl6LnJlZ3VsYWQub3JhY2xlZC5hcHB0d2+/iTYDAgEEv4k3AwIBAL+JOQMCAQC/iToDAgEAv4k7AwIBAKoDAgEAMD8GCSqGSIb3Y2QIBwQyMDC/ingIBAYxNS44Lji/iFAHAgUA/////7+KeQkEBzEuMC4yNDi/inwCBAC/in0CBAAwMwYJKoZIhvdjZAgCBCYwJKEiBCBhhYrIfKYVTIIRwb79r2MYy/5CK/9s+zJXvrUrHBiA4TAKBggqhkjOPQQDAgNpADBmAjEA5yfWB3/mLDwXAbIBCJEhV68kdbdNHCLF1+f5jasgAgyUZp50riSIbZnclDy4h0EOAjEAr88hjVtjyoc2qApWkso6h8hDZrlqPxEDrDqrE8zL3JreluPqDzwW7MM/El8aCoGu
```

### A.3 Registration request to Apple's App Attest CA

Captured inside `devicecheckd` by hooking `nw_connection_send`. The
endpoint was resolved via `getaddrinfo` as
`register-development.appattest.apple.com`. Total plaintext captured
5066 bytes across 5 sends (258 B headers, 4773 B body, 9 B,
17 B, then a NULL-content send).

Full JSON request body, verbatim:

```json
{
  "authenticatorData" : "gekW9vsq7WDHc3xp8iP\/SEoZQK63BcNnT6hEUrS5pk1AAAAAAGFwcGF0dGVzdGRldmVsb3AAIIPbzDKQewTOAGNyBcZAkO5ZfOkH7p\/hC8SnPA9CiSvTpQECAyYgASFYIOLpAxLjvA+GQZvsxyOPG669mvK3xJALjuo+mOoqOS3BIlggisg7r0LRmgarfrCUApubhgO1H5ik38Pl+8uzAJPcM\/c=",
  "chipIDECID" : "MDAwMDcwMDAtMDAwMjI4MTYwQUI4MDAyNg==",
  "appID" : "67QDNMUGFA.xyz.regulad.oracled.apptwo",
  "requestOrigin" : "appattestation",
  "attUIKtoBIK" : "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdD4KCTxrZXk+UktDZXJ0aWZpY2F0aW9uPC9rZXk+Cgk8ZGF0YT4KCU1JSURaQUlCQWpDQ0ExMEVJUDRDM3NxUXRQMVMyaHdCWnpDb0hjc29IMnhOdTVjK2E0UTQ1b0oxTUtGM0JFRUVYYjV5CglMK1l0SUVnVGhsN2VNbEU0blh6cUxUUjRXblViWTAzQzJwb0ppTU5zTDI2K01ZQjVzMXArL2pRMWRicWduUmxWa0l4TwoJVzdmSC82bm4zN0FDb1FRUVpFb1lBWTh1WWQzNGlsQnF0UUFJeXdRUTRxN29qSmNDNEg1T3Uvdm9JV1VrWndTQ0F0QVAKCXRONjNsS1pzQ0VMWjZrTjQ1dGtFT0JIc0hSeHdXT3drWDBPaWNMMHM4eFRFSDIvUnE1SkpKK2VGRFZMVmRBWjFSQjRqCglYVG5wQ0V1R3Bvd2Qvby9iS1p1emFUSVlyK3IwazNnODU0ZzdMSnNYM0xTN2lGTVRmTFVMUTZxdzJmbHhyZEV2VExmRwoJMGZQSjhaV2lTRVUrZ0RPT1NBT1FuRCtlaEtldnBMeHlGY3ZJQ2xoNjhhOG5nU05YbFZ3N0FuUlVEbGQzbkRVNmJ1U1UKCWE4SEk3L3RwbDh1YzRQcXR5ODJOM1NNcXM4ZEExRlFRL2dLTWw0aEREUWwyZW1Na2V5SENMRnhBRXNTVGVzVkxWSE03Cgk3UGNVaGlQK1Y4U3AxRnVsNU9RcEp1RkR5TE5LWklTcm9Qc004V0R1dDA3aXU4NlJMVDUwNjFtdC9DVHAzT0lFQkJQcwoJZjJFNHRwanNyTkVuN1IyRXl2OXBVVTAxSGJjaCt3ZlVjVEpPVzJUcWpyekk2Mk80TjBBZXVXUCtrMDVoOWx1LzhSb3gKCWRJTmFsVTk3NGwrY1J0K1VnMlR2YlpBWXNKTzhFd0RmK2NYbWxOVU1Md2djVVhUbU9Ld1hVS1IyekdYb3hxbTdXWnhaCglIaG5YRTRJZ0JRdEF1RmFzODRZc2VoWWVQYXF4MTU4SkIxOWZSZ2lGeDRxVExEYzlwRTF2VXZtYnEzN3VOK0RzRU5CSAoJVHkrbXdNckUxcy9WSGtSTndoMDUyN01paWlEQmlRUlkzeTB2TTJYQm5zQ240QWNWc1VGbVZuMFNyUkxLN3I3aVN0SkoKCS81Nm1rbHBuTlFJL1gzaWdsTUs0eGNreG1zWXhBc0V2MkUwK1VPQ3MvTC9KeUpzR3ZoQ043UGtxK3hUdVRZdW9uZUIxCglpVXFRYWJDWENrVFp3VEN0dnhsMTUrNXZMMk0yWU5wWHd0M0JQOHBWZ1BXNjVxcGJPZmxSTUVOOVBPY3RRbDhPVjRxbQoJZEZkL1dZVnp2OVIveTZXVDdQSzc2T0NjUXNnb0Z0VkdsUnVia002MnA3eWV1V1U1Rm5IejdhUkdOSE9ZZ08vTnhIM24KCXczbUYwbGdaZGlRL3JrWEdRbFIxaHBkOEVkSWZSS2ZtQmZQeVd1b0FMcU02WGN3K29KYTZJTjRIRXNGeVdEV250R1paCgl4dEdsY080VmNTWEtIeUNneWdEUWRRSE9Ic21qTUxHNjlIS1c3VEk2VFRXcysvQnVBRDdmNHdqNUwrM2Q1dFlzQ05NbgoJMHZHdW9ZZz0KCTwvZGF0YT4KCTxrZXk+UktQcm9wZXJ0aWVzPC9rZXk+Cgk8ZGF0YT4KCVBEOTRiV3dnZG1WeWMybHZiajBpTVM0d0lpQmxibU52WkdsdVp6MGlWVlJHTFRnaVB6NEtQQ0ZFVDBOVVdWQkZJSEJzCglhWE4wSUZCVlFreEpReUFpTFM4dlFYQndiR1V2TDBSVVJDQlFURWxUVkNBeExqQXZMMFZPSWlBaWFIUjBjRG92TDNkMwoJZHk1aGNIQnNaUzVqYjIwdlJGUkVjeTlRY205d1pYSjBlVXhwYzNRdE1TNHdMbVIwWkNJK0NqeHdiR2x6ZENCMlpYSnoKCWFXOXVQU0l4TGpBaVBnbzhaR2xqZEQ0S0NUeHJaWGsrUVhCd1NVUThMMnRsZVQ0S0NUeHpkSEpwYm1jK05qZFJSRTVOCglWVWRHUVM1NGVYb3VjbVZuZFd4aFpDNXZjbUZqYkdWa0xtRndjSFIzYnp3dmMzUnlhVzVuUGdvSlBHdGxlVDVDYjJGeQoJWkVsa1BDOXJaWGsrQ2drOGFXNTBaV2RsY2o0NFBDOXBiblJsWjJWeVBnb0pQR3RsZVQ1RFFVTmxjblE4TDJ0bGVUNEsKCUNUeHBiblJsWjJWeVBqQThMMmx1ZEdWblpYSStDZ2s4YTJWNVBrTmxjblJVZVhCbFBDOXJaWGsrQ2drOGFXNTBaV2RsCgljajR3UEM5cGJuUmxaMlZ5UGdvSlBHdGxlVDVEYUdsd1NVUThMMnRsZVQ0S0NUeHBiblJsWjJWeVBqSTROamN5UEM5cAoJYm5SbFoyVnlQZ29KUEd0bGVUNVBTVVJUVkc5SmJtTnNkV1JsUEM5clpYaytDZ2s4WVhKeVlYaytDZ2tKUEhOMGNtbHUKCVp6NHhMakl1T0RRd0xqRXhNell6TlM0eE1EQXVPQzQxUEM5emRISnBibWMrQ2drSlBITjBjbWx1Wno0eExqSXVPRFF3CglMakV4TXpZek5TNHhNREF1T0M0M1BDOXpkSEpwYm1jK0Nna0pQSE4wY21sdVp6NHhMakl1T0RRd0xqRXhNell6TlM0eAoJTURBdU9DNHlQQzl6ZEhKcGJtYytDZ2s4TDJGeWNtRjVQZ29KUEd0bGVUNVNTME5sY25ScFptbGpZWFJwYjI1UWRXSTgKCUwydGxlVDRLQ1R4a1lYUmhQZ29KUWs5TWNFRjRUR3AyUVN0SFVWcDJjM2g1VDFCSE5qWTViWFpMTTNoS1FVeHFkVzhyCgliVTl2Y1U5VE0wSnBjMmMzY2pCTVVtMW5ZWEptY2tOVlFYQjFZbWhuVHpFS0NVZzFhV3N6T0ZCc0t6aDFla0ZLVUdOTgoJTDJNOUNnazhMMlJoZEdFK0NnazhhMlY1UGxOSlMxQjFZand2YTJWNVBnb0pQR1JoZEdFK0NnbENSVGxGYzFGSldFaHIKCWQxZ3pVMlJRTVV0UlRuVkthemRvUkZWd1ZuQnhTMmd5YzJ4bFdFbEhlak4zUVhCV05WSTBWM1k0VURoWk9IZFJVek0zCglOMWw0U2xSdGRBb0pVVEFyZHpGdWRtRmFlbWRMTUcxak1qQjZZejBLQ1R3dlpHRjBZVDRLQ1R4clpYaytVMlZqZFhKcAoJZEhsRWIyMWhhVzQ4TDJ0bGVUNEtDVHhwYm5SbFoyVnlQakU4TDJsdWRHVm5aWEkrQ2drOGEyVjVQbE5sY21saGJFNTEKCWJXSmxjand2YTJWNVBnb0pQSE4wY21sdVp6NUdPVVpYVkZCUk0wZElTMG84TDNOMGNtbHVaejRLQ1R4clpYaytWVzVwCgljWFZsUTJocGNFbEVQQzlyWlhrK0NnazhhVzUwWldkbGNqNDJNRGN3TWpVd09EYzJORE0yT0RZOEwybHVkR1ZuWlhJKwoJQ2drOGEyVjVQbFpoYkdsa2FYUjVQQzlyWlhrK0NnazhhVzUwWldkbGNqNHhORFF3UEM5cGJuUmxaMlZ5UGdvSlBHdGwKCWVUNXpZM0owUVhSMFpYTjBZWFJwYjI0OEwydGxlVDRLQ1R4cGJuUmxaMlZ5UGpBOEwybHVkR1ZuWlhJK0Nqd3ZaR2xqCglkRDRLUEM5d2JHbHpkRDRLCgk8L2RhdGE+Cgk8a2V5PlJLUHJvcGVydGllc1NpZ25hdHVyZTwva2V5PgoJPGRhdGE+CglNRVVDSUR4YU0vbHZMZEpyeXlCK1ptZ0xQbHI5cnIybXBQQllVdlNuck0zcWxiN2hBaUVBaWQ5SytrUkVwRXVCRXMzZgoJQlh5Znd4bmwyRGRvMU5hcVpOQS9DQ2JtRW1BPQoJPC9kYXRhPgo8L2RpY3Q+CjwvcGxpc3Q+Cg==",
  "environment" : "development",
  "clientDataHash" : "443ywx4yxM+9Zyf5uXfdZO9kyzU5BJ5bXK+EywzyW28="
}
```

`chipIDECID` base64-decodes to `00007000-000228160AB80026` — ChipID `0x7000` followed by the ECID.

`attUIKtoBIK` base64-decodes to this 3184-byte XML plist
(3 keys; `<data>` bodies elided here, given in full below):

```
RKCertification          <data 872 bytes>
RKProperties             <data 1134 bytes>
RKPropertiesSignature    <data 71 bytes>
```

`RKProperties` (1134 bytes) is itself an XML
plist. This is the structure covered by `RKPropertiesSignature`, and it
is where the forged `AppID` lives. Verbatim:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AppID</key>
	<string>67QDNMUGFA.xyz.regulad.oracled.apptwo</string>
	<key>BoardId</key>
	<integer>8</integer>
	<key>CACert</key>
	<integer>0</integer>
	<key>CertType</key>
	<integer>0</integer>
	<key>ChipID</key>
	<integer>28672</integer>
	<key>OIDSToInclude</key>
	<array>
		<string>1.2.840.113635.100.8.5</string>
		<string>1.2.840.113635.100.8.7</string>
		<string>1.2.840.113635.100.8.2</string>
	</array>
	<key>RKCertificationPub</key>
	<data>
	BOLpAxLjvA+GQZvsxyOPG669mvK3xJALjuo+mOoqOS3Bisg7r0LRmgarfrCUApubhgO1
	H5ik38Pl+8uzAJPcM/c=
	</data>
	<key>SIKPub</key>
	<data>
	BE9EsQIXHkwX3SdP1KQNuJk7hDUpVpqKh2sleXIGz3wApV5R4Wv8P8Y8wQS377YxJTmt
	Q0+w1nvaZzgK0mc20zc=
	</data>
	<key>SecurityDomain</key>
	<integer>1</integer>
	<key>SerialNumber</key>
	<string>F9FWTPQ3GHKJ</string>
	<key>UniqueChipID</key>
	<integer>607025087643686</integer>
	<key>Validity</key>
	<integer>1440</integer>
	<key>scrtAttestation</key>
	<integer>0</integer>
</dict>
</plist>
```

Note there is **no software or OS version key** among those 13 — the
device does not tell Apple what it is running. Keys present:

```
AppID, BoardId, CACert, CertType, ChipID, OIDSToInclude, RKCertificationPub, SIKPub, SecurityDomain, SerialNumber, UniqueChipID, Validity, scrtAttestation
```

`RKCertification` (872 bytes — 872-byte DER; SEP-signed, parsed only one level deep), hex:

```
308203640201023082035d0420fe02deca90b4fd52da1c016730a81dcb281f6c4dbb973e6b8438e6827530a1770441045dbe722fe62d204813865ede3251389d7cea2d34785a751b634dc2da9a0988c36c2f6ebe318079b35a7efe343575baa09d1955908c4e5bb7c7ffa9e7dfb002a10410644a18018f2e61ddf88a506ab50008cb0410e2aee88c9702e07e4ebbfbe821652467048202d00fb4deb794a66c0842d9ea4378e6d9043811ec1d1c7058ec245f43a270bd2cf314c41f6fd1ab924927e7850d52d5740675441e235d39e9084b86a68c1dfe8fdb299bb3693218afeaf493783ce7883b2c9b17dcb4bb8853137cb50b43aab0d9f971add12f4cb7c6d1f3c9f195a248453e80338e4803909c3f9e84a7afa4bc7215cbc80a587af1af27812357955c3b0274540e57779c353a6ee4946bc1c8effb6997cb9ce0faadcbcd8ddd232ab3c740d45410fe028c9788430d09767a63247b21c22c5c4012c4937ac54b54733becf7148623fe57c4a9d45ba5e4e42926e143c8b34a6484aba0fb0cf160eeb74ee2bbce912d3e74eb59adfc24e9dce2040413ec7f6138b698ecacd127ed1d84caff69514d351db721fb07d471324e5b64ea8ebcc8eb63b837401eb963fe934e61f65bbff11a3174835a954f7be25f9c46df948364ef6d9018b093bc1300dff9c5e694d50c2f081c5174e638ac1750a476cc65e8c6a9bb599c591e19d7138220050b40b856acf3862c7a161e3daab1d79f09075f5f460885c78a932c373da44d6f52f99bab7eee37e0ec10d0474f2fa6c0cac4d6cfd51e444dc21d39dbb3228a20c1890458df2d2f3365c19ec0a7e00715b14166567d12ad12caeebee24ad249ff9ea6925a6735023f5f78a094c2b8c5c9319ac63102c12fd84d3e50e0acfcbfc9c89b06be108decf92afb14ee4d8ba89de075894a9069b0970a44d9c130adbf1975e7ee6f2f633660da57c2ddc13fca5580f5bae6aa5b39f95130437d3ce72d425f0e578aa674577f598573bfd47fcba593ecf2bbe8e09c42c82816d546951b9b90ceb6a7bc9eb965391671f3eda44634739880efcdc47de7c37985d2581976243fae45c642547586977c11d21f44a7e605f3f25aea002ea33a5dcc3ea096ba20de0712c1725835a7b46659c6d1a570ee157125ca1f20a0ca00d07501ce1ec9a330b1baf47296ed323a4d35acfbf06e003edfe308f92feddde6d62c08d327d2f1aea188
```

`RKPropertiesSignature` (71 bytes — signature over RKProperties), hex:

```
304502203c5a33f96f2dd26bcb207e66680b3e5afdaebda6a4f05852f4a7accdea95bee102210089df4afa4444a44b8112cddf057c9fc319e5d83768d4d6aa64d03f0826e61260
```

`SIKPub` (65 bytes, EC P-256 uncompressed point), hex:

```
044f44b102171e4c17dd274fd4a40db8993b843529569a8a876b25797206cf7c00a55e51e16bfc3fc63cc104b7efb6312539ad434fb0d67bda67380ad26736d337
```

`RKCertificationPub` (65 bytes, EC P-256 uncompressed point), hex:

```
04e2e90312e3bc0f86419becc7238f1baebd9af2b7c4900b8eea3e98ea2a392dc18ac83baf42d19a06ab7eb094029b9b8603b51f98a4dfc3e5fbcbb30093dc33f7
```

### A.4 SEP firmware IM4P header

`Firmware/all_flash/sep-firmware.j96.RELEASE.im4p` from
`iPad_64bit_TouchID_15.8.8_19H422_Restore.ipsw`, 2724094 bytes. The `j81`/`j82`/`j96`/`j97` variants are all the same
size. First 160 bytes, hex:

```
30 83 29 90 f9 16 04 49 4d 34 50 16 04 73 65 70 69 16 70 66 66 38 36 63 62 62 35 65 30 36 63 33 31 33 30 32 66 31 36 30 34 36 39 36 64 37 30 36 63 33 31 32 37 66 66 38 36 38 62 63 39 64 61 37 33 30 62 33 30 30 39 31 36 30 34 36 31 37 32 36 64 37 33 30 32 30 31 30 30 66 66 38 37 61 33 65 38 65 30 37 33 30 65 33 30 30 63 31 36 30 34 37 34 37 61 33 30 37 33 30 32 30 34 30 30 62 64 30 30 30 30 04 83 29 90 00 85 e7 1c 75 e6 2f 53 ac c0 62 37 51 58 94 d8 a9 9a 2e ea 39 2d 3e 6f fa
```

Parsed: `IM4P`, type `sepi`, then a 112-character description field
which is a **hex-encoded nested IMG4 property set** (payload
placement metadata, not a version):

```
pff86cbb5e06c31302f1604696d706c3127ff868bc9da730b3009160461726d73020100ff87a3e8e0730e300c1604747a3073020400bd000
```

Decoding that hex yields IA5Strings `impl`, `arms` (INTEGER 0) and
`tz0s` (INTEGER `0x00BD0000` = 12386304, the TZ0 size). The payload
is a 2723964-byte encrypted OCTET STRING followed by a
116-byte KBAG, so no version string is recoverable without the
device GID key.

