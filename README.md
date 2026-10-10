# aaoracled

Daemon that enables an iOS/iPadOS device to be used as a sockpuppet/oracle
that passes App Attest challenges on behalf of other devices.

Created by [Parker Wahle](https://github.com/regulad). Anthropic's Claude 5 series models
(Fable, Opus, Sonnet & Haiku) were used to rapidly iterate.

## Install

You can either build `aaoracled` yourself or add my Cydia repo `https://ios.regulad.xyz`
to your package manager and install `xyz.regulad.aaoracled`.

## Building

`aaoracled` ships as a single Debian package (`xyz.regulad.aaoracled`)
containing both the `OracledDCPatch` tweak (injected into `devicecheckd`)
and the `aaoracled` CLI/daemon itself. See [SETUP.md](SETUP.md) first for
preparing the jailbroken test device and the laptop-side build toolchain
(theos).

Build it:

```bash
./build_and_sign.sh                  # debug build, auto-incrementing version
FINALPACKAGE=1 ./build_and_sign.sh   # final release build
```

This produces `packages/xyz.regulad.aaoracled_<version>_iphoneos-arm64e.deb`.

Install it on the device:

```bash
scp packages/xyz.regulad.aaoracled_*.deb <device-alias>:/tmp/aaoracled.deb
ssh <device-alias> 'sudo apt install /tmp/aaoracled.deb -y'
```

**Before installing, confirm your device's exact build.** `Tweak.x` hooks
`AppAttestInternal` at hardcoded, Ghidra-derived static offsets that are
only valid for one specific `dyld_shared_cache` build. This project's
offsets were extracted from, and are currently verified against, an
**iPad mini 4 (`iPad5,1`, A8/T7000) running iPadOS 15.8.8, build `19H422`.**
Installing on any other device model or OS build without first re-deriving
the offsets (see `AGENTS.md`'s Ghidra workflow) will either silently call
the wrong function or crash `devicecheckd`.

## Use

The full HTTP surface is documented as an OpenAPI 3.1 contract in
[`openapi.yaml`](openapi.yaml). Once installed, `aaoracled` listens on
`127.0.0.1:8181` on the device — reach it over an SSH tunnel
(`ssh -L 8181:127.0.0.1:8181 <device-alias>`) or `curl` it directly from an
on-device shell.

The three core routes mirror Apple's own `DCAppAttestService` one-for-one —
`generateKey`, `attestKey` and `generateAssertion` — because the point is that
a stub `DeviceCheck.framework` should be able to forward to this daemon
instead of to a real `devicecheckd`. They are **separate calls**, exactly as
they are in the framework.

Request bodies are closed: any field a route does not accept is a `400`
naming it, rather than being silently ignored.

A helper for the percent-encoding, since both `keyId`s and keychain labels
are standard base64 and `/` must become `%2F` in a path:

```bash
API=http://127.0.0.1:8181
enc() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"; }
cdh() { openssl rand -base64 32; }   # in real use: base64(SHA-256(server challenge))
```

**1. `generateKey` — mint a key under any App ID you choose.** This is the
core oracle primitive: `appId` is caller-chosen, and nothing about this
process is legitimately provisioned for it. No attestation and no Apple
round trip happen here.

```bash
KEYID=$(curl -s -X POST $API/keys \
  -H 'Content-Type: application/json' \
  -d '{"appId": "ABCDE12345.com.example.myapp", "environment": "development"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["keyId"])')
```

**2. `attestKey` — attest it over a server challenge.** This is the Apple CA
round trip. The `appId` must match the one the key was minted under; passing a
different one is undefined behaviour.

```bash
curl -s -X POST "$API/keys/$(enc "$KEYID")/attest" \
  -H 'Content-Type: application/json' \
  -d "{\"appId\": \"ABCDE12345.com.example.myapp\", \"clientDataHash\": \"$(cdh)\"}"
```

There is deliberately no `environment` field here — it was burned into the
key at mint time and is read back off the device, so a mint/attest mismatch
cannot be expressed.

**3. `generateAssertion` — sign subsequent requests with the attested key.**
Returns the CBOR `{signature, authenticatorData}` a relying party expects.
devicecheckd builds `authenticatorData` itself, including the key's
monotonically incrementing counter.

```bash
curl -s -X POST "$API/keys/$(enc "$KEYID")/assert" \
  -H 'Content-Type: application/json' \
  -d "{\"appId\": \"ABCDE12345.com.example.myapp\", \"clientDataHash\": \"$(cdh)\"}"
```

Asserting with a key that was never attested fails with
`DCErrorInvalidKey` (`com.apple.devicecheck.error` code `3`).

### `/labels` — device-wide credential access

`/keys` above is the framework surface, addressed by `keyId`. `/labels` is a
**separate hierarchy** for the privileged device-wide keychain surface,
addressed by an opaque AppAttestInternal label. It has no framework
counterpart at all — it exists only because `devicecheckd` is compromised, and
no stub framework would ever call it.

The two identifiers are not interchangeable: `POST /keys` returns a `keyId`,
`GET /labels` returns labels. Labels always begin `aa:`, and passing a `keyId`
to a `/labels` route is a `400` rather than a silent no-op.

List every App Attest credential on the device — not just ones `aaoracled`
minted (see Vulnerability & Mitigation below):

```bash
curl -s $API/labels
```

Delete one permanently:

```bash
LABEL='aa:9Ur1MdQmPZZbOLudX+0T2lAbouGfiPZH1GQOIRyp88Y=d:...'
curl -s -X DELETE "$API/labels/$(enc "$LABEL")"
```

This is idempotent by Apple's own design: it reports success whether or not
the credential was present, because `_delete_keychain_item` treats
`errSecItemNotFound` as success. That applies to real labels only — a value
that isn't label-shaped is rejected.

> **Removed in 0.3.0:** `POST /keys/{key}/sign`, which produced a raw ECDSA
> signature over arbitrary bytes with no identity and no counter. Its only
> real use was assembling an assertion client-side, and
> `POST /keys/{keyId}/assert` now produces a genuine one. The underlying
> capability — a compromised `devicecheckd` can sign with any credential on
> the device — still exists in the tweak and remains a finding; only the HTTP
> route is gone.

## Vulnerability & Mitigation

Apple's [App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
service can be used to prove that a request has been sanctioned by a
genuine Apple iOS or iPadOS device (T2 and Apple Silicon Macs use a
different mechanism). When used exclusively for that purpose, it is
adequate, and can serve as an anchor to limit the number of sessions
launched by a specific device (Apple may rate-limit attestation key
creation attempts per device). However, commercial anti-tampering SDK
providers like [Radar](https://docs.radar.com/geofencing/fraud),
[Guardsquare](https://www.guardsquare.com/), and [Approov](https://approov.io/)
often place too much trust in App Attest's ability to vouch for a device's
or application's integrity. This is caused, at least in part, by Apple's
own marketing of App Attest, which does not clearly disclose that App
Attest is not fully qualified to attest to the integrity of a non-secure
environment.

`aaoracled` makes that shortfall concrete. It mints App Attest keys for
App IDs that the device it runs on could never run legitimately, turning
an old, jailbroken device into a sockpuppet that forges attestations for
apps that would otherwise require current hardware. Paired with an iOS
simulator or a stripped-down app runtime, a request attested by
`aaoracled` carries a genuine, Apple-signed attestation naming an App ID
the device was never provisioned for — because `devicecheckd` derives that
identity entirely in application-processor userspace, and the Secure
Enclave signs whatever it is handed. Apple's App Attest CA will sign any
request carrying a well-formed App ID; the identity binding fails open.

What the attestation discloses about the *device*, however, is more than
this project originally credited, and it is the lever a relying party
actually has. The credential certificate's leaf carries extension
`1.2.840.113635.100.8.7`, which reports an OS version for the minting
device — measured as `15.8.8` on the reference iPad mini 4, in both the
development and production environments (see [RESEARCH.md](RESEARCH.md)
for the full decode, the raw blobs, and the date that data was collected).

Be precise about what that field is and is not. It is **not** an integrity
measurement: there is no hardware model string, and no measurement of the
OS or of the app binary, anywhere in the attestation. It is also **not**
something the client reports — the registration request this tool sends to
Apple contains no software or OS version field at all, which was verified
by decoding every layer of it. So the value is not trivially chosen by a
compromised client, and that is what makes it worth checking.

What it means beyond that is genuinely undetermined. Its provenance is
unverified: it may come from Apple's own records for the device, or from a
component of the request this research could not decode. And the reference
device is sitting on its *terminal* release — `15.8.8` is the last
iPadOS build ever shipped for `iPad5,1` — so a single sample cannot
distinguish "the OS this device is running" from "the newest OS this
hardware can run." Rolling the device back to a much older release may
well still produce `15.8.8` here; that experiment has not been done. The
only claim this research supports is the weak one: **the field reports a
version that this device's hardware is capable of running.**

That is still worth checking, because publishers routinely raise the
minimum OS version of their apps to keep unpatched or known-compromised
devices out, and an oracle like this one runs on hardware that is old
enough to be jailbreakable. Note carefully what the check therefore buys:
it excludes hardware that *cannot* reach your minimum — which is the
sockpuppet case this tool demonstrates. It may well **not** detect a
current device that has been downgraded to an old, vulnerable release,
since such a device could report a version it is merely capable of.

The OS floor is only the most legible casualty of a more general limit:
what an App Attest assertion actually proves is that a genuine Secure
Enclave exists somewhere behind the request — not which device holds it,
and not what software asked it to sign.

If you are developing an app that needs to enforce the integrity of its
operating environment, please note the following when using App Attest:

1. **Your origin server *must* verify the OS version baked into the
   attestation, and reject anything below the floor your app actually
   supports.** Parse extension `1.2.840.113635.100.8.7` out of the
   credential certificate's leaf and require that the OS version it
   reports is at least the minimum OS your current release runs on. This
   is not optional hardening — it is the one check that excludes hardware
   old enough to be a sockpuppet, and its absence is what makes this tool
   useful. The data is already in a certificate you have to parse anyway,
   and the client does not supply it: this tool's registration request
   carries no OS or software version field, so the value is not one a
   compromised client simply fills in.

   Understand its limit. All this research establishes is that the field
   reports a version the minting device's hardware is *capable* of
   running. It is not an integrity measurement, and it has **not** been
   shown to reflect the OS actually running at attestation time — a
   downgraded current device may be able to report a version it merely
   supports. So this check raises the hardware floor; it does not tell you
   the client is patched. See [RESEARCH.md](RESEARCH.md).

   **Fail closed.** The set of extensions Apple stamps into the leaf is
   *requested by the device*, in the signed `OIDSToInclude` field of the
   registration request — and the `AppID` in that same signed structure is
   demonstrably forgeable by the tweak in this repository. Treat a
   **missing** `1.2.840.113635.100.8.7` as a failed check, never as "no
   opinion." A version check that silently passes when the field is absent
   can be defeated by simply not asking for the field. Whether that
   omission actually succeeds was still untested as of 2026-10-10; assume
   it works until someone demonstrates otherwise.
2. App Attest can **only** be used to advocate for the presence of a
   legitimate, Apple-provisioned Secure Element *somewhere* that the
   request sender controls. It is a strong trust signal, but it can only be
   used to prove that a real Apple device is being used — never that your
   app or the OS is unmodified, since a device that has been completely
   compromised via a jailbreak still has a fully operational, functional
   Secure Enclave.
3. Use App Attest alongside other difficult-to-spoof checks, like
   MobileSubstrate/ElleKit detection — and always remember that **any
   client-side restriction can be bypassed; anything life-or-death *must*
   be enforced server-side!**

This issue was privately disclosed to Apple as Security Research
submission #OE1107928141015. The submission was allowed to close before
the publication of this research tool.

## License

All original work in this repository is licensed under
[AGPLv3](./LICENSE.md).
