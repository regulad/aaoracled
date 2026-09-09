# aaoracled

Daemon that enables an iOS/iPadOS device to be used as a sockpuppet/oracle
that passes App Attest challenges on behalf of other devices.

Created by [Parker Wahle](https://github.com/regulad)
([hire me!](mailto:pw@regulad.xyz)). Anthropic's Claude "5" series models
(Fable, Opus, Sonnet & Haiku) were used to rapidly iterate.

## Install

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

Create (mint + attest) a key under any App ID you choose — this is the core
oracle primitive:

```bash
CDH=$(openssl rand -base64 32)   # in real use: base64(SHA-256(server challenge))

curl -s -X POST http://127.0.0.1:8181/keys \
  -H 'Content-Type: application/json' \
  -d "{\"appId\": \"ABCDE12345.com.example.myapp\", \"environment\": \"development\", \"clientDataHash\": \"$CDH\"}"
```

List every App Attest key resident on the device (not just ones `aaoracled`
itself minted — see Threat Mitigation below):

```bash
curl -s http://127.0.0.1:8181/keys
```

Sign an arbitrary challenge with any listed key. The `key` value returned
by `GET /keys` must be URL-encoded before it goes in a path — it contains
`:` plus base64's `+`/`/`/`=`:

```bash
KEY='aa:9Ur1MdQmPZZbOLudX+0T2lAbouGfiPZH1GQOIRyp88Y=d:...'
ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$KEY")

curl -s -X POST "http://127.0.0.1:8181/keys/$ENC/sign" \
  -H 'Content-Type: application/json' \
  -d "{\"clientDataHash\": \"$CDH\"}"
```

Delete a key from the device permanently:

```bash
curl -s -X DELETE "http://127.0.0.1:8181/keys/$ENC"
```

## Threat Mitigation

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

If you are developing an app that needs to enforce the integrity of its
operating environment, please note the following when using App Attest:

1. App Attest can **only** be used to advocate for the presence of a
   legitimate, Apple-provisioned Secure Element *somewhere* that the
   request sender controls. It is a strong trust signal, but it can only be
   used to prove that a real Apple device is being used — never that your
   app or the OS is unmodified, since a device that has been completely
   compromised via a jailbreak still has a fully operational, functional
   Secure Enclave.
2. Use App Attest alongside other difficult-to-spoof checks, like
   MobileSubstrate/ElleKit detection — and always remember that **any
   client-side restriction can be bypassed; anything life-or-death *must*
   be enforced server-side!**

While this project targets iOS, the underlying architectural pattern it
demonstrates isn't inherently iOS-specific. This project's specific exploit
chain relies on checkm8, a permanent bootROM exploit that runs before any
OS-level code — including Apple's own Secure Boot chain — which has no real
Android equivalent, since Android Verified Boot (AVB) measures the boot
chain into a hardware root of trust starting from the very first stage.
Compromising a verified-boot Android device generally means either
unlocking the bootloader outright (which AVB and remote attestation are
explicitly designed to detect and report) or finding a runtime exploit that
leaves the measured boot chain untouched.

That distinction matters for *how* a device would need to be compromised,
but not necessarily for *whether* the underlying gap exists at all. The
real question this project's finding raises is architectural, not
Apple-specific: is the userspace code brokering between the OS and the
secure hardware independently checked by that hardware, or does the
hardware simply sign whatever identity claim userspace hands it? If
Android's own attestation stack (Keystore key attestation, and the Play
Integrity API built on top of it) has a similarly-shaped userspace daemon
deriving app identity without an independent check from its own secure
element (a TEE, or a dedicated StrongBox module analogous to Apple's Secure
Enclave), then a sufficiently privileged, post-boot userspace compromise —
one that leaves verified boot's own measurements intact — could in
principle abuse the same class of gap. This project did not attempt this
against any Android device or attestation stack, so this is a hypothesis
about a shared architectural failure mode, not a claim about Android's
actual security — a direction for further research, not a finding.

## License

All original work in this repository is licensed under
[AGPLv3](./LICENSE.md).
