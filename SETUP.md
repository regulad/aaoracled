# Setup

What a human needs to do to stand up the test environment this project
builds against: a jailbroken iPad mini 4, its SSH/Frida access, and the
laptop-side toolchain used to build and deploy the package. The build
toolchain (theos, in particular) natively expects a Linux or macOS
environment — see step 9 for how to get one on Windows via WSL, including
the container image this project's own sessions were run from.

**Scope note:** everything below (steps 1–11) is what's needed to build and
run `aaoracled`/`OracledDCPatch` itself. **No app installation on the
device, no Apple ID sign-in, and no Apple Developer account are needed for
aaoracled to work** — it's an ad-hoc/`ldid`-signed daemon + tweak with no
genuine Apple signing material anywhere, by design (see `AGENTS.md`'s
threat model). The one exception is `fixtures/` — the App A baseline app
and its build script *do* require a real Apple Developer account (a
genuine signing identity + provisioning profile), because it exists to
demonstrate the legitimate, unforged control case. See
`fixtures/README.md` if you need that baseline; it is not required to use
aaoracled itself.

## 1. Hardware

A checkm8-vulnerable device (A5–A11). This project's reference device is an
**iPad mini 4 (`iPad5,1`, A8/T7000)**. checkm8 is a permanent bootrom
exploit — any device in that chip range works the same way.

## 2. Jailbreak the device

This project expects **[Palera1n-roothide](https://github.com/roothide/Palera1n-roothide)
(checkm8) with [Dopamine2-roothide](https://github.com/roothide/Dopamine2-roothide)
layered on top** — not plain rootless palera1n, and not stock Dopamine.
There is no `/var/jb`; roothide uses a per-install *randomized* jbroot path
instead.

1. Jailbreak with Palera1n-roothide as normal.
2. Install Dopamine2-roothide on top.
3. Confirm the jbroot markers exist: the jbroot directory (resolve it with
   `jbroot /` — do **not** hardcode the random hex suffix anywhere) should
   contain `.installed_palera1n`, `.installed_dopamine`, and
   `.procursus_strapped`.
4. Confirm a package manager is present (Sileo + `apt`) with sources
   configured (`default.sources`, `procursus.sources`, `sileo.sources`).

Note: roothide tags its packages with dpkg arch `iphoneos-arm64e`. That is a
**roothide compatibility sentinel only** — the actual binaries are plain
arm64 and run fine on an A8. Don't read anything into the `arm64e` label.

## 3. Confirm the device model and OS build

**Do this every time you set up a new device, and re-check after any OS
update.** `Tweak.x` hardcodes static Ghidra-derived offsets into
`AppAttestInternal` that are valid for exactly one `dyld_shared_cache`
build — they will silently break (wrong function called, or a crash) on any
other iOS version.

```
ssh <device> 'sw_vers; uname -a'
```

Confirm the model/board against `iPad5,1` and the build number against the
one documented in `Tweak.x`'s offset comment block. If they don't match, the
hardcoded offsets in `Tweak.x` are stale and must be re-derived (see
`AGENTS.md`'s Ghidra workflow) before trusting anything the tweak does.

## 4. SSH access

- Set up a stable SSH alias to the device (e.g. a Tailscale MagicDNS
  hostname, `<device-alias>.tail<id>.ts.net`, user `mobile`).
- Add the alias to your SSH config so `ssh <alias>` and `scp ... <alias>:...`
  work directly, and add the host key to `known_hosts` up front (don't rely
  on `accept-new` mid-session).
- **On Windows specifically:** use a real SSH client that talks to the
  Windows `ssh-agent` and your configured key (PowerShell's `ssh`/`scp`, or
  OpenSSH for Windows). Git Bash's bundled SSH cannot use this device's key
  format and fails publickey auth — don't use it for device access. This
  doesn't apply on Linux/macOS, where the system `ssh`/`scp` just work.
- Real on-device system paths (`/System/...`, `/var/mobile/...`,
  `/var/mobile/Library/Logs/CrashReporter/*.ips`, the dyld shared cache,
  etc.) are only reachable with an `/rootfs` prefix from the default
  jbroot-namespaced SSH shell.

## 5. Install `frida-server` on the device

Install a pinned `frida-server` build (this project uses **16.7.0**) as a
persistent LaunchDaemon so it survives reboots:

```
# on device, via apt from a frida repo (e.g. miticollo's roothide repo)
apt install re.frida.server
launchctl list | grep frida   # confirm re.frida.server is running
```

It should bind loopback-only (`127.0.0.1:27042`). This device's shell has a
sandboxed `ps`/`lsof` that won't show the process — use `launchctl list` to
check status instead.

## 6. Install Frida on the laptop, pinned to match

The `frida` Python binding must match the on-device `frida-server` version
exactly — cross-version handshakes are refused.

```
uv tool install "frida-tools==13.7.1" --with "frida==16.7.0" --python 3.12
```

Adjust both version numbers together if you upgrade `frida-server`.

## 7. Install Ghidra + the Ghidra MCP server

Static analysis (pulling function offsets out of `AppAttestInternal` and
other private frameworks) is done via Ghidra, driven through
[bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) so an
agent session can call Ghidra's decompiler/scripting API directly instead of
driving the GUI by hand.

1. Install Ghidra itself (a recent stable release).
2. Install the `ghidra-mcp` extension/server per that repo's README, and
   connect it to your Ghidra install.
3. Create (or reuse) a Ghidra project for this device's dyld shared cache
   extractions — this project's convention is a project named `oracled`.
4. If you need Ghidra's scripting API (used to extract a single dylib out of
   the combined `dyld_shared_cache` without importing the whole cache — see
   `AGENTS.md`'s Ghidra workflow), make sure inline script execution is
   enabled for the MCP server (`GHIDRA_MCP_ALLOW_SCRIPTS=1` or equivalent).

See `AGENTS.md` for how this is actually driven once it's set up.

## 8. Set up tunnels

`frida-server` is loopback-only on the device, and the relying-party harness
runs on the laptop — tunnel both directions rather than exposing either:

```
# laptop -> device frida-server (forward tunnel)
ssh -L 27042:127.0.0.1:27042 <device-alias> -o ServerAliveInterval=30

# device -> laptop RP harness (reverse tunnel)
ssh -R 8080:127.0.0.1:8080 <device-alias> -o ServerAliveInterval=30
```

Drive Frida against `127.0.0.1:27042` locally once the forward tunnel is up.

## 9. Build toolchain (Linux, macOS, or Windows via WSL)

theos (the build system this project's `Makefile` is written for) natively
targets Linux and macOS. On Windows, run it inside WSL rather than trying
to install it directly on the Windows filesystem.

**On Linux or macOS directly:**

1. Install [theos](https://theos.dev/) per its own install instructions,
   set `THEOS=~/theos` (or wherever you installed it).
2. Run the build: `./build_and_sign.sh` from the repo root.

That's it on a native Linux/macOS filesystem — the two gotchas below are
specific to running theos through a Windows/WSL mount and don't apply here.

**On Windows, via WSL:**

Any WSL distro with theos installed works. This project's own sessions ran
theos inside a container built from
[`ghcr.io/regulad/dotfiles:latest-fedora`](https://github.com/regulad/dotfiles)
imported as a WSL distro — a convenient starting point since it already
carries a configured shell/toolchain, but not a requirement; a plain
Fedora/Debian/Ubuntu WSL distro with theos installed manually works
identically. Adjust the `-d <distro>` flag in `build_and_sign.sh` and any
manual `wsl` invocations to match whatever distro name you import it as.

1. Install theos inside the WSL distro, set `THEOS=~/theos`.
2. **Build in a native WSL filesystem path, not `/mnt/c/...` or
   `/mnt/d/...`.** The Windows/WSL 9p mount does not reliably persist
   `chmod`, and theos' packaging step requires `layout/DEBIAN` at ≤0775 and
   the LaunchDaemon plist at exactly 644 — both silently revert to 777 on
   the Windows mount, which breaks the package (launchd refuses a
   group/other-writable plist). `build_and_sign.sh` already handles this by
   building in `~/.cache/oracled-build` (native WSL ext4) and copying the
   finished `.deb` back out to the Windows-side repo checkout.
3. **Don't wipe the build directory between builds.** theos' debug packaging
   auto-increments a build suffix (`0.1.0-1+debug`, `-2+debug`, ...) so
   every iteration installs cleanly — but only if `$BUILD/.theos` survives
   between runs. Deleting the whole build dir resets the counter and can
   produce colliding version strings that `apt`/`dpkg` silently mishandle.
4. Run the build from a Windows shell:
   ```
   wsl -d <your-distro> -e bash -lc '/mnt/c/path/to/oracled/build_and_sign.sh'
   ```
   or run `build_and_sign.sh` directly from inside a WSL shell already
   `cd`'d into the repo.

## 10. Deploy to the device

```
scp packages/<latest>.deb <device-alias>:/tmp/aaoracled.deb
ssh <device-alias> 'sudo apt install /tmp/aaoracled.deb -y'
```

Always use `apt install <path>`, never bare `dpkg -i` (apt handles the
postinst/dependency bookkeeping correctly; bare dpkg has been observed to
leave stale LaunchDaemon jobs behind on removal). `apt` needs a sudo
password on this test device — use whatever credential you've set up for
your own device; don't reuse another environment's password.

## 11. Sanity-check after any fresh install

```
ssh <device-alias> 'curl -s http://127.0.0.1:8181/health'
```

Should report `{"ok": true, ...}`. If it doesn't, re-check step 3 (device
build vs. hardcoded offsets) before debugging anything else.
