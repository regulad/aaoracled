#!/usr/bin/env bash
# Build App A with theos and sign it with the GENUINE Apple Development cert +
# provisioning profile using rcodesign. On Linux/macOS run directly; on
# Windows run inside WSL as a LOGIN shell so $PATH (rcodesign) and $THEOS
# are set, e.g.:
#
#   wsl -d <your-distro> -e bash -lc '/mnt/c/path/to/oracled/fixtures/appa/build_and_sign.sh'
#
# Produces a signed appa.app and an appa.ipa ready to install on the device.
set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
APPA="$REPO/fixtures/appa"
ART="$REPO/artifacts"
export THEOS="${THEOS:-$HOME/theos}"

PEM="$ART/appA_dev_signing.pem"   # unencrypted key + leaf cert + WWDR G3
PROFILE="$ART/appone.mobileprovision"
ENT="$APPA/entitlements.plist"
OUT="$APPA/build"

command -v rcodesign >/dev/null || { echo "rcodesign not on PATH (need login shell)"; exit 1; }
[ -d "$THEOS" ] || { echo "THEOS not found at $THEOS"; exit 1; }

# --- 1. Signing material (PEM bundle built on the Windows side; no PFX crypto) ---
[ -f "$PEM" ] || { echo "missing $PEM — build it: cat appA_dev.key <dev.pem> <wwdr.pem> > $PEM"; exit 1; }

# --- 2. Build the .app with theos ---
echo ">> theos build"
cd "$APPA"
make clean >/dev/null 2>&1 || true
make
APP="$(find "$APPA/.theos" -maxdepth 5 -type d -name 'appa.app' | head -1)"
[ -n "$APP" ] || { echo "could not locate built appa.app under .theos"; exit 1; }
echo ">> built: $APP"

# --- 3. Stage + embed the provisioning profile, then rcodesign ---
rm -rf "$OUT"; mkdir -p "$OUT"
STAGE="$OUT/appa.app"
cp -a "$APP" "$STAGE"
cp "$PROFILE" "$STAGE/embedded.mobileprovision"

echo ">> rcodesign sign (genuine Apple Development identity)"
rcodesign sign \
  --pem-file "$PEM" \
  --entitlements-xml-file "$ENT" \
  "$STAGE"

echo ">> verify signature"
rcodesign verify "$STAGE" || true

# --- 4. Package an .ipa for install ---
cd "$OUT"
rm -rf Payload appa.ipa; mkdir Payload; cp -a appa.app Payload/
( zip -qr appa.ipa Payload )
echo ">> DONE: $OUT/appa.ipa"
echo
echo "Install on device (pick one):"
echo "  go-ios (USB):   ios install --path=$OUT/appa.ipa"
echo "  TrollStore:     copy appa.ipa to device and open in TrollStore"
