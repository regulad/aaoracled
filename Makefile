# aaoracled — one combined roothide .deb: injects OracledDCPatch into
# devicecheckd (ElleKit) and installs the aaoracled CLI/daemon + its
# LaunchDaemon plist. One theos project, two target instances (a TWEAK_NAME
# and a TOOL_NAME) declared in sequence in this single flat Makefile — theos
# supports multiple target instances per Makefile without SUBPROJECTS/
# aggregate.mk, which is what lets both ship from one shared `control` +
# `layout/` as a single package.
export THEOS_PACKAGE_SCHEME = roothide

TARGET = iphone:clang:16.5:15.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

# --- devicecheckd tweak --------------------------------------------------
# Patches DCClientHandler so App Attest identity comes from a caller-supplied
# file (written by `aaoracled`) instead of being gated on the calling
# process's code-signing legitimacy.
TWEAK_NAME = OracledDCPatch

OracledDCPatch_FILES = Tweak.x
OracledDCPatch_CFLAGS = -fobjc-arc -Wall
OracledDCPatch_FRAMEWORKS = Security
# roothide libSandy fork: lets this tweak grant devicecheckd (sandboxed) read
# access to the one file aaoracled uses to hand it a forced App ID. No
# dev-stub (.tbd) for it is available in this theos install, and it's a real
# runtime dependency (control: com.opa334.libsandy) present in devicecheckd
# once loaded there — so leave the one symbol unresolved at link time and
# let dyld bind it on-device, rather than linking against a stub library.
OracledDCPatch_LDFLAGS += -Wl,-U,_libSandy_applyProfile

include $(THEOS_MAKE_PATH)/tweak.mk

# --- aaoracled CLI/daemon --------------------------------------------------
# On-device App Attest oracle: a headless REST API driving DCAppAttestService
# directly. Packaged (not a bare scp'd binary) because a raw binary dropped
# outside the package-managed tree gets SIGKILLed at launch on this device —
# the roothide-required entitlements plus a real dpkg install are what make a
# standalone (non-app-bundle) binary run at all.
TOOL_NAME = aaoracled

aaoracled_FILES = oracled.m
aaoracled_FRAMEWORKS = Foundation DeviceCheck
aaoracled_CFLAGS = -fobjc-arc -Wno-unused-parameter
aaoracled_INSTALL_PATH = /usr/local/bin
aaoracled_CODESIGN_FLAGS = -Sentitlements.plist
# Embed a real Info.plist so NSBundle.mainBundle has a CFBundleIdentifier,
# even though this is a bare tool (no .app wrapper) — DCAppAttestService.
# isSupported needs this to be non-nil.
aaoracled_LDFLAGS += -Wl,-sectcreate,__TEXT,__info_plist,Info.plist

include $(THEOS_MAKE_PATH)/tool.mk

# Restart both on `make install` (SSH-over-USB iterate loop); the packaged
# .deb's postinst (layout/DEBIAN/postinst) handles the apt/Sileo/dpkg-install
# path instead.
INSTALL_TARGET_PROCESSES = devicecheckd aaoracled
