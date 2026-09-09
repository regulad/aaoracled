# theos Application: builds appa.app (ObjC, links DeviceCheck for App Attest).
# We build the .app here, then sign it with a genuine Apple Development cert +
# provisioning profile using rcodesign (see build_and_sign.sh) — theos'
# own ldid pseudo-signing is NOT used, because App Attest needs the real
# team-issued signature.
#
# SDK 16.5 (ships DeviceCheck), deployment target iOS 15.0, arm64 (A8 device).
export ARCHS = arm64
export TARGET = iphone:clang:16.5:15.0

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = appa

appa_FILES = main.m AppDelegate.m AttestClient.m
appa_FRAMEWORKS = UIKit Foundation DeviceCheck
appa_CFLAGS = -fobjc-arc -Wno-unused-parameter
# theos ad-hoc ldid-signs here; rcodesign later overwrites it with the real
# Apple Development identity + entitlements + embedded.mobileprovision.

include $(THEOS)/makefiles/application.mk
