#!/usr/bin/env bash
#
# install.sh — connect adb to the Chromebook's Android container (ARCVM) and
# install the TLS Watchdog debug APK.
#
# Prereqs (one-time, done in the ChromeOS UI):
#   Settings -> About ChromeOS -> Developers -> Linux development environment
#     -> "Develop Android apps" -> enable "Enable ADB debugging" (needs a reboot).
#
# Usage:
#   ./install.sh                 # connect to default ARCVM address + install
#   ./install.sh 100.115.92.2:5555   # override the ARCVM adb address
#
set -euo pipefail

# --- locate adb ---------------------------------------------------------------
ADB="$(command -v adb || true)"
if [[ -z "$ADB" ]]; then
    for c in "$HOME/Android/Sdk/platform-tools/adb" "$ANDROID_HOME/platform-tools/adb" \
             "$ANDROID_SDK_ROOT/platform-tools/adb"; do
        [[ -x "$c" ]] && ADB="$c" && break
    done
fi
if [[ -z "$ADB" ]]; then
    echo "error: adb not found. Install platform-tools or add it to PATH." >&2
    exit 1
fi

# --- locate the APK -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APK="$SCRIPT_DIR/app/build/outputs/apk/debug/app-debug.apk"
if [[ ! -f "$APK" ]]; then
    echo "error: APK not found at $APK" >&2
    echo "       build it first:  ./gradlew :app:assembleDebug" >&2
    exit 1
fi

TARGET="${1:-100.115.92.2:5555}"

echo ">> using adb: $ADB"
echo ">> ARCVM target: $TARGET"
echo ">> apk: $APK"
echo

# --- connect ------------------------------------------------------------------
echo ">> connecting..."
"$ADB" connect "$TARGET" || true
sleep 1

# If the device shows as 'unauthorized', the on-device dialog needs accepting.
state="$("$ADB" devices | awk -v t="$TARGET" '$1==t {print $2}')"
if [[ "$state" == "unauthorized" ]]; then
    echo
    echo ">> Device is UNAUTHORIZED."
    echo "   Accept the 'Allow USB debugging?' dialog ON THE CHROMEBOOK"
    echo "   (tick 'Always allow from this computer'), then re-run this script."
    exit 1
fi
if [[ "$state" != "device" ]]; then
    echo
    echo ">> Could not reach the Android container (state: '${state:-none}')." >&2
    echo "   Checklist:" >&2
    echo "     - ADB debugging enabled in ChromeOS settings + rebooted?" >&2
    echo "     - Correct ARCVM address? Try:  ./install.sh <ip:port>" >&2
    echo "     - On managed/enterprise Chromebooks ADB may be blocked by policy." >&2
    exit 1
fi

echo ">> connected."
echo

# --- install ------------------------------------------------------------------
echo ">> installing (reinstall if present)..."
"$ADB" -s "$TARGET" install -r "$APK"

echo
echo ">> done. Launch 'TLS Watchdog' from the ChromeOS launcher."
echo "   Apps tab -> pick an Android app -> Monitor -> Start -> accept VPN consent."
