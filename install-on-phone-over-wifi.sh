#!/usr/bin/env bash
#
# install-on-phone-over-wifi.sh — build TLS Watchdog and install it on an Android
# phone over Wi-Fi (wireless debugging, no cable). Requires Android 11+ on the phone
# and the phone + this computer on the same network (device-to-device allowed).
#
# It:
#   1. Builds the release APK (incremental — Gradle skips the work if up-to-date).
#   2. Reuses an existing Wi-Fi connection / pairing if there is one.
#   3. Otherwise walks you through adb pairing + connecting, then streams the install.
#
# Usage:
#   ./install-on-phone-over-wifi.sh            # build release, install over Wi-Fi
#   ./install-on-phone-over-wifi.sh --debug    # build+install the debug APK instead
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="$SCRIPT_DIR/.phone-wifi-target"   # remembers the last connect ip:port
ARCVM="100.115.92.2:5555"                     # ChromeOS Android container — never the phone
PKG="com.example.tlswatchdog"

BUILD_TYPE="release"
[[ "${1:-}" == "--debug" ]] && BUILD_TYPE="debug"

say() { printf '\033[36m>> %s\033[0m\n' "$*"; }
ask() { local p="$1"; local __v="$2"; local a; read -rp "   $p" a; printf -v "$__v" '%s' "$a"; }

# --- locate adb --------------------------------------------------------------
ADB="$(command -v adb || true)"
if [[ -z "$ADB" ]]; then
    for c in "$HOME/Android/Sdk/platform-tools/adb" "${ANDROID_HOME:-}/platform-tools/adb" \
             "${ANDROID_SDK_ROOT:-}/platform-tools/adb"; do
        [[ -x "$c" ]] && ADB="$c" && break
    done
fi
[[ -n "$ADB" ]] || { echo "error: adb not found. Install platform-tools or add it to PATH." >&2; exit 1; }

# --- 1. build (incremental) --------------------------------------------------
if [[ "$BUILD_TYPE" == "debug" ]]; then
    say "Building debug APK (Gradle skips this if already up-to-date)…"
    "$SCRIPT_DIR/gradlew" -p "$SCRIPT_DIR" :app:assembleDebug
    APK="$SCRIPT_DIR/app/build/outputs/apk/debug/app-debug.apk"
else
    say "Building release APK (Gradle skips this if already up-to-date)…"
    "$SCRIPT_DIR/gradlew" -p "$SCRIPT_DIR" :app:assembleRelease
    APK="$SCRIPT_DIR/app/build/outputs/apk/release/app-release.apk"
fi
if [[ ! -f "$APK" ]]; then
    echo "error: APK not found at $APK" >&2
    [[ "$BUILD_TYPE" == "release" ]] && echo "       (release signing needs keystore.properties at the repo root)" >&2
    exit 1
fi
say "APK: $APK"

# --- adb helpers -------------------------------------------------------------
# True if $1 (a serial/ip:port) is present and in the 'device' state.
is_online() { "$ADB" devices | awk -v t="$1" '$1==t && $2=="device"{f=1} END{exit f?0:1}'; }
# Poll is_online for a few seconds (a fresh connect can take a moment to settle).
wait_online() { local t="$1" i; for i in 1 2 3 4 5 6; do is_online "$t" && return 0; sleep 0.5; done; return 1; }
# Print an already-connected wireless device (ip:port), excluding the ARCVM.
find_connected_wifi() {
    "$ADB" devices | awk -v arc="$ARCVM" \
        '$2=="device" && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/ && $1!=arc {print $1; exit}'
}

TARGET=""

# --- 2a. already connected? --------------------------------------------------
existing="$(find_connected_wifi || true)"
if [[ -n "$existing" ]]; then
    say "Phone already connected over Wi-Fi: $existing"
    TARGET="$existing"
fi

# --- 2b. try the last-used address (already paired ⇒ connect just works) ------
if [[ -z "$TARGET" && -f "$STATE_FILE" ]]; then
    last="$(cat "$STATE_FILE" 2>/dev/null || true)"
    if [[ -n "$last" ]]; then
        say "Trying last-used address $last …"
        "$ADB" connect "$last" >/dev/null 2>&1 || true
        if wait_online "$last"; then say "Connected (this computer is already paired)."; TARGET="$last"; fi
    fi
fi

# --- 3. connect, pairing first only if needed --------------------------------
if [[ -z "$TARGET" ]]; then
    cat <<'EOS'

   On the phone:
     Settings → Developer options → Wireless debugging → turn ON.
     Tap "Wireless debugging" to open its screen. Near the top, under the
     device name, it shows "IP address & Port", e.g.  192.168.1.23:39000
     — that is the CONNECT address (its port changes each time you toggle
     wireless debugging on).

EOS
    ask "Enter the phone's Wireless-debugging IP:port (connect): " TARGET
    [[ -n "$TARGET" ]] || { echo "no address entered"; exit 1; }

    say "Trying to connect (works without a code if this computer is already paired)…"
    "$ADB" connect "$TARGET" >/dev/null 2>&1 || true

    if ! wait_online "$TARGET"; then
        cat <<'EOS'

   Not connected yet — this computer isn't paired with the phone. Let's pair
   (one-time). On the phone's Wireless-debugging screen:
     Tap "Pair device with pairing code".
     A pop-up shows a DIFFERENT ip:port and a 6-digit code. Both are
     regenerated every time the pop-up opens and expire after ~1 minute,
     so enter them promptly below.

EOS
        ask "PAIRING ip:port (from the pop-up): " PAIRADDR
        ask "6-digit pairing code: " PAIRCODE
        say "Pairing…"
        if ! "$ADB" pair "$PAIRADDR" "$PAIRCODE"; then
            echo "pair failed. If it said 'protocol fault', the code went stale:" >&2
            echo "  run '$ADB kill-server', reopen the pairing pop-up for a fresh code, and retry." >&2
            exit 1
        fi
        say "Paired. Connecting to $TARGET …"
        "$ADB" connect "$TARGET" >/dev/null 2>&1 || true
        wait_online "$TARGET" || {
            echo "connected-pairing ok but connect failed. Re-check the CONNECT ip:port on the" >&2
            echo "main Wireless-debugging screen (it differs from the pairing pop-up's port)." >&2
            exit 1
        }
    fi
    say "Connected."
fi

# Remember for next time.
printf '%s\n' "$TARGET" > "$STATE_FILE"

# --- install (streamed) ------------------------------------------------------
say "Installing $BUILD_TYPE build (reinstall if present)…"
if out="$("$ADB" -s "$TARGET" install -r "$APK" 2>&1)"; then
    printf '%s\n' "$out"
else
    printf '%s\n' "$out"
    if grep -qE "INSTALL_FAILED_UPDATE_INCOMPATIBLE|signatures do not match" <<<"$out"; then
        echo
        say "A differently-signed build of $PKG is already installed."
        ask "Uninstall it (this ERASES the app's captured flows) and reinstall? [y/N] " ANS
        if [[ "${ANS:-}" == [yY]* ]]; then
            "$ADB" -s "$TARGET" uninstall "$PKG" || true
            "$ADB" -s "$TARGET" install -r "$APK"
        else
            echo "Aborted — nothing installed."; exit 1
        fi
    else
        exit 1
    fi
fi

echo
say "Done. Launch 'TLS Watchdog' on the phone."
say "  Apps tab → pick app(s) → Monitor → Start → accept the VPN consent dialog."
