# TLS Watchdog

An on-device Android VPN that flags outbound connections **not** using TLS, so you can
verify which apps encrypt their traffic (e.g. catch an app doing raw HTTP).

It uses `VpnService` (no root) to route traffic through a userspace TCP/UDP forwarder
([zdtun](https://github.com/emanuele-f/zdtun), LGPL — the same engine PCAPdroid uses).
By default it routes **only the apps you select** (the main performance lever); a
**"Monitor all apps"** toggle on the Monitor tab switches to full-system mode, routing every
app except itself. For each TCP flow it inspects the first client→server payload and records a
verdict: `TLS`, `CLEARTEXT_HTTP`, `CLEARTEXT_OTHER`, or `UNKNOWN`.

## Architecture

```
selected apps → TUN (VpnService) → zdtun (native) → protect()'d sockets → internet
                                       │
                     first client→server payload (JNI onFlow)
                                       ▼
                 FlowClassifier → Room DB → Compose UI + cleartext notification
```

- `app/src/main/cpp/native_bridge.c` — JNI + zdtun select loop; protects sockets, snapshots
  the first TCP payload per flow.
- `app/src/main/cpp/zdtun/` — vendored zdtun library (LGPL-3.0).
- `vpn/TlsWatchdogVpnService.kt` — builds the TUN with `addAllowedApplication` (per-app
  scoping = the main performance lever) or, in full-system mode, `addDisallowedApplication`
  for just itself; foreground service, classify→attribute→persist→alert.
- `detect/FlowClassifier.kt` — content-based TLS/cleartext detection (never port-based).
- `attribution/Attribution.kt` — `getConnectionOwnerUid` (API 29+) → package/label.
- `ui/` + `MainActivity.kt` — Monitor / Apps / Flows tabs, CSV export.

## Build

Requires JDK 17 + Android SDK (platform 35, build-tools 35, NDK r27, CMake 3.22.1).
`local.properties` must point `sdk.dir` at the SDK.

```bash
./gradlew :app:assembleDebug        # -> app/build/outputs/apk/debug/app-debug.apk
./gradlew :app:testDebugUnitTest    # FlowClassifier unit tests
```

### Release build (signed, minified)

Release signing reads `keystore.properties` (gitignored) at the repo root:

```
storeFile=/absolute/path/to/your-release.jks
storePassword=...
keyAlias=...
keyPassword=...
```

Create a keystore once with `keytool -genkeypair -keystore <path>.jks -alias <alias>
-keyalg RSA -keysize 2048 -validity 10000`, then:

```bash
./gradlew :app:assembleRelease      # -> app/build/outputs/apk/release/app-release.apk
```

R8 is enabled; `app/proguard-rules.pro` keeps the JNI native methods and the
`VpnCallbacks` methods (resolved from C by name) — do not remove those keeps.
**Keep the keystore + passwords safe**: the same key is required to ship updates.

## Install & run

**On a phone (USB):**
```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

**On a phone (Wi‑Fi / wireless debugging, no cable):** requires Android 11+ and the
phone + computer on the same network (client isolation off — a phone hotspot works if
normal Wi‑Fi blocks device-to-device). `adb` here means
`~/Android/Sdk/platform-tools/adb`.

1. Phone → Settings → Developer options → **Wireless debugging** → on.
2. Tap **"Pair device with pairing code"**. It shows an IP:port and a 6‑digit code.
   These are **regenerated every time the dialog opens** and expire after ~1 minute.
3. Pair, passing the code as an argument (avoids the interactive prompt):
   ```bash
   adb pair 192.168.x.y:<pair-port> <6-digit-code>
   ```
   If it errors with `protocol fault (couldn't read status message)`, the session went
   stale: `adb kill-server`, reopen the pairing dialog for a fresh port+code, retry fast.
4. Connect using the Wireless‑debugging **main screen** IP:port (different from the pair
   port), then install:
   ```bash
   adb connect 192.168.x.y:<connect-port>
   adb devices
   adb -s 192.168.x.y:<connect-port> install app/build/outputs/apk/release/app-release.apk
   ```
   `-s` is required when another device (e.g. the ChromeOS ARCVM `100.115.92.2:5555`) is
   also attached.

**On a Chromebook (locally, into ChromeOS's Android/ARCVM):** the debug build includes an
`x86_64` native lib for this. One-time: enable ADB in
`Settings → About ChromeOS → Developers → "Develop Android apps" → Enable ADB debugging`
(requires a reboot). Then:
```bash
./install.sh                     # connects to ARCVM (100.115.92.2:5555) + installs
./install.sh <ip:port>           # if your ARCVM adb address differs
```
Accept the "Allow USB debugging?" dialog on the Chromebook the first time.
Note: only *Android* apps' traffic is seen — not the ChromeOS browser or Linux/Crostini apps.
Managed/enterprise Chromebooks may block ADB by policy.

Then, on either platform:
1. Open the app → **Apps** tab → tick the app(s) to audit (e.g. your bank). Or, on the
   **Monitor** tab, flip **"Monitor all apps"** to audit the whole device instead.
2. **Monitor** tab → **Start monitoring** → accept the system VPN consent dialog.
3. Use the audited apps; watch verdicts appear in the **Flows** tab.

## Verification checklist

1. **Connectivity** — with monitoring on, the selected apps must still work normally.
2. **TLS true-negative** — open an HTTPS site in an audited browser → verdict `TLS`, no alert.
3. **Cleartext true-positive** — hit `http://neverssl.com` (or `python3 -m http.server` on your
   LAN) from an audited app → verdict `CLEARTEXT_HTTP`, a "Cleartext detected" notification,
   and it shows under the **Cleartext only** filter, attributed to the right app.
4. **Port independence** — plain HTTP on :443 is still flagged; TLS on :8443 is still `TLS`.
5. **Export** — Flows tab → **Export** writes a CSV of all recorded flows.

## Notes / limits

- Only one `VpnService` can run at a time (no-root limitation) — can't run alongside another VPN.
- MVP classifies **TCP**. UDP/QUIC is forwarded but not yet classified (Phase 3).
- Per-app routing means only selected apps pay the userspace-forwarding cost; everything else
  bypasses at the kernel. Full-system mode ("Monitor all apps") routes everything and costs more
  battery/latency accordingly.
