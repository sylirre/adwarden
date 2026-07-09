# Adwarden

A **no-root** network traffic filter for Android — rule-based ad/tracker
blocking, a per-app firewall (Wi-Fi + mobile), a live decoded traffic log, and
PCAP/HAR capture, built on a local `VpnService`.

## Technical details

```
Kotlin / Jetpack Compose (Material 3)        ← UI, ViewModels (Hilt)
        ▲  StateFlow (CaptureRepository)      Room + DataStore, WorkManager
        │
VpnService (AdwardenVpnService)              ← TUN, foreground service, consent
        │  TUN fd (detachFd) + control (rules, firewall, config, pcap)
        ▼          ▲  batched events / protect() / getConnectionOwnerUid (JNI)
Rust native core (libadwarden_core.so)
   ├─ smoltcp userspace TCP proxy (per-flow listen, protected upstream relay)
   ├─ hand-rolled UDP NAT + DNS sinkhole
   ├─ adblock-rust filter engine (serialized cache)
   ├─ per-app firewall (uid → per-transport policy)
   └─ pcapng tap
```

The core is a `rust/` cargo workspace (`core` cdylib + `netstack` / `dns` /
`filter` / `pcap` host-testable libs) built per-ABI by the
`org.mozilla.rust-android-gradle` plugin. Kotlin↔Rust is a thin hand-written JNI
bridge (`NativeCore` / `NativeBridge`).

### Stack

Kotlin · Jetpack Compose · Material 3 · Hilt · Room · DataStore · WorkManager ·
OkHttp · `minSdk 30` (Android 11) · `targetSdk 36` (Android 16). Native core:
Rust (smoltcp / adblock-rust / mio / socket2 / pcap-file) — all permissively
licensed for a closed-source product.

### Project structure

```
app/src/main/java/com/adwarden/
  core/            Capture models, NativeCore/NativeBridge (JNI), event codec
  data/            CaptureRepository, Filter/AppRule repos, Room db, DataStore
  firewall/        AppInventory, NetworkStateMonitor
  work/            FilterSyncWorker (WorkManager)
  capture/         PcapSessionManager
  vpn/             AdwardenVpnService (TUN + native handoff + control observers)
  ui/screens/      Onboarding, Dashboard, Apps, Traffic, Filters, Settings (+VMs)
rust/
  core/            cdylib: ffi, bridge, runtime (mio loop), forward, event
  netstack/        smoltcp TCP proxy, UDP helpers, packet decode, flow table
  dns/ filter/ pcap/  DNS synth, adblock engine wrapper, pcapng writer
```

## Build & run

Requires JDK 17+ and an Android SDK with platform 36 and NDK 28.

### Native build

`./gradlew :app:assembleDebug` runs `cargoBuild` to cross-compile the Rust core
and packages the per-ABI `libadwarden_core.so`. The Android targets install
automatically on first build (rustup 1.28+); if your toolchain doesn't
auto-install them, add them once:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  i686-linux-android x86_64-linux-android
```

`scripts/build-native.sh` builds the native side in isolation (via `cargo ndk`)
as a CI substitute. Host-side Rust tests run with `cd rust && cargo test
--workspace`.

```bash
export ANDROID_SDK_ROOT=/path/to/Android/Sdk   # or set sdk.dir in local.properties
./gradlew :app:assembleDebug
adb install -r -t app/build/outputs/apk/debug/app-debug.apk
```

Then launch, complete onboarding, and tap **Turn on protection** (accept the VPN
consent). Browse to see the Traffic log and Dashboard populate, toggle a
subscription on Filters, or block an app on Apps.
