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
Rust (smoltcp / adblock-rust / mio / socket2 / pcap-file) — all under
GPLv3-compatible licenses (see [License](#license)).

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

## License

Adwarden is free software, licensed under the **GNU General Public License,
version 3 or (at your option) any later version** (`GPL-3.0-or-later`). The full
text is in [`LICENSE`](LICENSE).

    Copyright (C) 2026 Sylirre

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the Free
    Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along
    with this program. If not, see <https://www.gnu.org/licenses/>.

### Third-party components

Every dependency shipped in the app is GPLv3-compatible:

- **Android/Kotlin stack** (AndroidX, Jetpack Compose, Material 3, Hilt/Dagger,
  Room, DataStore, WorkManager, OkHttp, Kotlin stdlib/coroutines) — Apache-2.0.
- **Rust core crates** — permissive (MIT / BSD-3-Clause / ISC / 0BSD /
  Unicode-3.0 / CDLA-Permissive-2.0) or Apache-2.0, with two weak-copyleft
  cases: **adblock-rust** (MPL-2.0) and **ring**'s BoringSSL-derived code
  (Apache-2.0 / ISC).

GPLv3 (rather than GPLv2) is the required copyleft here because several
dependencies are Apache-2.0, which is compatible with GPLv3 but not GPLv2.
MPL-2.0 files (from `adblock-rust`) stay under the MPL; distributing them as
part of a GPL-licensed larger work is expressly permitted by MPL-2.0 §3.3.
Test-only tooling that is not distributed with the app (e.g. JUnit, EPL-1.0)
does not affect the license of the shipped binary.

The built-in scriptlet pack under [`scriptlets/`](scriptlets/) is additionally
made available under the MIT License (see `scriptlets/README.md`); MIT is
GPL-compatible, so it may be used under either license.
