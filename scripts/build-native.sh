#!/usr/bin/env bash
#
# Build the Adwarden Rust native core (libadwarden_core.so) for every Android
# ABI and drop the artifacts into app/src/main/jniLibs/<abi>/.
#
# This is the CI-substitute / CLI fallback for the org.mozilla.rust-android-gradle
# plugin: `./gradlew :app:assembleDebug` already runs `cargoBuild` and merges the
# .so files, but this script is handy for building the native side in isolation
# (e.g. to inspect symbols or size) without a full Gradle run.
#
# Prerequisites (one-time):
#   1. Android std targets. This machine's rustup home (/usr/local/lib/rustup) is
#      root-owned, so installing targets needs sudo:
#
#        sudo rustup target add aarch64-linux-android armv7-linux-androideabi \
#                               i686-linux-android x86_64-linux-android
#
#   2. cargo-ndk (installs into the writable ~/.cargo/bin):
#
#        cargo install cargo-ndk
#
#   3. NDK present at $ANDROID_NDK_HOME (defaults below to the SDK's NDK 28).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$ROOT_DIR/rust"
JNILIBS_DIR="$ROOT_DIR/app/src/main/jniLibs"

export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/Android/Sdk/ndk/28.2.13676358}"

if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
  echo "error: NDK not found at $ANDROID_NDK_HOME (set ANDROID_NDK_HOME)" >&2
  exit 1
fi

# cargo-ndk ABI names map to the Rust target triples internally.
ABIS=(arm64-v8a armeabi-v7a x86_64 x86)

echo "==> Building adwarden_core for: ${ABIS[*]}"
cd "$RUST_DIR"
cargo ndk \
  --manifest-path "$RUST_DIR/core/Cargo.toml" \
  -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
  -o "$JNILIBS_DIR" \
  build --release

echo "==> Native libraries:"
find "$JNILIBS_DIR" -name 'libadwarden_core.so' -print -exec ls -lh {} \;
