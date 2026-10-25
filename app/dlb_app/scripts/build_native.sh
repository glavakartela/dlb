#!/usr/bin/env bash
# Build the Rust core as a shared library and put it where Flutter bundles it.
# Usage: scripts/build_native.sh android|linux|windows
set -euo pipefail
APP="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$APP/../.." && pwd)"
cd "$ROOT"
case "${1:-}" in
  android)   # needs: cargo install cargo-ndk, ANDROID_NDK_HOME, rustup android targets
    cargo ndk -t arm64-v8a -t armeabi-v7a -t x86 -t x86_64 \
      -o "$APP/android/app/src/main/jniLibs" build --release ;;
  linux)     # run after `flutter build linux --release`
    cargo build --release
    install -D target/release/libdlbcore.so "$APP/build/linux/x64/release/bundle/lib/libdlbcore.so" ;;
  windows)   # run after `flutter build windows --release` (Git Bash / MSYS)
    cargo build --release
    cp target/release/dlbcore.dll "$APP/build/windows/x64/runner/Release/dlbcore.dll" ;;
  *) echo "usage: $0 android|linux|windows"; exit 2 ;;
esac
