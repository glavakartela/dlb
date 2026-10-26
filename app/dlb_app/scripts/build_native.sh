#!/usr/bin/env bash
# Build the Rust core as a shared library and put it where Flutter bundles it.
# Usage: scripts/build_native.sh android|linux|windows|macos
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
  macos)     # run after `flutter build macos --release`; universal (arm64 + x86_64) dylib
    rustup target add aarch64-apple-darwin x86_64-apple-darwin
    cargo build --release --target aarch64-apple-darwin --lib
    cargo build --release --target x86_64-apple-darwin --lib
    APPDIR="$(ls -d "$APP"/build/macos/Build/Products/Release/*.app | head -n1)"
    mkdir -p "$APPDIR/Contents/Frameworks"
    lipo -create -output "$APPDIR/Contents/Frameworks/libdlbcore.dylib" \
      target/aarch64-apple-darwin/release/libdlbcore.dylib \
      target/x86_64-apple-darwin/release/libdlbcore.dylib
    install_name_tool -id "@rpath/libdlbcore.dylib" "$APPDIR/Contents/Frameworks/libdlbcore.dylib"
    # ad-hoc sign so the app launches on Apple Silicon (not notarized; see README)
    codesign --force --sign - "$APPDIR/Contents/Frameworks/libdlbcore.dylib"
    codesign --force --deep --sign - "$APPDIR"
    echo "$APPDIR" ;;
  *) echo "usage: $0 android|linux|windows|macos"; exit 2 ;;
esac
