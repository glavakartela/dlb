#!/usr/bin/env bash
# One-time: generate the platform runner folders (android/, linux/, windows/) around lib/.
set -euo pipefail
cd "$(dirname "$0")/.."
flutter create --platforms=android,linux,windows --project-name dlb_app --org dev.dlb .
rm -f test/widget_test.dart   # template counter test does not apply to this app
flutter pub get

# Android: plugins (desktop_drop, file_picker, ...) need compileSdk >= 34 (Android 14).
# Force a modern SDK level instead of relying on the Flutter template default.
for f in android/app/build.gradle.kts android/app/build.gradle; do
  [ -f "$f" ] || continue
  sed -i -E \
    -e 's/compileSdk(Version)? *(=)? *[^\r\n]*/compileSdk = 36/' \
    -e 's/targetSdk(Version)? *(=)? *[^\r\n]*/targetSdk = 36/' \
    -e 's/minSdk(Version)? *(=)? *[^\r\n]*/minSdk = 24/' "$f"
  # Groovy file uses space syntax without '='
  case "$f" in *.gradle) sed -i -E 's/^( *)(compileSdk|targetSdk|minSdk) = /\1\2 /' "$f";; esac
  grep -n -E "compileSdk|targetSdk|minSdk" "$f" || true
done
