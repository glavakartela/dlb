#!/usr/bin/env bash
# One-time: generate the platform runner folders (android/, linux/, windows/) around lib/.
set -euo pipefail
cd "$(dirname "$0")/.."
flutter create --platforms=android,linux,windows,macos --project-name dlb_app --org dev.dlb .
rm -f test/widget_test.dart   # template counter test does not apply to this app
flutter pub get

# Android: plugins (desktop_drop, file_picker, ...) need compileSdk >= 34 (Android 14).
# Force a modern SDK level instead of relying on the Flutter template default.
for f in android/app/build.gradle.kts android/app/build.gradle; do
  [ -f "$f" ] || continue
  sed -i -E \
    -e 's/compileSdk(Version)? *(=)? *[^\r\n]*/compileSdk = 36/' \
    -e 's/targetSdk(Version)? *(=)? *[^\r\n]*/targetSdk = 35/' \
    -e 's/minSdk(Version)? *(=)? *[^\r\n]*/minSdk = 24/' "$f"
  # Groovy file uses space syntax without '='
  case "$f" in *.gradle) sed -i -E 's/^( *)(compileSdk|targetSdk|minSdk) = /\1\2 /' "$f";; esac
  grep -n -E "compileSdk|targetSdk|minSdk" "$f" || true
done

# Plugins (file_picker, ...) are compiled against their own, older compileSdk, but their
# dependencies (flutter_plugin_android_lifecycle) need 36+. Raise it for every subproject.
if [ -f android/build.gradle.kts ]; then
  cat >> android/build.gradle.kts <<'KTS'

subprojects {
    val sub = this
    fun raiseCompileSdk() {
        sub.extensions.findByName("android")?.withGroovyBuilder { "compileSdkVersion"(36) }
    }
    if (sub.state.executed) raiseCompileSdk() else sub.afterEvaluate { raiseCompileSdk() }
}
KTS
elif [ -f android/build.gradle ]; then
  cat >> android/build.gradle <<'GRV'

subprojects {
    def raise = { p -> if (p.hasProperty('android')) { p.android { compileSdkVersion 36 } } }
    if (state.executed) { raise(project) } else { afterEvaluate { raise(it) } }
}
GRV
fi

# macOS: the sandboxed app needs access to files the user picks, and writes next to them.
for f in macos/Runner/DebugProfile.entitlements macos/Runner/Release.entitlements; do
  [ -f "$f" ] || continue
  /usr/libexec/PlistBuddy -c "Add :com.apple.security.files.user-selected.read-write bool true" "$f" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Add :com.apple.security.files.downloads.read-write bool true" "$f" 2>/dev/null || true
done
