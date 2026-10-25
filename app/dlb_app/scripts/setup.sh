#!/usr/bin/env bash
# One-time: generate the platform runner folders (android/, linux/, windows/) around lib/.
set -euo pipefail
cd "$(dirname "$0")/.."
flutter create --platforms=android,linux,windows --project-name dlb_app --org dev.dlb .
rm -f test/widget_test.dart   # template counter test does not apply to this app
flutter pub get
