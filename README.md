# DLB

A maximum-ratio file compressor with its own `.dlb` format, written in pure Rust (no
dependencies), plus a Flutter app on top of it.

DLB uses **context mixing** (the PAQ / lpaq / cmix family) instead of LZ77 + Huffman like zip,
xz and zstd. It is the strongest practical approach to lossless compression; the price is speed
(about 0.4 MB/s, in both directions).

## Command line

```
dlb c [-l 1-9] [-o out.dlb] <file|dir>...   compress  (level 7 default: ~115 MB RAM; 4: ~25 MB; 9: ~305 MB)
dlb x <archive.dlb> [-C dir] [-f]           extract   (-f overwrites existing files)
dlb t <archive.dlb>                         test integrity (CRC-32)
dlb l <archive.dlb>                         list contents
```

Several files or folders are packed into one *solid* archive (files are grouped by extension),
which noticeably improves the ratio. Extraction refuses paths that escape the target folder and
never overwrites without `-f`.

## Results (level 7, single thread)

| data | original | xz -9e | bzip2 -9 | **dlb** |
|---|---|---|---|---|
| Python source, 3 MB | 3,145,728 | 474,832 | 510,856 | **376,287** (x8.4) |
| executables, 3 MB | 3,000,000 | 609,884 | 859,313 | **589,283** (x5.1) |
| text logs, 5.6 MB | 5,600,732 | 221,060 | 208,194 | **168,227** (x33) |
| same file x4 (12.6 MB) | 12,582,912 | 476,216 | 2,089,787 | **380,056** (x33) |
| random data, 1 MB | 1,000,000 | 1,000,108 | 1,004,741 | 1,000,047 (x1.0) |
| zeros, 20 MB | 20,000,000 | 3,040 | 50 | 1,807 (x11,000) |

Every row was verified by decompressing and comparing byte for byte.

### What to expect

A ratio of "tens of times" is only possible when the data is redundant (logs, repeated content,
templated text, sparse data). Already-compressed formats (JPEG, MP4, ZIP, archives) and
encrypted or random data cannot be compressed at all; that is a theorem, not a limitation of
this program. Typical text and source code compress x4 to x9, executables x3 to x5.

## Flutter app (`app/dlb_app`)

A native-feeling UI over the same core, designed with the ui-ux-pro-max guidelines:

- OLED-black "Dark Mode" with Material You tonal surfaces (wallpaper colors on Android 12+,
  green accent elsewhere)
- touch targets of at least 48 dp, labels and semantics for screen readers, reduced-motion aware
- bottom navigation bar on phones, navigation rail on wide windows, content width capped at 640 px
- vector icons only
- **English by default**; Russian can be selected on the Help page (the choice is remembered)

Screens: **Compress** (files or folder, drag and drop on desktop, three presets, progress with
speed and ETA, cancel), **Extract** (with integrity check), **Help**.

The app calls the Rust core through `dart:ffi` (`src/ffi.rs`). Work runs on a background thread,
the UI polls progress, and cancelling is safe.

### Build the app

```
cd app/dlb_app
scripts/setup.sh                       # once: generates android/, linux/, windows/ runner folders
flutter build linux --release   && scripts/build_native.sh linux
flutter build windows --release && scripts/build_native.sh windows
scripts/build_native.sh android && flutter build apk --release --split-per-abi
```

`build_native.sh` builds the Rust core as a shared library (`libdlbcore.so` / `dlbcore.dll`)
and puts it where Flutter bundles it. Android needs `cargo install cargo-ndk`, the NDK and the
four Rust Android targets.

## Building the CLI

```
cargo build --release
cargo test --release
```

## CI

Three independent GitHub Actions workflows in `.github/workflows/`:

| workflow | jobs | artifacts |
|---|---|---|
| `linux.yml` | static musl CLI for x86_64, i686, aarch64, armv7; Flutter app (x64) | `dlb-cli-*`, `dlb-app-linux-x64` |
| `windows.yml` | CLI for x64, x86, arm64 (MSVC); Flutter app (x64) | `dlb-cli-*`, `dlb-app-windows-x64` |
| `android.yml` | APKs for arm64-v8a, armeabi-v7a, x86, x86_64 | `dlb-app-android` |

The static Linux CLI binaries also run on Android through `adb shell` or Termux. The whole
algorithm is integer-only, so an archive made on one architecture decompresses bit-identically
on any other.

## `.dlb` format (little endian)

| offset | size | field |
|---|---|---|
| 0 | 4 | magic `DLB1` |
| 4 | 1 | flags (bit 0: data stored uncompressed, used as a fallback) |
| 5 | 1 | `nbits`: log2 of the number of context-table slots |
| 6 | 8 | payload length |
| 14 | 4 | CRC-32 of the payload |
| 18 | ... | arithmetic-coder stream |

Payload: `"DLAR"`, entry count, then per entry `name_len u16 | name | size u64 | mode u32`,
followed by the data of all files back to back.

## Model

- 12 hashed contexts: orders 0-6 and 8, two word contexts, two sparse contexts; 32-bit slots
  (8-bit check, 6-bit count, 18-bit probability) laid out in cache lines (nibble buckets)
- 2 long-range match models (minimum length 20 and 6)
- 3 first-layer mixers (selected by partial byte, previous byte, match state) and a
  second-layer mixer
- 2 APM/SSE stages and a 32-bit arithmetic coder with 16-bit probabilities

## Limits (version 0.1)

- one archive is at most 4 GiB and is processed in memory (add roughly 2x the data size to the
  RAM figures above)
- single-threaded, about 0.4 MB/s
- no data-specific filters yet (x86 E8/E9, images, audio) and no built-in dictionary; these are
  the next steps for even stronger compression
- empty folders and symlinks are not stored

## Verification status

The Rust core and the FFI layer are covered by `cargo test` (round trips, corruption detection,
cancellation, error paths) and the C ABI was exercised from Python `ctypes`. The Flutter code
is checked by the CI workflows (`flutter analyze`, `flutter test`, build). Storage handling on
Android is the least tested part: the compressed result is built in the app cache and saved
through the system dialog, extraction goes to the app documents folder, and folder picking is
disabled there.
