# Changelog

Release numbers are `MAJOR.MINOR.PATCH`; each release also gets a name, like Linux kernels do.
Commit messages are in English: a short summary line (`feat:`, `fix:`, `perf:`, `docs:`,
`test:`, `ci:`), then a paragraph on what changed and why. Entries here are grouped as
Added / Changed / Fixed.

## 0.15.0 "Dial-up Dragon"

### Added
- Mutation fuzzing of every reader (`tests/fuzz.rs`): random bit flips, truncations, insertions
  and extreme header values against plain, encrypted, streamed and in-memory archives, with
  hang detection. `DLB_FUZZ_ITERS=50000 cargo test --release --test fuzz` runs it for long.
- `tests/regress.rs` replays archives that once crashed or hung a reader (`tests/data`).
- Windows builds refuse names Windows treats specially when extracting: device names
  (`CON`, `NUL.txt`, `COM1`), alternate data streams (`a:b`), forbidden characters and
  trailing dots or spaces.

### Fixed
- A damaged archive with a folder entry that claimed data made the extractor panic, and the
  panic left the worker threads waiting forever (a hang). The pipeline now always releases its
  workers and reports a panicking worker as an error.
- Damaged or lying compressed streams are rejected as soon as the decoder runs past the end of
  its input, instead of decoding garbage for as long as the declared length says.
- The table size in a block header is limited to what the program can actually produce
  (a forged value could ask for gigabytes of memory).
- Extraction no longer restores setuid, setgid or sticky bits; an archive from someone else
  extracted by root could otherwise create a setuid-root program.

## 0.14.0 "Turbo Button"

### Added
- Pixel-art application icon (a zipped box in the style of 90s desktop shells) for Android
  (adaptive and themed), Windows, macOS and Linux; sources and generator in
  `app/dlb_app/branding` and `tools/make_icons.py`.
- Release names: `dlb -V` prints `dlb 0.14.0 "Turbo Button"`, the app's Help page shows it, and
  `tests/version.rs` keeps Cargo.toml, pubspec.yaml, the Dart constants and this file in step.
- Model version in the `DLB2` header (byte 4, currently 0). Future compression models will get
  the next number while archives made today keep decoding; a program that does not know a
  model refuses the archive with a clear message instead of failing the checksum.

### Changed
- `CHANGELOG.md` replaces release notes scattered over the README.

## 0.13.0

### Added
- Low-memory mode (`dlb c -M`, "Low memory mode" switch in the app): files are read block by
  block and the archive is written as it is produced, so RAM does not grow with the input
  (1.2 GB: 2296 MB normally, 40 MB with `-M`). Encrypted output is encrypted in place.
- Streaming extraction, testing and listing: archives are read with positional reads and
  entries are written as data arrives; encrypted archives are authenticated in one pass and
  decrypted on the fly.
- Incremental CRC-32 with `combine`, streaming access to the encryption envelope.

### Fixed
- Encrypting more than 256 GiB would have reused the ChaCha20 keystream; such archives are now
  refused.

## 0.12.0

### Added
- Instant file list when an archive is opened in the app (double click, drop or pick), with
  search, select all / none and "Extract selected".
- Per-file CRC-32 in the archive (`DLA3`); partial extraction verifies only what it unpacks.
- Golden test: fixed corpus, pinned sizes and SHA-256 at levels 1, 5 and 10, proving that the
  output is bit-identical on every CI platform.

### Changed
- Release profile no longer uses `panic = "abort"` (it broke a clean test build).

## 0.11.0 and earlier

Own `.dlb` container with context mixing, block-parallel compression, the Ultra level,
password protection (ChaCha20 + HMAC-SHA256, PBKDF2), symlinks and empty folders, modification
times, the x86 branch filter, stored tail for already-compressed files, the command line
(`c x t l i cmp bench completions`), and a Flutter app in six languages with four CI workflows.
