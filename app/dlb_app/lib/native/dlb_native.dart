import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// Mirrors `JobStatus` in src/ffi.rs (48 bytes, repr(C)).
final class JobStatusNative extends Struct {
  @Uint32()
  external int state;
  @Uint32()
  external int phase;
  @Uint64()
  external int done;
  @Uint64()
  external int total;
  @Uint64()
  external int inBytes;
  @Uint64()
  external int outBytes;
  @Uint64()
  external int files;
}

enum JobState { running, done, error, cancelled }

enum JobPhase { reading, coding, writing }

/// Immutable copy of the native counters.
class JobSnapshot {
  const JobSnapshot({
    this.state = JobState.running,
    this.phase = JobPhase.reading,
    this.done = 0,
    this.total = 0,
    this.inBytes = 0,
    this.outBytes = 0,
    this.files = 0,
  });
  final JobState state;
  final JobPhase phase;
  final int done;
  final int total;
  final int inBytes;
  final int outBytes;
  final int files;

  /// 0..1, or null while the total is not known yet (indeterminate).
  double? get fraction =>
      total <= 0 ? null : (done / total).clamp(0.0, 1.0).toDouble();
}

typedef _CompressStartC = Pointer<Void> Function(Pointer<Pointer<Utf8>>, IntPtr,
    Pointer<Utf8>, Uint32, Uint32, Pointer<Utf8>, Uint32);
typedef _CompressStart = Pointer<Void> Function(
    Pointer<Pointer<Utf8>>, int, Pointer<Utf8>, int, int, Pointer<Utf8>, int);
typedef _ExtractStartC = Pointer<Void> Function(
    Pointer<Utf8>, Pointer<Utf8>, Uint8, Pointer<Utf8>, Pointer<Utf8>);
typedef _ExtractStart = Pointer<Void> Function(
    Pointer<Utf8>, Pointer<Utf8>, int, Pointer<Utf8>, Pointer<Utf8>);
typedef _ListStartC = Pointer<Void> Function(Pointer<Utf8>, Pointer<Utf8>);
typedef _ListStart = Pointer<Void> Function(Pointer<Utf8>, Pointer<Utf8>);
typedef _ProbeC = Uint32 Function(Pointer<Utf8>);
typedef _Probe = int Function(Pointer<Utf8>);
typedef _PollC = Void Function(Pointer<Void>, Pointer<JobStatusNative>);
typedef _Poll = void Function(Pointer<Void>, Pointer<JobStatusNative>);
typedef _MessageC = Pointer<Utf8> Function(Pointer<Void>);
typedef _Message = Pointer<Utf8> Function(Pointer<Void>);
typedef _VoidPtrC = Void Function(Pointer<Void>);
typedef _VoidPtr = void Function(Pointer<Void>);
typedef _StrFreeC = Void Function(Pointer<Utf8>);
typedef _StrFree = void Function(Pointer<Utf8>);

class DlbNative {
  DlbNative._(DynamicLibrary lib)
      : _compress =
            lib.lookupFunction<_CompressStartC, _CompressStart>('dlb_compress_start'),
        _extract =
            lib.lookupFunction<_ExtractStartC, _ExtractStart>('dlb_extract_start'),
        _list = lib.lookupFunction<_ListStartC, _ListStart>('dlb_list_start'),
        _probe = lib.lookupFunction<_ProbeC, _Probe>('dlb_probe'),
        _poll = lib.lookupFunction<_PollC, _Poll>('dlb_job_poll'),
        _message = lib.lookupFunction<_MessageC, _Message>('dlb_job_message'),
        _cancel = lib.lookupFunction<_VoidPtrC, _VoidPtr>('dlb_job_cancel'),
        _free = lib.lookupFunction<_VoidPtrC, _VoidPtr>('dlb_job_free'),
        _strFree = lib.lookupFunction<_StrFreeC, _StrFree>('dlb_string_free');

  final _CompressStart _compress;
  final _ExtractStart _extract;
  final _ListStart _list;
  final _Probe _probe;
  final _Poll _poll;
  final _Message _message;
  final _VoidPtr _cancel;
  final _VoidPtr _free;
  final _StrFree _strFree;

  static DlbNative? _instance;
  static DlbNative get instance => _instance ??= DlbNative._(_open());

  static DynamicLibrary _open() {
    if (Platform.isAndroid || Platform.isLinux) {
      return DynamicLibrary.open('libdlbcore.so');
    }
    if (Platform.isWindows) return DynamicLibrary.open('dlbcore.dll');
    if (Platform.isMacOS) {
      // bundled at DLB.app/Contents/Frameworks (see scripts/build_native.sh)
      final exe = File(Platform.resolvedExecutable);
      final inBundle =
          '${exe.parent.parent.path}/Frameworks/libdlbcore.dylib';
      return DynamicLibrary.open(
          File(inBundle).existsSync() ? inBundle : 'libdlbcore.dylib');
    }
    throw UnsupportedError('DLB: unsupported platform');
  }

  /// Returns null when the arguments were rejected by the core.
  NativeJob? startCompress(List<String> paths, String outPath, int level,
      {int threads = 0, String? password, bool lowMemory = false}) {
    final arr = calloc<Pointer<Utf8>>(paths.length);
    final strs = <Pointer<Utf8>>[];
    final out = outPath.toNativeUtf8();
    final pw = (password == null || password.isEmpty)
        ? null
        : password.toNativeUtf8();
    try {
      for (var i = 0; i < paths.length; i++) {
        final p = paths[i].toNativeUtf8();
        strs.add(p);
        arr[i] = p;
      }
      final h = _compress(arr, paths.length, out, level, threads, pw ?? nullptr,
          lowMemory ? 1 : 0);
      return h == nullptr ? null : NativeJob._(this, h);
    } finally {
      // the core copies all strings before returning
      for (final s in strs) {
        calloc.free(s);
      }
      calloc.free(arr);
      calloc.free(out);
      if (pw != null) calloc.free(pw);
    }
  }

  /// [dest] == null only verifies integrity.
  NativeJob? startExtract(String archive, String? dest,
      {bool force = false, String? password, List<int>? select}) {
    final a = archive.toNativeUtf8();
    final d = dest?.toNativeUtf8();
    final sel = (select == null || select.isEmpty)
        ? null
        : select.join(',').toNativeUtf8();
    final pw = (password == null || password.isEmpty)
        ? null
        : password.toNativeUtf8();
    try {
      final h = _extract(
          a, d ?? nullptr, force ? 1 : 0, pw ?? nullptr, sel ?? nullptr);
      return h == nullptr ? null : NativeJob._(this, h);
    } finally {
      calloc.free(a);
      if (d != null) calloc.free(d);
      if (pw != null) calloc.free(pw);
      if (sel != null) calloc.free(sel);
    }
  }

  /// Reads the entry table; the job message is TSV (see `dlb_list_start`).
  NativeJob? startList(String archive, {String? password}) {
    final a = archive.toNativeUtf8();
    final pw = (password == null || password.isEmpty)
        ? null
        : password.toNativeUtf8();
    try {
      final h = _list(a, pw ?? nullptr);
      return h == nullptr ? null : NativeJob._(this, h);
    } finally {
      calloc.free(a);
      if (pw != null) calloc.free(pw);
    }
  }

  /// 0 = not a DLB file / unreadable, 1 = plain archive, 2 = password protected.
  int probe(String path) {
    final a = path.toNativeUtf8();
    try {
      return _probe(a);
    } finally {
      calloc.free(a);
    }
  }
}

class NativeJob {
  NativeJob._(this._api, this._ptr) : _st = calloc<JobStatusNative>();

  final DlbNative _api;
  final Pointer<Void> _ptr;
  final Pointer<JobStatusNative> _st;
  bool _disposed = false;

  JobSnapshot poll() {
    _api._poll(_ptr, _st);
    final s = _st.ref;
    return JobSnapshot(
      state: JobState.values[s.state.clamp(0, 3).toInt()],
      phase: JobPhase.values[s.phase.clamp(0, 2).toInt()],
      done: s.done,
      total: s.total,
      inBytes: s.inBytes,
      outBytes: s.outBytes,
      files: s.files,
    );
  }

  /// Result path / "verified" on success, error text otherwise.
  String message() {
    final p = _api._message(_ptr);
    final s = p.toDartString();
    _api._strFree(p);
    return s;
  }

  void cancel() => _api._cancel(_ptr);

  /// Cancels if running, joins the worker thread and releases memory.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _api._free(_ptr);
    calloc.free(_st);
  }
}
