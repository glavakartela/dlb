import 'dart:async';

import 'package:flutter/foundation.dart';

import 'native/dlb_native.dart';

enum RunState { idle, running, done, error, cancelled }

/// Owns one native job at a time and exposes its progress to the UI.
class JobRunner extends ChangeNotifier {
  RunState state = RunState.idle;
  JobSnapshot snap = const JobSnapshot();
  String message = '';
  bool wasCompress = true;
  Duration elapsed = Duration.zero;

  NativeJob? _job;
  Timer? _timer;
  final Stopwatch _sw = Stopwatch();

  bool get running => state == RunState.running;

  /// Bytes per second of *uncompressed* data processed so far.
  double get speed {
    final s = _sw.elapsedMilliseconds / 1000.0;
    return s <= 0.2 ? 0 : snap.done / s;
  }

  Duration? get eta {
    final sp = speed;
    if (sp <= 0 || snap.total <= 0 || snap.phase != JobPhase.coding) return null;
    return Duration(seconds: ((snap.total - snap.done) / sp).round());
  }

  void startCompress(List<String> paths, String out, int level,
      {int threads = 0}) {
    wasCompress = true;
    _begin(() => DlbNative.instance.startCompress(paths, out, level,
        threads: threads));
  }

  void startExtract(String archive, String? dest, {bool force = false}) {
    wasCompress = false;
    _begin(() => DlbNative.instance.startExtract(archive, dest, force: force));
  }

  void _begin(NativeJob? Function() start) {
    if (running) return;
    _release();
    NativeJob? job;
    try {
      job = start();
    } catch (e) {
      // library missing or symbol lookup failed
      _fail('$e');
      return;
    }
    if (job == null) {
      _fail('invalid arguments');
      return;
    }
    _job = job;
    snap = const JobSnapshot();
    message = '';
    state = RunState.running;
    _sw
      ..reset()
      ..start();
    _timer = Timer.periodic(const Duration(milliseconds: 100), (_) => _tick());
    notifyListeners();
  }

  void _fail(String m) {
    message = m;
    state = RunState.error;
    notifyListeners();
  }

  void _tick() {
    final job = _job;
    if (job == null) return;
    final s = job.poll();
    snap = s;
    elapsed = _sw.elapsed;
    if (s.state != JobState.running) {
      _sw.stop();
      _timer?.cancel();
      message = job.message();
      state = switch (s.state) {
        JobState.done => RunState.done,
        JobState.cancelled => RunState.cancelled,
        _ => RunState.error,
      };
    }
    notifyListeners();
  }

  void cancel() => _job?.cancel();

  /// Back to the idle form (keeps nothing from the previous run).
  void reset() {
    if (running) return;
    _release();
    state = RunState.idle;
    snap = const JobSnapshot();
    message = '';
    notifyListeners();
  }

  void _release() {
    _timer?.cancel();
    _timer = null;
    _job?.dispose();
    _job = null;
  }

  @override
  void dispose() {
    _release();
    super.dispose();
  }
}
