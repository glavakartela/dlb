import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// Small persisted preferences (compression level, multi-core switch).
/// Stored as JSON in the app support directory; failures are ignored.
class AppSettings {
  static int level = 7;
  static bool multiCore = true;
  static bool lowMemory = false;

  static Future<File> _file() async {
    final dir = await getApplicationSupportDirectory();
    return File(p.join(dir.path, 'settings.json'));
  }

  static Future<void> load() async {
    try {
      final f = await _file();
      if (!await f.exists()) return;
      final m = jsonDecode(await f.readAsString());
      if (m is Map) {
        final l = m['level'];
        if (l is int && (l == 4 || l == 7 || l == 9 || l == 10)) level = l;
        final mc = m['multiCore'];
        if (mc is bool) multiCore = mc;
        final lm = m['lowMemory'];
        if (lm is bool) lowMemory = lm;
      }
    } catch (_) {
      // keep defaults
    }
  }

  static Future<void> save() async {
    try {
      await (await _file())
          .writeAsString(jsonEncode(
          {'level': level, 'multiCore': multiCore, 'lowMemory': lowMemory}));
    } catch (_) {
      // not persisted
    }
  }
}
