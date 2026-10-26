import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// Languages offered in the app: code -> name in that language.
const Map<String, String> kLanguages = {
  'en': 'English',
  'ru': 'Русский',
  'uk': 'Українська',
  'de': 'Deutsch',
  'es': 'Español',
  'zh': '中文',
};

/// App language. English is the default (it does not follow the system language);
/// the user's choice is remembered in a tiny file in the app support directory.
class LocaleController extends ValueNotifier<Locale> {
  LocaleController() : super(const Locale('en'));

  Future<File> _file() async {
    final dir = await getApplicationSupportDirectory();
    return File(p.join(dir.path, 'language.txt'));
  }

  Future<void> load() async {
    try {
      final f = await _file();
      if (await f.exists()) {
        final code = (await f.readAsString()).trim();
        if (kLanguages.containsKey(code)) value = Locale(code);
      }
    } catch (_) {
      // keep the default
    }
  }

  Future<void> select(String code) async {
    value = Locale(code);
    try {
      await (await _file()).writeAsString(code);
    } catch (_) {
      // not persisted, still applied for this session
    }
  }
}

final LocaleController localeController = LocaleController();
