import 'dart:io';

import 'package:dynamic_color/dynamic_color.dart';
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'launch.dart';
import 'locale_controller.dart';
import 'pages/shell.dart';
import 'settings.dart';
import 'theme.dart';

Future<void> main(List<String> args) async {
  WidgetsFlutterBinding.ensureInitialized();
  for (final a in args) {
    if (a.toLowerCase().endsWith('.dlb') && File(a).existsSync()) {
      launchArchive.value = a;
      break;
    }
  }
  await localeController.load();
  await AppSettings.load();
  runApp(const DlbApp());
}

class DlbApp extends StatelessWidget {
  const DlbApp({super.key});

  @override
  Widget build(BuildContext context) {
    // On Android 12+ DynamicColorBuilder supplies the wallpaper-based Material You
    // palette; elsewhere it is null and the brand seed is used.
    return ValueListenableBuilder<Locale>(
      valueListenable: localeController,
      builder: (context, locale, _) => DynamicColorBuilder(
        builder: (ColorScheme? light, ColorScheme? dark) {
          final theme = buildTheme(dark);
          return MaterialApp(
            title: 'DLB',
            debugShowCheckedModeBanner: false,
            theme: theme,
            darkTheme: theme,
            themeMode: ThemeMode.dark, // the OLED-black design is dark only
            locale: locale,
            supportedLocales: const [
              Locale('en'),
              Locale('ru'),
              Locale('uk'),
              Locale('de'),
              Locale('es'),
              Locale('zh'),
            ],
            localizationsDelegates: const [
              GlobalMaterialLocalizations.delegate,
              GlobalWidgetsLocalizations.delegate,
              GlobalCupertinoLocalizations.delegate,
            ],
            home: const Shell(),
          );
        },
      ),
    );
  }
}
