import 'package:dynamic_color/dynamic_color.dart';
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'pages/shell.dart';
import 'theme.dart';

void main() => runApp(const DlbApp());

class DlbApp extends StatelessWidget {
  const DlbApp({super.key});

  @override
  Widget build(BuildContext context) {
    // On Android 12+ DynamicColorBuilder supplies the wallpaper-based Material You
    // palette; elsewhere it is null and the brand seed is used.
    return DynamicColorBuilder(
      builder: (ColorScheme? light, ColorScheme? dark) {
        final theme = buildTheme(dark);
        return MaterialApp(
          title: 'DLB',
          debugShowCheckedModeBanner: false,
          theme: theme,
          darkTheme: theme,
          themeMode: ThemeMode.dark, // the OLED-black design is dark only
          supportedLocales: const [Locale('en'), Locale('ru')],
          localizationsDelegates: const [
            GlobalMaterialLocalizations.delegate,
            GlobalWidgetsLocalizations.delegate,
            GlobalCupertinoLocalizations.delegate,
          ],
          home: const Shell(),
        );
      },
    );
  }
}
