import 'package:flutter/material.dart';

/// Brand seed. Used when the OS does not provide Material You colors.
const Color kSeed = Color(0xFF22C55E);

/// OLED black + Material You tonal surfaces.
///
/// Surfaces are true black at the lowest level and get a faint tint of the
/// primary color as they rise, so cards stay distinguishable on black
/// without borders or shadows.
ThemeData buildTheme([ColorScheme? dynamicDark]) {
  final base = dynamicDark ??
      ColorScheme.fromSeed(seedColor: kSeed, brightness: Brightness.dark);

  Color tone(double a) =>
      Color.alphaBlend(base.primary.withValues(alpha: a), Colors.black);

  final scheme = base.copyWith(
    surface: Colors.black,
    surfaceDim: Colors.black,
    surfaceBright: tone(0.16),
    surfaceContainerLowest: Colors.black,
    surfaceContainerLow: tone(0.05),
    surfaceContainer: tone(0.08),
    surfaceContainerHigh: tone(0.11),
    surfaceContainerHighest: tone(0.14),
  );

  const radius = 28.0;
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: Colors.black,
    visualDensity: VisualDensity.standard,
    materialTapTargetSize: MaterialTapTargetSize.padded,
    cardTheme: CardThemeData(
      color: scheme.surfaceContainerHigh,
      elevation: 0,
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(radius)),
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: scheme.surfaceContainer,
      indicatorColor: scheme.secondaryContainer,
      height: 72,
    ),
    navigationRailTheme: NavigationRailThemeData(
      backgroundColor: Colors.black,
      indicatorColor: scheme.secondaryContainer,
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        minimumSize: const Size(64, 56),
        shape: const StadiumBorder(),
        textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        minimumSize: const Size(64, 48),
        shape: const StadiumBorder(),
        side: BorderSide(color: scheme.outline),
      ),
    ),
    segmentedButtonTheme: SegmentedButtonThemeData(
      style: ButtonStyle(
        minimumSize: const WidgetStatePropertyAll(Size(48, 48)),
        side: WidgetStatePropertyAll(BorderSide(color: scheme.outline)),
      ),
    ),
    progressIndicatorTheme: ProgressIndicatorThemeData(
      color: scheme.primary,
      linearTrackColor: scheme.surfaceContainerHighest,
      linearMinHeight: 8,
    ),
    // visible keyboard focus on desktop
    focusColor: scheme.primary.withValues(alpha: 0.24),
  );
}
