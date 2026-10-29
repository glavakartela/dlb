import 'package:flutter/material.dart';

import '../format.dart';
import '../locale_controller.dart';
import '../strings.dart';
import '../version.dart';
import '../widgets/layout.dart';

class HelpPage extends StatelessWidget {
  const HelpPage({super.key});

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final t = Theme.of(context);
    return LayoutBuilder(builder: (context, c) {
      final g = gutterFor(c.maxWidth);
      return ListView(
        padding: EdgeInsets.fromLTRB(g, 24, g, 32),
        children: [
          PageHeader(title: s.helpTitle, subtitle: 'DLB · context mixing'),
          const SizedBox(height: 16),
          Row(
            children: [
              ExcludeSemantics(
                child: Image.asset(
                  'branding/png/icon-64.png',
                  width: 64,
                  height: 64,
                  filterQuality: FilterQuality.none,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('DLB', style: t.textTheme.titleLarge),
                    Text('v$kVersion · "$kCodename"',
                        style: t.textTheme.bodyMedium?.copyWith(
                            color: t.colorScheme.onSurfaceVariant)),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(s.language, style: t.textTheme.titleMedium),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      for (final e in kLanguages.entries)
                        ChoiceChip(
                          label: Text(e.value),
                          selected: s.code == e.key,
                          onSelected: (_) => localeController.select(e.key),
                        ),
                    ],
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 8),
          _Info(Icons.psychology_outlined, s.helpWhatTitle, s.helpWhat),
          const SizedBox(height: 8),
          _Info(Icons.trending_down, s.helpGoodTitle, s.helpGood),
          const SizedBox(height: 8),
          _Info(Icons.block, s.helpBadTitle, s.helpBad),
          const SizedBox(height: 8),
          _Info(Icons.lock_outline, s.helpSecurityTitle, s.helpSecurity),
          const SizedBox(height: 8),
          _Info(Icons.info_outline, s.helpLimitsTitle, s.helpLimits),
          const SizedBox(height: 8),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(s.quality, style: t.textTheme.titleMedium),
                  const SizedBox(height: 12),
                  for (final l in const [4, 7, 9, 10])
                    Padding(
                      padding: const EdgeInsets.symmetric(vertical: 4),
                      child: Row(
                        children: [
                          Expanded(
                              child: Text(l == 4
                                  ? s.fast
                                  : l == 7
                                      ? s.balanced
                                      : l == 9
                                          ? s.maximum
                                          : s.ultra)),
                          Text(s.ramHint(l, levelRamMb(l)),
                              style: t.textTheme.bodySmall?.copyWith(
                                  color: t.colorScheme.onSurfaceVariant)),
                        ],
                      ),
                    ),
                  const SizedBox(height: 8),
                  Text('${s.helpFormat}: .dlb (DLB2)',
                      style: t.textTheme.bodySmall
                          ?.copyWith(color: t.colorScheme.onSurfaceVariant)),
                ],
              ),
            ),
          ),
        ],
      );
    });
  }
}

class _Info extends StatelessWidget {
  const _Info(this.icon, this.title, this.body);
  final IconData icon;
  final String title;
  final String body;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            ExcludeSemantics(child: Icon(icon, color: t.colorScheme.primary)),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: t.textTheme.titleMedium),
                  const SizedBox(height: 4),
                  Text(body,
                      style: t.textTheme.bodyMedium
                          ?.copyWith(color: t.colorScheme.onSurfaceVariant)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
