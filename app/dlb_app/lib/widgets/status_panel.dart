import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;
import 'package:url_launcher/url_launcher.dart';

import '../format.dart';
import '../job_runner.dart';
import '../native/dlb_native.dart';
import '../platform.dart';
import '../strings.dart';

/// Progress / result / error card driven by a [JobRunner].
///
/// [resultPath] is the file or folder produced by the job (shown in the result card).
/// [onSaveCopy] is offered on Android, where the result lives in app storage.
class StatusPanel extends StatelessWidget {
  const StatusPanel({
    super.key,
    required this.runner,
    required this.onAgain,
    this.onSaveCopy,
  });

  final JobRunner runner;
  final VoidCallback onAgain;
  final VoidCallback? onSaveCopy;

  @override
  Widget build(BuildContext context) {
    final fast = MediaQuery.disableAnimationsOf(context);
    return AnimatedSwitcher(
      duration: fast ? Duration.zero : const Duration(milliseconds: 250),
      child: switch (runner.state) {
        RunState.running => _Progress(key: const ValueKey('run'), runner: runner),
        RunState.done => _Result(
            key: const ValueKey('done'),
            runner: runner,
            onAgain: onAgain,
            onSaveCopy: onSaveCopy),
        RunState.error => _Message(
            key: const ValueKey('err'),
            error: true,
            title: S.of(context).error,
            body: runner.message,
            onAgain: onAgain),
        RunState.cancelled => _Message(
            key: const ValueKey('cancel'),
            error: false,
            title: S.of(context).cancelledMsg,
            body: '',
            onAgain: onAgain),
        RunState.idle => const SizedBox.shrink(key: ValueKey('idle')),
      },
    );
  }
}

class _Progress extends StatelessWidget {
  const _Progress({super.key, required this.runner});
  final JobRunner runner;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final t = Theme.of(context);
    final snap = runner.snap;
    final f = snap.fraction;
    final pct = f == null ? null : (f * 100).floor();
    final label = switch (snap.phase) {
      JobPhase.reading => s.reading,
      JobPhase.writing => s.writing,
      JobPhase.coding => runner.wasCompress ? s.compressing : s.extracting,
    };
    final eta = runner.eta;
    final sp = runner.speed;
    final detail = [
      if (snap.total > 0)
        '${fmtBytes(snap.done, ru: s.ru)} / ${fmtBytes(snap.total, ru: s.ru)}',
      if (sp > 0) s.speed(fmtBytes(sp, ru: s.ru)),
      if (eta != null) s.eta(fmtDuration(eta)),
    ].join(' · ');

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                    child: Text(label, style: t.textTheme.titleMedium)),
                if (pct != null)
                  Text('$pct%',
                      style: t.textTheme.titleMedium
                          ?.copyWith(color: t.colorScheme.primary)),
              ],
            ),
            const SizedBox(height: 16),
            ClipRRect(
              borderRadius: BorderRadius.circular(8),
              child: LinearProgressIndicator(
                value: f,
                semanticsLabel: label,
                semanticsValue: pct == null ? null : '$pct%',
              ),
            ),
            const SizedBox(height: 12),
            Text(detail.isEmpty ? ' ' : detail,
                style: t.textTheme.bodyMedium
                    ?.copyWith(color: t.colorScheme.onSurfaceVariant)),
            const SizedBox(height: 16),
            Align(
              alignment: Alignment.centerRight,
              child: OutlinedButton.icon(
                onPressed: runner.cancel,
                icon: const Icon(Icons.close),
                label: Text(s.cancel),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _Result extends StatelessWidget {
  const _Result({
    super.key,
    required this.runner,
    required this.onAgain,
    this.onSaveCopy,
  });
  final JobRunner runner;
  final VoidCallback onAgain;
  final VoidCallback? onSaveCopy;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final t = Theme.of(context);
    final snap = runner.snap;
    final msg = runner.message;
    final verifyOnly = msg == 'verified';
    final isPath = !verifyOnly && msg.isNotEmpty;

    final String headline;
    final String sub;
    if (verifyOnly) {
      headline = s.done;
      sub = '${s.verified} · ${s.filesCount(snap.files)}';
    } else if (runner.wasCompress) {
      headline = fmtRatio(snap.inBytes, snap.outBytes);
      final saved = snap.inBytes == 0
          ? 0
          : ((1 - snap.outBytes / snap.inBytes) * 100).clamp(0, 100).round();
      sub = '${fmtBytes(snap.inBytes, ru: s.ru)} → ${fmtBytes(snap.outBytes, ru: s.ru)}'
          ' · $saved% ${s.savedSpace} · ${s.filesCount(snap.files)}';
    } else {
      headline = s.done;
      sub = '${s.filesCount(snap.files)} · ${fmtBytes(snap.outBytes, ru: s.ru)}';
    }

    return Card(
      color: t.colorScheme.primaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Semantics(
              liveRegion: true,
              child: Row(
                children: [
                  Icon(Icons.check_circle_outline,
                      color: t.colorScheme.onPrimaryContainer),
                  const SizedBox(width: 12),
                  Flexible(
                    child: Text(headline,
                        style: t.textTheme.displaySmall?.copyWith(
                            color: t.colorScheme.onPrimaryContainer,
                            fontWeight: FontWeight.w700)),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),
            Text(sub,
                style: t.textTheme.bodyLarge
                    ?.copyWith(color: t.colorScheme.onPrimaryContainer)),
            if (isPath) ...[
              const SizedBox(height: 12),
              SelectableText(msg,
                  style: t.textTheme.bodySmall
                      ?.copyWith(color: t.colorScheme.onPrimaryContainer)),
            ],
            const SizedBox(height: 16),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                if (isPath && onSaveCopy != null)
                  FilledButton.icon(
                    onPressed: onSaveCopy,
                    icon: const Icon(Icons.save_alt),
                    label: Text(s.saveCopy),
                  ),
                if (isPath && isDesktop)
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                        foregroundColor: t.colorScheme.onPrimaryContainer,
                        side: BorderSide(
                            color: t.colorScheme.onPrimaryContainer)),
                    onPressed: () {
                      final dir = runner.wasCompress ? p.dirname(msg) : msg;
                      launchUrl(Uri.directory(dir));
                    },
                    icon: const Icon(Icons.folder_open),
                    label: Text(s.openFolder),
                  ),
                if (isPath)
                  OutlinedButton.icon(
                    style: OutlinedButton.styleFrom(
                        foregroundColor: t.colorScheme.onPrimaryContainer,
                        side: BorderSide(
                            color: t.colorScheme.onPrimaryContainer)),
                    onPressed: () async {
                      await Clipboard.setData(ClipboardData(text: msg));
                      if (context.mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(content: Text(s.copied)));
                      }
                    },
                    icon: const Icon(Icons.copy),
                    label: Text(s.copyPath),
                  ),
                TextButton.icon(
                  style: TextButton.styleFrom(
                      minimumSize: const Size(48, 48),
                      foregroundColor: t.colorScheme.onPrimaryContainer),
                  onPressed: onAgain,
                  icon: const Icon(Icons.refresh),
                  label: Text(s.newTask),
                ),
              ],
            ),
            if (isAndroid && onSaveCopy != null) ...[
              const SizedBox(height: 12),
              Text(s.androidStorageNote,
                  style: t.textTheme.bodySmall
                      ?.copyWith(color: t.colorScheme.onPrimaryContainer)),
            ],
          ],
        ),
      ),
    );
  }
}

class _Message extends StatelessWidget {
  const _Message({
    super.key,
    required this.error,
    required this.title,
    required this.body,
    required this.onAgain,
  });
  final bool error;
  final String title;
  final String body;
  final VoidCallback onAgain;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context);
    final s = S.of(context);
    final bg = error ? t.colorScheme.errorContainer : t.colorScheme.surfaceContainerHigh;
    final fg = error ? t.colorScheme.onErrorContainer : t.colorScheme.onSurface;
    return Card(
      color: bg,
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Semantics(
              liveRegion: true,
              child: Row(children: [
                Icon(error ? Icons.error_outline : Icons.block, color: fg),
                const SizedBox(width: 12),
                Text(title, style: t.textTheme.titleLarge?.copyWith(color: fg)),
              ]),
            ),
            if (body.isNotEmpty) ...[
              const SizedBox(height: 12),
              SelectableText(body,
                  style: t.textTheme.bodyMedium?.copyWith(color: fg)),
            ],
            const SizedBox(height: 16),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.tonalIcon(
                onPressed: onAgain,
                icon: const Icon(Icons.refresh),
                label: Text(s.again),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
