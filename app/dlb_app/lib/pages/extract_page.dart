import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

import '../format.dart';
import '../job_runner.dart';
import '../platform.dart';
import '../strings.dart';
import '../widgets/layout.dart';
import '../widgets/status_panel.dart';

class ExtractPage extends StatefulWidget {
  const ExtractPage({super.key});

  @override
  State<ExtractPage> createState() => _ExtractPageState();
}

class _ExtractPageState extends State<ExtractPage> {
  final JobRunner _runner = JobRunner();
  String? _archive;
  int _archiveSize = 0;
  String? _dest;
  bool _force = false;

  @override
  void dispose() {
    _runner.dispose();
    super.dispose();
  }

  Future<void> _pickArchive() async {
    final r = await FilePicker.platform.pickFiles(
      // ".dlb" has no registered MIME type on Android, so do not filter there
      type: isAndroid ? FileType.any : FileType.custom,
      allowedExtensions: isAndroid ? null : ['dlb'],
    );
    final path = r?.files.single.path;
    if (path == null) return;
    final base = isAndroid
        ? (await getApplicationDocumentsDirectory()).path
        : p.dirname(path);
    setState(() {
      _archive = path;
      _archiveSize = File(path).lengthSync();
      _dest = p.join(base, p.basenameWithoutExtension(path));
    });
    _runner.reset();
  }

  Future<void> _pickDest() async {
    final d = await FilePicker.platform.getDirectoryPath();
    if (d != null) setState(() => _dest = d);
  }

  void _extract() =>
      _runner.startExtract(_archive!, _dest, force: _force);

  void _verify() => _runner.startExtract(_archive!, null);

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final t = Theme.of(context);
    return ListenableBuilder(
      listenable: _runner,
      builder: (context, _) {
        final busy = _runner.running;
        final idle = _runner.state == RunState.idle;
        return LayoutBuilder(builder: (context, c) {
          final g = gutterFor(c.maxWidth);
          return ListView(
            padding: EdgeInsets.fromLTRB(g, 24, g, 32),
            children: [
              PageHeader(title: s.extractTitle, subtitle: s.extractHint),
              const SizedBox(height: 16),
              if (_archive == null)
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      children: [
                        ExcludeSemantics(
                            child: Icon(Icons.unarchive_outlined,
                                size: 40, color: t.colorScheme.primary)),
                        const SizedBox(height: 16),
                        FilledButton.tonalIcon(
                          onPressed: _pickArchive,
                          icon: const Icon(Icons.folder_open_outlined),
                          label: Text(s.pickArchive),
                        ),
                      ],
                    ),
                  ),
                )
              else ...[
                PathTile(
                  icon: Icons.inventory_2_outlined,
                  title: p.basename(_archive!),
                  subtitle: fmtBytes(_archiveSize, ru: s.ru),
                  removeLabel: s.change,
                  onRemove: busy
                      ? null
                      : () => setState(() {
                            _archive = null;
                            _runner.reset();
                          }),
                ),
                const SizedBox(height: 8),
                PathTile(
                  icon: Icons.folder_outlined,
                  title: s.destination,
                  subtitle: _dest ?? '',
                ),
                if (isDesktop && !busy)
                  Align(
                    alignment: Alignment.centerRight,
                    child: TextButton(
                        onPressed: _pickDest, child: Text(s.change)),
                  ),
                const SizedBox(height: 8),
                Card(
                  color: t.colorScheme.surfaceContainer,
                  child: SwitchListTile(
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(28)),
                    title: Text(s.overwrite),
                    value: _force,
                    onChanged: busy ? null : (v) => setState(() => _force = v),
                  ),
                ),
                const SizedBox(height: 16),
                if (idle) ...[
                  FilledButton.icon(
                    onPressed: _extract,
                    icon: const Icon(Icons.unarchive),
                    label: Text(s.startExtract),
                  ),
                  const SizedBox(height: 12),
                  OutlinedButton.icon(
                    onPressed: _verify,
                    icon: const Icon(Icons.verified_outlined),
                    label: Text(s.verify),
                  ),
                ] else
                  StatusPanel(runner: _runner, onAgain: _runner.reset),
              ],
            ],
          );
        });
      },
    );
  }
}
