import 'dart:io';

import 'package:desktop_drop/desktop_drop.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

import '../format.dart';
import '../job_runner.dart';
import '../platform.dart';
import '../settings.dart';
import '../strings.dart';
import '../widgets/layout.dart';
import '../widgets/password_field.dart';
import '../widgets/status_panel.dart';

class CompressPage extends StatefulWidget {
  const CompressPage({super.key});

  @override
  State<CompressPage> createState() => _CompressPageState();
}

class _CompressPageState extends State<CompressPage> {
  final JobRunner _runner = JobRunner();
  final List<String> _items = [];
  int _level = AppSettings.level;
  bool _multi = AppSettings.multiCore;
  final TextEditingController _pw = TextEditingController();
  final TextEditingController _pw2 = TextEditingController();
  bool get _pwOk => _pw.text.isEmpty || _pw.text == _pw2.text;
  String? _customOut; // desktop "Save as" choice
  bool _dragging = false;

  @override
  void dispose() {
    _runner.dispose();
    _pw.dispose();
    _pw2.dispose();
    super.dispose();
  }

  void _add(Iterable<String> paths) {
    if (_runner.running) return;
    setState(() {
      for (final x in paths) {
        if (!_items.contains(x)) _items.add(x);
      }
      _customOut = null;
    });
    _runner.reset();
  }

  Future<void> _pickFiles() async {
    final r = await FilePicker.platform.pickFiles(allowMultiple: true);
    if (r != null) _add(r.paths.whereType<String>());
  }

  Future<void> _pickFolder() async {
    final d = await FilePicker.platform.getDirectoryPath();
    if (d != null) _add([d]);
  }

  /// Desktop: next to the first input. Android: app cache (saved via dialog afterwards).
  String _autoOut(String? cacheDir) {
    final first = _items.first;
    final dir = cacheDir ?? p.dirname(first);
    final name = uniqueName(
        '${p.basename(first)}.dlb', (n) => File(p.join(dir, n)).existsSync());
    return p.join(dir, name);
  }

  Future<void> _chooseOut() async {
    final cur = _customOut ?? _autoOut(null);
    final r = await FilePicker.platform.saveFile(
      dialogTitle: S.of(context).saveAs,
      fileName: p.basename(cur),
      initialDirectory: p.dirname(cur),
    );
    if (r == null) return;
    setState(() => _customOut = r.toLowerCase().endsWith('.dlb') ? r : '$r.dlb');
  }

  Future<void> _start() async {
    if (_items.isEmpty) return;
    final cache = isAndroid ? (await getTemporaryDirectory()).path : null;
    final out = _customOut ?? _autoOut(cache);
    _runner.startCompress(List.of(_items), out, _level,
        threads: (_multi && _level < 10) ? 0 : 1, password: _pw.text);
  }

  Future<void> _saveCopy() async {
    final path = _runner.message;
    final s = S.of(context);
    final bytes = await File(path).readAsBytes();
    final r = await FilePicker.platform.saveFile(
        dialogTitle: s.saveCopy, fileName: p.basename(path), bytes: bytes);
    if (r != null && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(s.saved)));
    }
  }

  void _again() {
    final done = _runner.state == RunState.done;
    _runner.reset();
    if (done) {
      setState(() {
        _items.clear();
        _pw.clear();
        _pw2.clear();
      });
    }
  }

  Widget _drop(Widget child) {
    if (!isDesktop) return child;
    return DropTarget(
      onDragEntered: (_) => setState(() => _dragging = true),
      onDragExited: (_) => setState(() => _dragging = false),
      onDragDone: (d) {
        setState(() => _dragging = false);
        _add(d.files.map((f) => f.path));
      },
      child: child,
    );
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final t = Theme.of(context);
    return ListenableBuilder(
      listenable: _runner,
      builder: (context, _) {
        final busy = _runner.running;
        return LayoutBuilder(builder: (context, c) {
          final g = gutterFor(c.maxWidth);
          return CustomScrollView(
            slivers: [
              SliverPadding(
                padding: EdgeInsets.fromLTRB(g, 24, g, 16),
                sliver: SliverToBoxAdapter(
                    child: PageHeader(
                        title: s.compressTitle, subtitle: s.compressHint)),
              ),
              SliverPadding(
                padding: EdgeInsets.symmetric(horizontal: g),
                sliver: SliverToBoxAdapter(
                  child: _drop(AnimatedContainer(
                    duration: MediaQuery.disableAnimationsOf(context)
                        ? Duration.zero
                        : const Duration(milliseconds: 150),
                    padding: const EdgeInsets.all(24),
                    decoration: BoxDecoration(
                      color: _dragging
                          ? t.colorScheme.secondaryContainer
                          : t.colorScheme.surfaceContainerHigh,
                      borderRadius: BorderRadius.circular(28),
                    ),
                    child: Column(
                      children: [
                        ExcludeSemantics(
                            child: Icon(Icons.archive_outlined,
                                size: 40, color: t.colorScheme.primary)),
                        const SizedBox(height: 12),
                        Text(isDesktop ? s.dropHere : s.pickFiles,
                            style: t.textTheme.titleMedium),
                        const SizedBox(height: 16),
                        Wrap(
                          spacing: 12,
                          runSpacing: 12,
                          alignment: WrapAlignment.center,
                          children: [
                            FilledButton.tonalIcon(
                              onPressed: busy ? null : _pickFiles,
                              icon: const Icon(Icons.insert_drive_file_outlined),
                              label: Text(s.files),
                            ),
                            // Android does not allow plain-path access to arbitrary folders.
                            if (!isAndroid)
                              FilledButton.tonalIcon(
                                onPressed: busy ? null : _pickFolder,
                                icon: const Icon(Icons.folder_outlined),
                                label: Text(s.folder),
                              ),
                          ],
                        ),
                      ],
                    ),
                  )),
                ),
              ),
              SliverPadding(
                padding: EdgeInsets.fromLTRB(g, 8, g, 0),
                sliver: SliverList.builder(
                  itemCount: _items.length,
                  itemBuilder: (context, i) {
                    final path = _items[i];
                    final isDir = FileSystemEntity.isDirectorySync(path);
                    return Padding(
                      padding: const EdgeInsets.only(top: 8),
                      child: PathTile(
                        icon: isDir
                            ? Icons.folder_outlined
                            : Icons.insert_drive_file_outlined,
                        title: p.basename(path),
                        subtitle: p.dirname(path),
                        removeLabel: s.remove,
                        onRemove: busy
                            ? null
                            : () => setState(() {
                                  _items.removeAt(i);
                                  _customOut = null;
                                }),
                      ),
                    );
                  },
                ),
              ),
              SliverPadding(
                padding: EdgeInsets.fromLTRB(g, 16, g, 0),
                sliver: SliverToBoxAdapter(child: _levelCard(s, t, busy)),
              ),
              SliverPadding(
                padding: EdgeInsets.fromLTRB(g, 8, g, 0),
                sliver: SliverToBoxAdapter(child: _passwordCard(s, t, busy)),
              ),
              if (isDesktop && _items.isNotEmpty)
                SliverPadding(
                  padding: EdgeInsets.fromLTRB(g, 8, g, 0),
                  sliver: SliverToBoxAdapter(
                    child: PathTile(
                      icon: Icons.save_outlined,
                      title: s.saveAs,
                      subtitle: _customOut ?? _autoOut(null),
                    ),
                  ),
                ),
              if (isDesktop && _items.isNotEmpty && !busy)
                SliverPadding(
                  padding: EdgeInsets.fromLTRB(g, 4, g, 0),
                  sliver: SliverToBoxAdapter(
                    child: Align(
                      alignment: Alignment.centerRight,
                      child: TextButton(
                          onPressed: _chooseOut, child: Text(s.change)),
                    ),
                  ),
                ),
              SliverPadding(
                padding: EdgeInsets.fromLTRB(g, 16, g, 32),
                sliver: SliverToBoxAdapter(
                  child: _runner.state == RunState.idle
                      ? FilledButton.icon(
                          onPressed: (_items.isEmpty || !_pwOk) ? null : _start,
                          icon: const Icon(Icons.compress),
                          label: Text(s.startCompress),
                        )
                      : StatusPanel(
                          runner: _runner,
                          onAgain: _again,
                          onSaveCopy: isAndroid ? _saveCopy : null,
                        ),
                ),
              ),
            ],
          );
        });
      },
    );
  }

  Widget _passwordCard(S s, ThemeData t, bool busy) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            PasswordField(
              controller: _pw,
              label: s.passwordOptional,
              enabled: !busy,
              helperText: s.passwordHelp,
              onChanged: (v) => setState(() {
                if (v.isEmpty) _pw2.clear();
              }),
            ),
            if (_pw.text.isNotEmpty) ...[
              const SizedBox(height: 12),
              PasswordField(
                controller: _pw2,
                label: s.repeatPassword,
                enabled: !busy,
                errorText: (_pw2.text.isNotEmpty && !_pwOk)
                    ? s.passwordMismatch
                    : null,
                onChanged: (_) => setState(() {}),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _levelCard(S s, ThemeData t, bool busy) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(s.quality, style: t.textTheme.titleMedium),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: SegmentedButton<int>(
                showSelectedIcon: false,
                segments: [
                  ButtonSegment(value: 4, label: Text(s.fast)),
                  ButtonSegment(value: 7, label: Text(s.balanced)),
                  ButtonSegment(value: 9, label: Text(s.maximum)),
                  ButtonSegment(value: 10, label: Text(s.ultra)),
                ],
                selected: {_level},
                onSelectionChanged: busy
                    ? null
                    : (v) => setState(() {
                          _level = v.first;
                          AppSettings.level = _level;
                          AppSettings.save();
                        }),
              ),
            ),
            const SizedBox(height: 12),
            Text(s.ramHint(_level, levelRamMb(_level)),
                style: t.textTheme.bodyMedium),
            const SizedBox(height: 8),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(s.multiCore),
              subtitle: Text(s.multiCoreHint),
              value: _multi,
              onChanged:
                  (busy || _level >= 10)
                      ? null
                      : (v) => setState(() {
                            _multi = v;
                            AppSettings.multiCore = v;
                            AppSettings.save();
                          }),
            ),
            if (_level >= 10) ...[
              const SizedBox(height: 8),
              Text(s.ultraWarn,
                  style: t.textTheme.bodyMedium
                      ?.copyWith(color: t.colorScheme.tertiary)),
            ],
            const SizedBox(height: 4),
            Text(s.slowNote,
                style: t.textTheme.bodySmall
                    ?.copyWith(color: t.colorScheme.onSurfaceVariant)),
          ],
        ),
      ),
    );
  }
}
