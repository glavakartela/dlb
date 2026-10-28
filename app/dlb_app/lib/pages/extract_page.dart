import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

import '../format.dart';
import '../job_runner.dart';
import '../launch.dart';
import '../native/dlb_native.dart';
import '../platform.dart';
import '../strings.dart';
import '../widgets/layout.dart';
import '../widgets/password_field.dart';
import '../widgets/status_panel.dart';

class ExtractPage extends StatefulWidget {
  const ExtractPage({super.key});

  @override
  State<ExtractPage> createState() => _ExtractPageState();
}

/// One line of the entry table produced by `dlb_list_start`.
class _Entry {
  const _Entry(this.index, this.kind, this.size, this.name);
  final int index;
  final int kind; // 0 file, 1 empty folder, 2 link
  final int size;
  final String name;
}

class _ExtractPageState extends State<ExtractPage> {
  final JobRunner _runner = JobRunner();
  final JobRunner _lister = JobRunner();
  String? _archive;
  int _archiveSize = 0;
  String? _dest;
  bool _force = false;
  bool _encrypted = false;
  final TextEditingController _pw = TextEditingController();
  final TextEditingController _search = TextEditingController();

  List<_Entry>? _entries;
  List<_Entry> _visible = const [];
  final Set<int> _sel = <int>{};
  int _totalBytes = 0;
  bool _parsed = false;

  bool get _needPw => _encrypted && _pw.text.isEmpty;

  @override
  void initState() {
    super.initState();
    _lister.addListener(_onLister);
    launchArchive.addListener(_onLaunch);
    WidgetsBinding.instance.addPostFrameCallback((_) => _onLaunch());
  }

  @override
  void dispose() {
    launchArchive.removeListener(_onLaunch);
    _lister.removeListener(_onLister);
    _lister.dispose();
    _runner.dispose();
    _pw.dispose();
    _search.dispose();
    super.dispose();
  }

  void _onLaunch() {
    final path = launchArchive.value;
    if (path == null || !mounted) return;
    launchArchive.value = null;
    if (_runner.running || _lister.running) return;
    _setArchive(path);
  }

  Future<void> _pickArchive() async {
    final r = await FilePicker.platform.pickFiles(
      // ".dlb" has no registered MIME type on Android, so do not filter there
      type: isAndroid ? FileType.any : FileType.custom,
      allowedExtensions: isAndroid ? null : ['dlb'],
    );
    final path = r?.files.single.path;
    if (path == null) return;
    await _setArchive(path);
  }

  Future<void> _setArchive(String path) async {
    final base = isAndroid
        ? (await getApplicationDocumentsDirectory()).path
        : p.dirname(path);
    var kind = 1;
    try {
      kind = DlbNative.instance.probe(path);
    } catch (_) {
      // library problems surface when the job starts
    }
    if (!mounted) return;
    _pw.clear();
    _search.clear();
    _lister.reset();
    _runner.reset();
    setState(() {
      _encrypted = kind == 2;
      _archive = path;
      _archiveSize = File(path).lengthSync();
      _dest = p.join(base, p.basenameWithoutExtension(path));
      _entries = null;
      _visible = const [];
      _sel.clear();
      _parsed = false;
    });
    // plain archives open straight into the file list, like WinRAR / 7-Zip
    if (kind != 2) _list();
  }

  void _list() {
    _parsed = false;
    _lister.startList(_archive!, password: _encrypted ? _pw.text : null);
  }

  void _onLister() {
    if (!mounted) return;
    if (_lister.state == RunState.done && !_parsed) {
      _parsed = true;
      final lines = _lister.message.split('\n');
      if (lines.isNotEmpty && lines.last.isEmpty) lines.removeLast();
      final list = <_Entry>[];
      var bytes = 0;
      for (var i = 0; i < lines.length; i++) {
        final f = lines[i].split('\t');
        if (f.length < 4) {
          list.add(_Entry(i, 0, 0, lines[i]));
          continue;
        }
        final kind = int.tryParse(f[0]) ?? 0;
        final size = int.tryParse(f[1]) ?? 0;
        if (kind == 0) bytes += size;
        list.add(_Entry(i, kind, size, f.sublist(3).join('\t')));
      }
      setState(() {
        _entries = list;
        _totalBytes = bytes;
        _sel
          ..clear()
          ..addAll(list.map((e) => e.index));
        _applyFilter();
      });
    }
  }

  void _applyFilter() {
    final all = _entries ?? const <_Entry>[];
    final q = _search.text.trim().toLowerCase();
    _visible = q.isEmpty
        ? all
        : all.where((e) => e.name.toLowerCase().contains(q)).toList();
  }

  void _toggleVisible(bool on) {
    setState(() {
      for (final e in _visible) {
        on ? _sel.add(e.index) : _sel.remove(e.index);
      }
    });
  }

  int get _selectedBytes {
    var n = 0;
    for (final e in _entries ?? const <_Entry>[]) {
      if (e.kind == 0 && _sel.contains(e.index)) n += e.size;
    }
    return n;
  }

  /// null = everything (also when every entry is ticked).
  List<int>? get _selection {
    final all = _entries;
    if (all == null || _sel.length == all.length) return null;
    return (_sel.toList()..sort());
  }

  Future<void> _pickDest() async {
    final d = await FilePicker.platform.getDirectoryPath();
    if (d != null) setState(() => _dest = d);
  }

  void _extract() => _runner.startExtract(_archive!, _dest,
      force: _force,
      password: _encrypted ? _pw.text : null,
      select: _selection);

  void _verify() => _runner.startExtract(_archive!, null,
      password: _encrypted ? _pw.text : null);

  Widget _entryList(S s, ThemeData t) {
    final vis = _visible;
    if (vis.isEmpty) {
      return Padding(
        padding: const EdgeInsets.all(24),
        child: Center(child: Text(s.nothingFound)),
      );
    }
    return SizedBox(
      height: 380,
      child: ListView.builder(
        itemCount: vis.length,
        itemExtent: 60,
        itemBuilder: (context, i) {
          final e = vis[i];
          final sub = switch (e.kind) {
            1 => s.emptyFolder,
            2 => s.symlink,
            _ => fmtBytes(e.size, ru: s.cyr),
          };
          final icon = switch (e.kind) {
            1 => Icons.folder_outlined,
            2 => Icons.link,
            _ => Icons.insert_drive_file_outlined,
          };
          return CheckboxListTile(
            dense: true,
            controlAffinity: ListTileControlAffinity.leading,
            secondary: ExcludeSemantics(
                child: Icon(icon, color: t.colorScheme.onSurfaceVariant)),
            title: Text(e.name, maxLines: 1, overflow: TextOverflow.ellipsis),
            subtitle: Text(sub),
            value: _sel.contains(e.index),
            onChanged: _runner.running
                ? null
                : (v) => setState(() {
                      v == true ? _sel.add(e.index) : _sel.remove(e.index);
                    }),
          );
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final t = Theme.of(context);
    return ListenableBuilder(
      listenable: Listenable.merge([_runner, _lister]),
      builder: (context, _) {
        final busy = _runner.running;
        final listing = _lister.running;
        final idle = _runner.state == RunState.idle;
        final entries = _entries;
        final partial = entries != null && _selection != null;
        final nothingTicked = entries != null && _sel.isEmpty;
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
                  subtitle: fmtBytes(_archiveSize, ru: s.cyr),
                  removeLabel: s.change,
                  onRemove: (busy || listing)
                      ? null
                      : () {
                          _lister.reset();
                          setState(() {
                            _archive = null;
                            _entries = null;
                            _sel.clear();
                            _runner.reset();
                          });
                        },
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
                if (_encrypted && entries == null) ...[
                  const SizedBox(height: 8),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(20),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(children: [
                            Icon(Icons.lock_outline,
                                color: t.colorScheme.primary),
                            const SizedBox(width: 12),
                            Expanded(
                                child: Text(s.encryptedArchive,
                                    style: t.textTheme.titleMedium)),
                          ]),
                          const SizedBox(height: 12),
                          PasswordField(
                            controller: _pw,
                            label: s.password,
                            enabled: !listing,
                            helperText: s.enterPassword,
                            onChanged: (_) => setState(() {}),
                            onSubmitted: (_) {
                              if (!listing && !_needPw) _list();
                            },
                          ),
                          const SizedBox(height: 12),
                          FilledButton.icon(
                            onPressed: (listing || _needPw) ? null : _list,
                            icon: const Icon(Icons.lock_open_outlined),
                            label: Text(s.showContents),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
                if (listing) ...[
                  const SizedBox(height: 16),
                  Semantics(
                    liveRegion: true,
                    label: s.readingArchive,
                    child: Row(children: [
                      const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2.5)),
                      const SizedBox(width: 12),
                      Text(s.readingArchive),
                    ]),
                  ),
                ],
                if (_lister.state == RunState.error) ...[
                  const SizedBox(height: 12),
                  Semantics(
                    liveRegion: true,
                    child: Text(s.errorText(_lister.message),
                        style: TextStyle(color: t.colorScheme.error)),
                  ),
                ],
                if (entries != null) ...[
                  const SizedBox(height: 16),
                  Text(s.archiveInfo(entries.length,
                      fmtBytes(_totalBytes, ru: s.cyr)),
                      style: t.textTheme.bodyMedium?.copyWith(
                          color: t.colorScheme.onSurfaceVariant)),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _search,
                    enabled: !busy,
                    decoration: InputDecoration(
                      prefixIcon: const Icon(Icons.search),
                      labelText: s.searchFiles,
                      border: const OutlineInputBorder(),
                    ),
                    onChanged: (_) => setState(_applyFilter),
                  ),
                  const SizedBox(height: 8),
                  Card(
                    clipBehavior: Clip.antiAlias,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Padding(
                          padding: const EdgeInsets.fromLTRB(16, 8, 8, 0),
                          child: Row(children: [
                            Expanded(
                              child: Text(
                                  s.selectedInfo(
                                      _sel.length,
                                      entries.length,
                                      fmtBytes(_selectedBytes, ru: s.cyr)),
                                  style: t.textTheme.labelLarge),
                            ),
                            TextButton(
                                onPressed:
                                    busy ? null : () => _toggleVisible(true),
                                child: Text(s.selectAll)),
                            TextButton(
                                onPressed:
                                    busy ? null : () => _toggleVisible(false),
                                child: Text(s.selectNone)),
                          ]),
                        ),
                        const Divider(height: 1),
                        _entryList(s, t),
                      ],
                    ),
                  ),
                  const SizedBox(height: 8),
                  Card(
                    color: t.colorScheme.surfaceContainer,
                    child: SwitchListTile(
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(28)),
                      title: Text(s.overwrite),
                      value: _force,
                      onChanged:
                          busy ? null : (v) => setState(() => _force = v),
                    ),
                  ),
                  const SizedBox(height: 16),
                  if (idle) ...[
                    FilledButton.icon(
                      onPressed: nothingTicked ? null : _extract,
                      icon: const Icon(Icons.unarchive),
                      label: Text(partial ? s.extractSelected : s.startExtract),
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
            ],
          );
        });
      },
    );
  }
}
