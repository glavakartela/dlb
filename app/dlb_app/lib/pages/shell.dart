import 'package:flutter/material.dart';

import '../launch.dart';
import '../strings.dart';
import 'compress_page.dart';
import 'extract_page.dart';
import 'help_page.dart';

/// Adaptive navigation: bottom bar on phones, rail on wide windows.
class Shell extends StatefulWidget {
  const Shell({super.key});

  @override
  State<Shell> createState() => _ShellState();
}

class _ShellState extends State<Shell> {
  // an archive passed on the command line opens the Extract tab
  int _index = launchArchive.value != null ? 1 : 0;

  // IndexedStack keeps every page alive, so a running job survives tab switches.
  static const _pages = [CompressPage(), ExtractPage(), HelpPage()];

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final body = SafeArea(
      bottom: false,
      child: IndexedStack(index: _index, children: _pages),
    );

    return LayoutBuilder(builder: (context, c) {
      if (c.maxWidth < 840) {
        return Scaffold(
          body: body,
          bottomNavigationBar: NavigationBar(
            selectedIndex: _index,
            onDestinationSelected: (i) => setState(() => _index = i),
            destinations: [
              NavigationDestination(
                  icon: const Icon(Icons.compress), label: s.navCompress),
              NavigationDestination(
                  icon: const Icon(Icons.unarchive_outlined),
                  selectedIcon: const Icon(Icons.unarchive),
                  label: s.navExtract),
              NavigationDestination(
                  icon: const Icon(Icons.help_outline),
                  selectedIcon: const Icon(Icons.help),
                  label: s.navHelp),
            ],
          ),
        );
      }
      return Scaffold(
        body: Row(
          children: [
            SafeArea(
              child: NavigationRail(
                extended: c.maxWidth >= 1100,
                selectedIndex: _index,
                onDestinationSelected: (i) => setState(() => _index = i),
                destinations: [
                  NavigationRailDestination(
                      icon: const Icon(Icons.compress),
                      label: Text(s.navCompress)),
                  NavigationRailDestination(
                      icon: const Icon(Icons.unarchive_outlined),
                      selectedIcon: const Icon(Icons.unarchive),
                      label: Text(s.navExtract)),
                  NavigationRailDestination(
                      icon: const Icon(Icons.help_outline),
                      selectedIcon: const Icon(Icons.help),
                      label: Text(s.navHelp)),
                ],
              ),
            ),
            Expanded(child: body),
          ],
        ),
      );
    });
  }
}
