import 'package:flutter/material.dart';

/// Horizontal inset that keeps content at a readable 640 px measure
/// on wide screens and 16 px gutters on phones.
double gutterFor(double width) =>
    ((width - 640) / 2).clamp(16.0, double.infinity).toDouble();

class PageHeader extends StatelessWidget {
  const PageHeader({super.key, required this.title, required this.subtitle});
  final String title;
  final String subtitle;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Semantics(header: true, child: Text(title, style: t.textTheme.headlineMedium)),
        const SizedBox(height: 4),
        Text(subtitle,
            style: t.textTheme.bodyLarge
                ?.copyWith(color: t.colorScheme.onSurfaceVariant)),
      ],
    );
  }
}

/// A labelled file/folder row with an optional remove button (48 dp hit area).
class PathTile extends StatelessWidget {
  const PathTile({
    super.key,
    required this.icon,
    required this.title,
    required this.subtitle,
    this.onRemove,
    this.removeLabel = '',
  });
  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback? onRemove;
  final String removeLabel;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context);
    return Card(
      color: t.colorScheme.surfaceContainer,
      child: ListTile(
        minVerticalPadding: 12,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        leading: ExcludeSemantics(child: Icon(icon, color: t.colorScheme.primary)),
        title: Text(title, maxLines: 1, overflow: TextOverflow.ellipsis),
        subtitle: Text(subtitle,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(color: t.colorScheme.onSurfaceVariant)),
        trailing: onRemove == null
            ? null
            : IconButton(
                tooltip: removeLabel,
                onPressed: onRemove,
                icon: const Icon(Icons.close),
              ),
      ),
    );
  }
}
