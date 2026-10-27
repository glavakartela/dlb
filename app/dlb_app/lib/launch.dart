import 'package:flutter/foundation.dart';

/// A `.dlb` file passed on the command line ("Open with DLB", file association).
/// The extract page consumes it once and clears it.
final ValueNotifier<String?> launchArchive = ValueNotifier<String?>(null);
