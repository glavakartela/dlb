import 'dart:io';

bool get isAndroid => Platform.isAndroid;
bool get isDesktop =>
    Platform.isWindows || Platform.isLinux || Platform.isMacOS;
