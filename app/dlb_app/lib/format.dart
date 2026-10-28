/// Pure helpers (unit tested).
String fmtBytes(num b, {bool ru = true}) {
  const ruU = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  const enU = ['B', 'KB', 'MB', 'GB', 'TB'];
  final u = ru ? ruU : enU;
  var v = b.toDouble();
  var i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  final s = (i == 0 || v >= 100) ? v.toStringAsFixed(0) : v.toStringAsFixed(v >= 10 ? 1 : 2);
  return '$s ${u[i]}';
}

/// "x8.4" style ratio; huge ratios are rounded to whole numbers.
String fmtRatio(num original, num compressed) {
  if (compressed <= 0) return '-';
  final r = original / compressed;
  if (r >= 100) return '×${r.round()}';
  if (r >= 10) return '×${r.toStringAsFixed(1)}';
  return '×${r.toStringAsFixed(2)}';
}

String fmtDuration(Duration d, {String sec = 's'}) {
  final s = d.inSeconds;
  if (s < 60) return '$s $sec';
  final m = s ~/ 60;
  if (m < 60) return '$m:${(s % 60).toString().padLeft(2, '0')}';
  return '${m ~/ 60}:${(m % 60).toString().padLeft(2, '0')}:${(s % 60).toString().padLeft(2, '0')}';
}

/// Approximate peak RAM in MB for a compression level (1..9), excluding the data itself
/// (add roughly 2x the input size). Context table = 4 bytes << (17 + level); the two
/// match tables use 4 bytes << min(22, nbits - 2) each; ~12 MB for APM and mixers.
/// Measured on a 3 MB input: level 4 = 26 MB, 7 = 114 MB, 9 = 306 MB.
int levelRamMb(int level) {
  final nbits = 17 + level;
  final hbits = nbits - 2 > 22 ? 22 : nbits - 2;
  const mb = 1 << 20;
  return (4 << nbits) ~/ mb + 2 * (4 << hbits) ~/ mb + 12;
}

/// Extra RAM of the low-memory mode on top of [levelRamMb]: one 64 MB block of input plus
/// its compressed output and buffers (measured: level 1 peaks at 87 MB for any input size).
const int lowMemExtraMb = 85;

/// Next free name: `a.dlb`, `a (1).dlb`, ...
String uniqueName(String name, bool Function(String) exists) {
  if (!exists(name)) return name;
  final dot = name.lastIndexOf('.');
  final stem = dot > 0 ? name.substring(0, dot) : name;
  final ext = dot > 0 ? name.substring(dot) : '';
  for (var i = 1; i < 10000; i++) {
    final c = '$stem ($i)$ext';
    if (!exists(c)) return c;
  }
  return name;
}
