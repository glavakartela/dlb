import 'package:dlb_app/format.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('fmtBytes', () {
    expect(fmtBytes(0, ru: false), '0 B');
    expect(fmtBytes(1536, ru: false), '1.50 KB');
    expect(fmtBytes(3 * 1024 * 1024, ru: true), '3.00 МБ');
    expect(fmtBytes(250 * 1024 * 1024, ru: false), '250 MB');
  });
  test('fmtRatio', () {
    expect(fmtRatio(1000, 125), '×8.00');
    expect(fmtRatio(1000, 50), '×20.0');
    expect(fmtRatio(20000000, 1807), '×11068');
    expect(fmtRatio(10, 0), '-');
  });
  test('levelRamMb', () {
    expect(levelRamMb(4), 8 + 4 + 12);
    expect(levelRamMb(7), 64 + 32 + 12);
    expect(levelRamMb(9), 256 + 32 + 12);
  });
  test('uniqueName', () {
    final taken = {'a.dlb', 'a (1).dlb'};
    expect(uniqueName('b.dlb', taken.contains), 'b.dlb');
    expect(uniqueName('a.dlb', taken.contains), 'a (2).dlb');
  });
}
