import 'package:flutter/widgets.dart';

import 'strings_i18n.dart';

/// Localization: Russian and English are written inline; Ukrainian, German, Spanish and
/// Chinese are looked up in [kTr] by the English text (missing entries fall back to English).
class S {
  S(this.code);
  final String code;

  static S of(BuildContext c) =>
      S(Localizations.localeOf(c).languageCode);

  bool get ru => code == 'ru';

  /// Cyrillic unit names (Б, КБ, МБ) are used for Russian and Ukrainian.
  bool get cyr => code == 'ru' || code == 'uk';

  String t(String r, String e) => ru ? r : (kTr[code]?[e] ?? e);

  /// Picks a per-language template (key = language code, 'en' is the fallback).
  String _p(Map<String, String> m) => m[code] ?? m['en']!;

  String get appName => 'DLB';
  String get navCompress => t('Сжать', 'Compress');
  String get navExtract => t('Распаковать', 'Extract');
  String get navHelp => t('Справка', 'Help');

  String get compressTitle => t('Сжать файлы', 'Compress files');
  String get compressHint =>
      t('Максимальное сжатие в формат .dlb', 'Maximum compression into .dlb');
  String get dropHere => t('Перетащите файлы сюда', 'Drop files here');
  String get pickFiles => t('Выберите файлы', 'Choose files');
  String get files => t('Файлы', 'Files');
  String get folder => t('Папка', 'Folder');
  String get remove => t('Убрать', 'Remove');
  String get quality => t('Степень сжатия', 'Compression level');
  String get fast => t('Быстро', 'Fast');
  String get balanced => t('Баланс', 'Balanced');
  String get ultra => t('Ультра', 'Ultra');
  String get ultraWarn => t(
      'Ультра: самое сильное сжатие, какое умеет программа. Один поток, примерно в 1,6 раза медленнее обычного максимума, около 550 МБ памяти.',
      'Ultra: the strongest compression this program can do. Single thread, roughly 1.6x slower than Maximum, about 550 MB of memory.');
  String get maximum => t('Максимум', 'Maximum');
  String ramHint(int level, int mb) => _p({
        'en': 'Level $level · about $mb MB of memory',
        'ru': 'Уровень $level · около $mb МБ памяти',
        'uk': 'Рівень $level · близько $mb МБ пам’яті',
        'de': 'Stufe $level · etwa $mb MB Speicher',
        'es': 'Nivel $level · unos $mb MB de memoria',
        'zh': '级别 $level · 约 $mb MB 内存',
      });
  String get multiCore => t('Все ядра процессора', 'Use all CPU cores');
  String get multiCoreHint => t(
      'Большие данные (от 64 МБ) делятся на блоки и сжимаются параллельно: быстрее в разы, ужатие чуть слабее, памяти больше.',
      'Large data (64 MB and up) is split into blocks compressed in parallel: several times faster, slightly weaker ratio, more memory.');
  String get slowNote => t(
      'Чем сильнее сжатие, тем дольше работа: примерно 0,4 МБ/с.',
      'Stronger compression takes longer: roughly 0.4 MB/s.');
  String get saveAs => t('Сохранить как', 'Save as');
  String get change => t('Изменить', 'Change');
  String get startCompress => t('Сжать', 'Compress');

  String get extractTitle => t('Распаковать архив', 'Extract archive');
  String get extractHint => t('Файл .dlb', 'A .dlb file');
  String get pickArchive => t('Выбрать архив', 'Choose archive');
  String get destination => t('Куда распаковать', 'Extract to');
  String get overwrite =>
      t('Перезаписывать существующие файлы', 'Overwrite existing files');
  String get startExtract => t('Распаковать', 'Extract');
  String get verify => t('Проверить целостность', 'Verify integrity');

  String get reading => t('Чтение файлов…', 'Reading files…');
  String get compressing => t('Сжатие', 'Compressing');
  String get extracting => t('Распаковка', 'Extracting');
  String get writing => t('Запись…', 'Writing…');
  String get cancel => t('Отмена', 'Cancel');
  String get cancelling => t('Отмена…', 'Cancelling…');
  String get cancelledMsg => t('Отменено', 'Cancelled');
  String get done => t('Готово', 'Done');
  String get verified => t('Архив цел, CRC совпал', 'Archive is intact, CRC matches');
  String get error => t('Ошибка', 'Error');
  String get again => t('Ещё раз', 'Again');
  String get newTask => t('Новая задача', 'New task');
  String get openFolder => t('Показать папку', 'Show folder');
  String get copyPath => t('Копировать путь', 'Copy path');
  String get copied => t('Путь скопирован', 'Path copied');
  String get saveCopy => t('Сохранить копию…', 'Save a copy…');
  String get saved => t('Сохранено', 'Saved');
  String filesCount(int n) => _p({
        'en': '$n file${n == 1 ? '' : 's'}',
        'ru': '$n ${_plural(n, 'файл', 'файла', 'файлов')}',
        'uk': '$n ${_plural(n, 'файл', 'файли', 'файлів')}',
        'de': '$n ${n == 1 ? 'Datei' : 'Dateien'}',
        'es': '$n ${n == 1 ? 'archivo' : 'archivos'}',
        'zh': '$n 个文件',
      });
  String get savedSpace => t('меньше', 'smaller');
  String speed(String s) => _p({
        'en': '$s/s',
        'ru': '$s/с',
        'uk': '$s/с',
        'de': '$s/s',
        'es': '$s/s',
        'zh': '$s/秒',
      });
  String eta(String s) => _p({
        'en': '$s left',
        'ru': 'осталось $s',
        'uk': 'залишилось $s',
        'de': '$s übrig',
        'es': 'quedan $s',
        'zh': '剩余 $s',
      });
  String get secUnit => _p({'en': 's', 'ru': 'с', 'uk': 'с', 'zh': '秒'});
  String get androidStorageNote => t(
      'На Android результат сначала создаётся во временной папке приложения, затем его можно сохранить через системный диалог.',
      'On Android the result is first built in the app cache; then you can save it with the system dialog.');

  String get helpTitle => t('Справка', 'Help');
  String get helpWhatTitle => t('Как это работает', 'How it works');
  String get helpWhat => t(
      'DLB использует контекстное смешивание (как PAQ): десятки моделей предсказывают каждый бит, а арифметический кодер записывает результат. Это сильнее zip и xz, но медленнее.',
      'DLB uses context mixing (like PAQ): dozens of models predict every bit and an arithmetic coder stores the result. Stronger than zip and xz, but slower.');
  String get helpGoodTitle => t('Хорошо сжимается', 'Compresses well');
  String get helpGood => t(
      'Текст, исходный код, логи, таблицы, повторяющиеся данные: в 4-9 раз, а при сильной избыточности в десятки раз.',
      'Text, source code, logs, tables, repetitive data: 4-9x, and tens of times when data is highly redundant.');
  String get helpBadTitle => t('Почти не сжимается', 'Barely compresses');
  String get helpBad => t(
      'JPEG, MP4, ZIP, зашифрованные и случайные данные. Это ограничение теории, а не программы.',
      'JPEG, MP4, ZIP, encrypted and random data. That is a limit of theory, not of the program.');
  String get helpLimitsTitle => t('Ограничения', 'Limits');
  String get helpLimits => t(
      'Размер ограничен доступной памятью: всё обрабатывается в ОЗУ. Файлы упаковываются вместе (solid), поэтому для извлечения одного файла распаковывается весь архив.',
      'Size is limited by available memory: everything is processed in RAM. Files are packed together (solid), so extracting one file decompresses the whole archive.');
  String get helpFormat => t('Формат', 'Format');
  // password protection
  String get passwordOptional => t('Пароль (необязательно)', 'Password (optional)');
  String get password => t('Пароль', 'Password');
  String get repeatPassword => t('Повторите пароль', 'Repeat password');
  String get passwordMismatch => t('Пароли не совпадают', 'Passwords do not match');
  String get passwordHelp => t(
      'Шифрует архив вместе с именами файлов. Если забудете пароль, данные восстановить нельзя.',
      'Encrypts the archive together with file names. If you forget the password, the data cannot be recovered.');
  String get showPassword => t('Показать пароль', 'Show password');
  String get hidePassword => t('Скрыть пароль', 'Hide password');
  String get encryptedArchive => t('Архив защищён паролем', 'Password protected archive');
  String get enterPassword => t('Введите пароль, чтобы открыть его', 'Enter the password to open it');
  String get wrongPassword => t('Неверный пароль или архив повреждён', 'Wrong password or damaged archive');
  String get passwordRequired => t('Для этого архива нужен пароль', 'This archive needs a password');
  String get helpSecurityTitle => t('Защита паролем', 'Password protection');
  String get helpSecurity => t(
      'Необязательна. Шифрование ChaCha20 с проверкой подлинности HMAC-SHA256 и ключом PBKDF2 (300 000 итераций); имена файлов тоже скрыты. Код написан с нуля и не проходил независимый аудит, поэтому для особо важных секретов используйте ещё и проверенный инструмент.',
      'Optional. ChaCha20 encryption with HMAC-SHA256 authentication and a PBKDF2 key (300,000 iterations); file names are hidden too. The code is written from scratch and has not been audited by third parties, so for critical secrets also use a well-known tool.');

  /// Translates the few error texts the core produces that the user can act on.
  String errorText(String raw) {
    if (raw == 'wrong password or damaged archive') return wrongPassword;
    if (raw == 'password required') return passwordRequired;
    return raw;
  }

  String get language => t('Язык', 'Language');

  static String _plural(int n, String one, String few, String many) {
    final m10 = n % 10, m100 = n % 100;
    if (m10 == 1 && m100 != 11) return one;
    if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
    return many;
  }
}
