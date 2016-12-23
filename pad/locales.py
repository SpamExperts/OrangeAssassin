import re

from pad.regex import Regex

UNUSUAL_CHARSETS_FOR_LOCALE = {
    'ja': ('EUCJP', 'JISX020119760', 'JISX020819830', 'JISX020819900',
           'JISX020819970', 'JISX021219900', 'JISX021320001', 'JISX021320002',
           'SHIFT_JIS', 'SHIFTJIS', 'ISO2022JP', 'SJIS', 'JIS7', 'JISX0201',
           'JISX0208', 'JISX0212', ),
    # Korea
    'ko': ('EUCKR', 'KSC56011987'),

    # Cyrillic
    'ru': ('KOI8R', 'KOI8U', 'KOI8T', 'ISOIR111', 'CP1251', 'GEORGIANPS',
           'PT154', 'CP866'),
    'ka': ('KOI8R', 'KOI8U', 'KOI8T', 'ISOIR111', 'CP1251', 'GEORGIANPS',
           'PT154', 'CP866'),
    'tg': ('KOI8R', 'KOI8U', 'KOI8T', 'ISOIR111', 'CP1251', 'GEORGIANPS',
           'PT154', 'CP866'),
    'be': ('KOI8R', 'KOI8U', 'KOI8T', 'ISOIR111', 'CP1251', 'GEORGIANPS',
           'PT154', 'CP866'),
    'uk': ('KOI8R', 'KOI8U', 'KOI8T', 'ISOIR111', 'CP1251', 'GEORGIANPS',
           'PT154', 'CP866'),
    'bg': ('KOI8R', 'KOI8U', 'KOI8T', 'ISOIR111', 'CP1251', 'GEORGIANPS',
           'PT154', 'CP866'),

    # Thai
    'th': ('TIS620',),

    # Chinese
    'zh': ('GB1988', 'GB2312', 'GB231219800', 'GB18030', 'GBK', 'BIG5HKSCS',
           'BIG5', 'EUCTW', 'ISO2022CN'),

}

ALWAYS_OK_CHARSETS_PATTERN = """
^USASCII$|
^ISO8859|
^ISO10646|
^UTF|
^USC|
^CP125|
^WINDOWS|
^UNICODE11UTF[78]|
^XUNKNOWN$|
^ISO$"""

ALWAYS_OK_CHARSETS_RE = Regex(ALWAYS_OK_CHARSETS_PATTERN, re.VERBOSE)
INVALID_CHARACTERS_RE = Regex(r'[^A-Z0-9]')


def charset_ok_for_locales(charset, locales):
    if not charset:
        charset = ""
    clean_charset = charset.upper()
    clean_charset = INVALID_CHARACTERS_RE.sub("", clean_charset)

    if ALWAYS_OK_CHARSETS_RE.match(clean_charset):
        return True

    for locale in locales:
        if locale == "C":
            locale = "en"
        locale = locale[:2]
        unusual_charsets = UNUSUAL_CHARSETS_FOR_LOCALE.get(locale, [])
        if unusual_charsets and (clean_charset in unusual_charsets):
            return True
    return False
