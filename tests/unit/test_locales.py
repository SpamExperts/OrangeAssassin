import unittest

import oa.locales


class TestLocale(unittest.TestCase):
    always_valid_charsets = ("iSo-8859-7", "UTF-8", "WINDOWS", "CP-1254")
    invalid_charsets = ("NOT-A-CHARSET", )

    def setUp(self):
        unittest.TestCase.setUp(self)

    def tearDown(self):
        unittest.TestCase.tearDown(self)

    def test_always_valid_charset(self):
        for charset in self.always_valid_charsets:
            ok = oa.locales.charset_ok_for_locales(charset, ["gr", "ru"])
            self.assertTrue(ok)

    def test_unusual_charset(self):
        locale_charsets = oa.locales.UNUSUAL_CHARSETS_FOR_LOCALE.items()
        for locale, charsets in locale_charsets:
            for charset in charsets:
                ok = oa.locales.charset_ok_for_locales(charset, [locale])
                self.assertTrue(ok,
                                "Didn't match %s with %s" % (locale, charset))

    def test_invalid_charset(self):
        for charset in self.invalid_charsets:
            ok = oa.locales.charset_ok_for_locales(charset, ["gr", "ru"])
            self.assertFalse(ok)
