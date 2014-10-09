import re
import unittest

try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock

import sa.regex


class TestPerl2Re(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_compile = patch("sa.regex.re.compile").start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def check_compile(self, pattern=None, flags=None):
        cpattern, cflags = self.mock_compile.call_args[0]
        if pattern is not None:
            self.assertEqual(cpattern, pattern)
        if flags is not None:
            self.assertEqual(cflags, flags)

    def test_strip_flags(self):
        sa.regex.perl2re("m/test/gisapsd")
        self.check_compile("test")

    def test_correct_all_flags(self):
        sa.regex.perl2re("m/test/ismx")
        self.check_compile("test", re.I | re.S | re.M | re.X)

    def test_correct_some_flags(self):
        sa.regex.perl2re("m/test/im")
        self.check_compile("test", re.I | re.M)

    def test_no_flags(self):
        sa.regex.perl2re("m/test/")
        self.check_compile("test", 0)


class TestPattern(unittest.TestCase):
    def test_pattern(self):
        p = sa.regex.Pattern(None)
        self.assertRaises(NotImplementedError, p.match, "test")

    def test_matchpattern_matched(self):
        p = sa.regex.MatchPattern(Mock(**{"search.return_value": True}))
        result = p.match("test")
        self.assertEqual(result, 1)

    def test_matchpattern_not_matched(self):
        p = sa.regex.MatchPattern(Mock(**{"search.return_value": False}))
        result = p.match("test")
        self.assertEqual(result, 0)

    def test_countpattern_matched(self):
        p = sa.regex.CountPattern(Mock(**{"findall.return_value": ["1", "1"]}))
        result = p.match("test")
        self.assertEqual(result, 2)

    def test_countpattern_not_matched(self):
        p = sa.regex.CountPattern(Mock(**{"findall.return_value": []}))
        result = p.match("test")
        self.assertEqual(result, 0)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestPerl2Re, "test"))
    test_suite.addTest(unittest.makeSuite(TestPattern, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
