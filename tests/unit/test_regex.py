"""Tests for pad.regex"""

import re
import unittest

try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock

import oa.regex


class TestPerl2Re(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_compile = patch("oa.regex.re.compile").start()
        self.mock_match_pattern = patch("oa.regex.MatchPattern").start()
        self.mock_notmatch_pattern = patch("oa.regex.NotMatchPattern").start()

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
        oa.regex.perl2re("m/test/gisapsd")
        self.check_compile("test")

    def test_correct_all_flags(self):
        oa.regex.perl2re("m/test/ismx")
        self.check_compile("test", re.I | re.S | re.M | re.X)

    def test_correct_some_flags(self):
        oa.regex.perl2re("m/test/im")
        self.check_compile("test", re.I | re.M)

    def test_no_flags(self):
        oa.regex.perl2re("m/test/")
        self.check_compile("test", 0)

    def test_match_op_pattern(self):
        result = oa.regex.perl2re("/test/", "=~")
        pattern = self.mock_compile("test", 0)
        self.assertEqual(result, self.mock_match_pattern(pattern))

    def test_match_op_pattern_not(self):
        result = oa.regex.perl2re("/test/", "!~")
        pattern = self.mock_compile("test", 0)
        self.assertEqual(result, self.mock_notmatch_pattern(pattern))


class TestPattern(unittest.TestCase):
    def test_pattern(self):
        p = oa.regex.Pattern(None)
        self.assertRaises(NotImplementedError, p.match, "test")

    def test_matchpattern_matched(self):
        p = oa.regex.MatchPattern(Mock(**{"search.return_value": True}))
        result = p.match("test")
        self.assertEqual(result, 1)

    def test_matchpattern_not_matched(self):
        p = oa.regex.MatchPattern(Mock(**{"search.return_value": False}))
        result = p.match("test")
        self.assertEqual(result, 0)

    def test_notmatchpattern_matched(self):
        p = oa.regex.NotMatchPattern(Mock(**{"search.return_value": True}))
        result = p.match("test")
        self.assertEqual(result, 0)

    def test_notmatchpattern_not_matched(self):
        p = oa.regex.NotMatchPattern(Mock(**{"search.return_value": False}))
        result = p.match("test")
        self.assertEqual(result, 1)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestPerl2Re, "test"))
    test_suite.addTest(unittest.makeSuite(TestPattern, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
