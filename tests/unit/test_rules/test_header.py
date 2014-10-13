"""Tests for sa.rules.header"""

import unittest

try:
    from unittest.mock import patch, Mock, call
except ImportError:
    from mock import patch, Mock, call

import sa.rules.header


class TestMimeHeader(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mock_raw_mime = patch("sa.rules.header._PatternMimeRawHeaderRule").start()
        self.mock_mime = patch("sa.rules.header._PatternMimeHeaderRule").start()
        self.mock_perl2re = patch("sa.rules.header.sa.regex.perl2re").start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_get_rule_mimeheader(self):
        data = {"value": "Content-Id =~ /test/"}
        expected = {"header_name": "Content-Id",
                    "pattern": self.mock_perl2re(" /test/")}
        result = sa.rules.header.MimeHeaderRule.get_rule("TEST", data)
        self.mock_perl2re.assert_called_with(" /test/")
        self.assertEqual(self.mock_mime("TEST", **expected), result)

    def test_get_rule_raw_mimeheader(self):
        data = {"value": "Content-Id:raw =~ /test/"}
        expected = {"header_name": "Content-Id",
                    "pattern": self.mock_perl2re(" /test/")}
        result = sa.rules.header.MimeHeaderRule.get_rule("TEST", data)
        self.mock_perl2re.assert_called_with(" /test/")
        self.assertEqual(self.mock_raw_mime("TEST", **expected), result)

    def test_match(self):
        result = sa.rules.header.MimeHeaderRule("TEST")
        self.assertRaises(NotImplementedError, result.match, Mock())


class TestPatternMimeHeader(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mime_headers = ["test1", "test2"]
        self.mock_msg = Mock(**{"get_decoded_mime_header.return_value":
                                self.mime_headers})

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        header_name = "Content-Id"
        mock_pattern = Mock(**{"match.return_value": True})
        rule = sa.rules.header._PatternMimeHeaderRule("TEST",
                                                      pattern=mock_pattern,
                                                      header_name=header_name)
        result = rule.match(self.mock_msg)

        self.mock_msg.get_decoded_mime_header.assert_called_with(header_name)
        mock_pattern.match.assert_called_once_with(self.mime_headers[0])
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        header_name = "Content-Id"
        mock_pattern = Mock(**{"match.return_value": False})
        rule = sa.rules.header._PatternMimeHeaderRule("TEST",
                                                      pattern=mock_pattern,
                                                      header_name=header_name)
        result = rule.match(self.mock_msg)

        calls = [call(value) for value in self.mime_headers]
        self.mock_msg.get_decoded_mime_header.assert_called_with(header_name)
        mock_pattern.match.assert_has_calls(calls)
        self.assertEqual(result, False)


class TestPatternRawMimeHeader(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mime_headers = ["test1", "test2"]
        self.mock_msg = Mock(**{"get_raw_mime_header.return_value":
                                self.mime_headers})

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        header_name = "Content-Id"
        mock_pattern = Mock(**{"match.return_value": True})
        rule = sa.rules.header._PatternMimeRawHeaderRule("TEST",
                                                         pattern=mock_pattern,
                                                         header_name=header_name)
        result = rule.match(self.mock_msg)

        self.mock_msg.get_raw_mime_header.assert_called_with(header_name)
        mock_pattern.match.assert_called_once_with(self.mime_headers[0])
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        header_name = "Content-Id"
        mock_pattern = Mock(**{"match.return_value": False})
        rule = sa.rules.header._PatternMimeRawHeaderRule("TEST",
                                                         pattern=mock_pattern,
                                                         header_name=header_name)
        result = rule.match(self.mock_msg)

        calls = [call(value) for value in self.mime_headers]
        self.mock_msg.get_raw_mime_header.assert_called_with(header_name)
        mock_pattern.match.assert_has_calls(calls)
        self.assertEqual(result, False)


class TestHeaderRule(unittest.TestCase):
    _mocks = ("_AllHeaderRule", "_ToCcHeaderRule", "_MessageIDHeaderRule",
              "_PatternRawHeaderRule", "_PatternAddrHeaderRule",
              "_PatternNameHeaderRule", "_PatternHeaderRule",
              "_ExistsHeaderRule"
              )

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.mocks = {}
        for mock in self._mocks:
            self.mocks[mock] = patch("sa.rules.header.%s" % mock).start()
        self.mock_perl2re = patch("sa.rules.header.sa.regex.perl2re").start()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        result = sa.rules.header.HeaderRule("TEST")
        self.assertRaises(NotImplementedError, result.match, Mock())

    def check_get_rule(self, value, klass, name=None, pattern=None):
        data = {"value": value}
        expected = {}
        if name is not None:
            expected["header_name"] = name
        if pattern is not None:
            expected["pattern"] = self.mock_perl2re(pattern)

        result = sa.rules.header.HeaderRule.get_rule("TEST", data)
        if pattern is not None:
            self.mock_perl2re.assert_called_with(" /test/")
        self.assertEqual(self.mocks[klass]("TEST", **expected), result)

    def test_get_rule_allheader(self):
        self.check_get_rule("ALL =~ /test/", "_AllHeaderRule", pattern="/test/")

    def test_get_rule_toccheader(self):
        self.check_get_rule("ToCc =~ /test/", "_ToCcHeaderRule", pattern="/test/")

    def test_get_rule_msgidheader(self):
        self.check_get_rule("MESSAGEID =~ /test/", "_MessageIDHeaderRule",
                            pattern="/test/")

    def test_get_rule_header(self):
        self.check_get_rule("X-Test =~ /test/", "_PatternHeaderRule",
                            name="X-Test", pattern="/test/")

    def test_get_rule_raw_header(self):
        self.check_get_rule("X-Test:raw =~ /test/", "_PatternRawHeaderRule",
                            name="X-Test", pattern="/test/")

    def test_get_rule_addr_header(self):
        self.check_get_rule("X-Test:addr =~ /test/", "_PatternAddrHeaderRule",
                            name="X-Test", pattern="/test/")

    def test_get_rule_name_header(self):
        self.check_get_rule("X-Test:name =~ /test/", "_PatternNameHeaderRule",
                            name="X-Test", pattern="/test/")

    def test_get_exists_header(self):
        self.check_get_rule("exists:X-Test", "_ExistsHeaderRule",
                            name="X-Test")


class TestExistsHeader(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.headers = ["test1", "test2"]
        self.mock_msg = Mock(raw_headers=self.headers)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        rule = sa.rules.header._ExistsHeaderRule("TEST", header_name="test1")
        result = rule.match(self.mock_msg)
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        rule = sa.rules.header._ExistsHeaderRule("TEST", header_name="test3")
        result = rule.match(self.mock_msg)
        self.assertEqual(result, False)


class TestPatternHeader(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.headers = ["test1", "test2"]
        self.mock_msg = Mock(**{"get_decoded_header.return_value":
                                self.headers})

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        header_name = "X-Test"
        mock_pattern = Mock(**{"match.return_value": True})
        rule = sa.rules.header._PatternHeaderRule("TEST",
                                                  pattern=mock_pattern,
                                                  header_name=header_name)
        result = rule.match(self.mock_msg)

        self.mock_msg.get_decoded_header.assert_called_with(header_name)
        mock_pattern.match.assert_called_once_with(self.headers[0])
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        header_name = "X-Test"
        mock_pattern = Mock(**{"match.return_value": False})
        rule = sa.rules.header._PatternHeaderRule("TEST",
                                                  pattern=mock_pattern,
                                                  header_name=header_name)
        result = rule.match(self.mock_msg)

        calls = [call(value) for value in self.headers]
        self.mock_msg.get_decoded_header.assert_called_with(header_name)
        mock_pattern.match.assert_has_calls(calls)
        self.assertEqual(result, False)


class TestPatternRawHeader(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.headers = ["test1", "test2"]
        self.mock_msg = Mock(**{"get_raw_header.return_value":
                                self.headers})

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        header_name = "X-Test"
        mock_pattern = Mock(**{"match.return_value": True})
        rule = sa.rules.header._PatternRawHeaderRule("TEST",
                                                     pattern=mock_pattern,
                                                     header_name=header_name)
        result = rule.match(self.mock_msg)

        self.mock_msg.get_raw_header.assert_called_with(header_name)
        mock_pattern.match.assert_called_once_with(self.headers[0])
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        header_name = "X-Test"
        mock_pattern = Mock(**{"match.return_value": False})
        rule = sa.rules.header._PatternRawHeaderRule("TEST",
                                                     pattern=mock_pattern,
                                                     header_name=header_name)
        result = rule.match(self.mock_msg)

        calls = [call(value) for value in self.headers]
        self.mock_msg.get_raw_header.assert_called_with(header_name)
        mock_pattern.match.assert_has_calls(calls)
        self.assertEqual(result, False)


class TestPatternAddrHeader(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.headers = ["test1", "test2"]
        self.mock_msg = Mock(**{"get_addr_header.return_value":
                                self.headers})

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        header_name = "X-Test"
        mock_pattern = Mock(**{"match.return_value": True})
        rule = sa.rules.header._PatternAddrHeaderRule("TEST",
                                                      pattern=mock_pattern,
                                                      header_name=header_name)
        result = rule.match(self.mock_msg)

        self.mock_msg.get_addr_header.assert_called_with(header_name)
        mock_pattern.match.assert_called_once_with(self.headers[0])
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        header_name = "X-Test"
        mock_pattern = Mock(**{"match.return_value": False})
        rule = sa.rules.header._PatternAddrHeaderRule("TEST",
                                                      pattern=mock_pattern,
                                                      header_name=header_name)
        result = rule.match(self.mock_msg)

        calls = [call(value) for value in self.headers]
        self.mock_msg.get_addr_header.assert_called_with(header_name)
        mock_pattern.match.assert_has_calls(calls)
        self.assertEqual(result, False)


class TestPatternNameHeader(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.headers = ["test1", "test2"]
        self.mock_msg = Mock(**{"get_name_header.return_value":
                                self.headers})

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        header_name = "X-Test"
        mock_pattern = Mock(**{"match.return_value": True})
        rule = sa.rules.header._PatternNameHeaderRule("TEST",
                                                      pattern=mock_pattern,
                                                      header_name=header_name)
        result = rule.match(self.mock_msg)

        self.mock_msg.get_name_header.assert_called_with(header_name)
        mock_pattern.match.assert_called_once_with(self.headers[0])
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        header_name = "X-Test"
        mock_pattern = Mock(**{"match.return_value": False})
        rule = sa.rules.header._PatternNameHeaderRule("TEST",
                                                      pattern=mock_pattern,
                                                      header_name=header_name)
        result = rule.match(self.mock_msg)

        calls = [call(value) for value in self.headers]
        self.mock_msg.get_name_header.assert_called_with(header_name)
        mock_pattern.match.assert_has_calls(calls)
        self.assertEqual(result, False)


class TestMultiplePatternHeader(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.header_names = ["X-Test1", "X-Test2"]
        sa.rules.header._MultiplePatternHeaderRule._headers = self.header_names
        self.headers = ["test1", "test2"]
        self.mock_msg = Mock(**{"get_decoded_header.return_value":
                                self.headers})

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        sa.rules.header._MultiplePatternHeaderRule._headers = None
        patch.stopall()

    def test_match(self):
        mock_pattern = Mock(**{"match.return_value": True})
        rule = sa.rules.header._MultiplePatternHeaderRule("TEST",
                                                          pattern=mock_pattern)
        result = rule.match(self.mock_msg)

        self.mock_msg.get_decoded_header.assert_called_with(self.header_names[0])
        mock_pattern.match.assert_called_once_with(self.headers[0])
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        mock_pattern = Mock(**{"match.return_value": False})
        rule = sa.rules.header._MultiplePatternHeaderRule("TEST",
                                                          pattern=mock_pattern)
        result = rule.match(self.mock_msg)

        calls = [call(value) for value in self.header_names]
        self.mock_msg.get_decoded_header.assert_has_calls(calls)

        calls = [call(value) for value in self.headers]
        mock_pattern.match.assert_has_calls(calls)

        self.assertEqual(result, False)


class TestAllHeaderRule(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.headers = ["test1", "test2"]
        self.mock_msg = Mock(**{"iter_decoded_headers.return_value":
                                self.headers})

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_match(self):
        mock_pattern = Mock(**{"match.return_value": True})
        rule = sa.rules.header._AllHeaderRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)

        self.assertTrue(self.mock_msg.iter_decoded_headers.called)
        mock_pattern.match.assert_called_once_with(self.headers[0])
        self.assertEqual(result, True)

    def test_match_notmatched(self):
        mock_pattern = Mock(**{"match.return_value": False})
        rule = sa.rules.header._AllHeaderRule("TEST", pattern=mock_pattern)
        result = rule.match(self.mock_msg)

        self.assertTrue(self.mock_msg.iter_decoded_headers.called)
        calls = [call(value) for value in self.headers]
        mock_pattern.match.assert_has_calls(calls)
        self.assertEqual(result, False)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestMimeHeader, "test"))
    test_suite.addTest(unittest.makeSuite(TestPatternMimeHeader, "test"))
    test_suite.addTest(unittest.makeSuite(TestPatternRawMimeHeader, "test"))

    test_suite.addTest(unittest.makeSuite(TestHeaderRule, "test"))
    test_suite.addTest(unittest.makeSuite(TestExistsHeader, "test"))

    test_suite.addTest(unittest.makeSuite(TestPatternHeader, "test"))
    test_suite.addTest(unittest.makeSuite(TestPatternRawHeader, "test"))
    test_suite.addTest(unittest.makeSuite(TestPatternAddrHeader, "test"))
    test_suite.addTest(unittest.makeSuite(TestPatternNameHeader, "test"))

    test_suite.addTest(unittest.makeSuite(TestMultiplePatternHeader, "test"))
    test_suite.addTest(unittest.makeSuite(TestAllHeaderRule, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
