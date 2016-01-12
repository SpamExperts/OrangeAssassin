"""Package for unit tests."""

from __future__ import absolute_import

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""

    import tests.unit.test_regex as test_regex
    import tests.unit.test_rules as test_rules
    import tests.unit.test_match as test_match
    import tests.unit.test_context as test_context
    import tests.unit.test_plugins as test_plugins
    import tests.unit.test_message as test_message

    test_suite = unittest.TestSuite()
    test_suite.addTest(test_regex.suite())
    test_suite.addTest(test_rules.suite())
    test_suite.addTest(test_match.suite())
    test_suite.addTest(test_context.suite())
    test_suite.addTest(test_plugins.suite())
    test_suite.addTest(test_message.suite())
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
