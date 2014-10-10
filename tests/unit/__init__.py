"""Package for unit tests."""

from __future__ import absolute_import 

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""

    import tests.unit.test_regex as test_regex
    import tests.unit.test_rules as test_rules
    import tests.unit.test_message as test_message

    test_suite = unittest.TestSuite()
    test_suite.addTest(test_regex.suite())
    test_suite.addTest(test_message.suite())
    test_suite.addTest(test_rules.suite())
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
