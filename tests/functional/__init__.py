"""Package for functional tests."""

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""
    from tests.functional import test_match

    test_suite = unittest.TestSuite()
    test_suite.addTest(test_match.suite())
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
