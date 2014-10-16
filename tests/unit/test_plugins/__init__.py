"""Package for unit tests."""

from __future__ import absolute_import

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""

    import tests.unit.test_plugins.test_base as test_base

    test_suite = unittest.TestSuite()
    test_suite.addTest(test_base.suite())
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
