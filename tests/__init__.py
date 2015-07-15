#! /usr/bin/env python

"""Package reserved for tests and test utilities."""

from __future__ import absolute_import

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""
    import tests.unit
    import tests.functional

    test_suite = unittest.TestSuite()
    test_suite.addTest(tests.unit.suite())
    test_suite.addTest(tests.functional.suite())
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
