"""Package for unit tests."""

from __future__ import absolute_import

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""

    import tests.unit.test_plugins.test_base as test_base
    import tests.unit.test_plugins.test_pyzor as test_pyzor
    import tests.unit.test_plugins.test_whitelist_subject as test_whitelist_subject

    test_suite = unittest.TestSuite()
    test_suite.addTest(test_base.suite())
    test_suite.addTest(test_pyzor.suite())
    test_suite.addTest(test_whitelist_subject.suite())
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
