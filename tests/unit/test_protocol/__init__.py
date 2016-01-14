"""Package for unit tests."""

from __future__ import absolute_import

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""

    import tests.unit.test_protocol.test_tell as test_tell
    import tests.unit.test_protocol.test_base as test_base
    import tests.unit.test_protocol.test_noop as test_noop
    import tests.unit.test_protocol.test_check as test_check
    import tests.unit.test_protocol.test_process as test_process

    test_suite = unittest.TestSuite()
    test_suite.addTest(test_tell.suite())
    test_suite.addTest(test_base.suite())
    test_suite.addTest(test_noop.suite())
    test_suite.addTest(test_check.suite())
    test_suite.addTest(test_process.suite())
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
