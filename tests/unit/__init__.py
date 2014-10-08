"""Package for unit tests."""

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""

    test_suite = unittest.TestSuite()
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
