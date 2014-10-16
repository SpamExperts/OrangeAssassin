"""Package for unit tests."""

from __future__ import absolute_import

import unittest


def suite():
    """Gather all the tests from this package in a test suite."""

    import tests.unit.test_rules.test_uri as test_uri
    import tests.unit.test_rules.test_base as test_base
    import tests.unit.test_rules.test_body as test_body
    import tests.unit.test_rules.test_meta as test_eval
    import tests.unit.test_rules.test_full as test_full
    import tests.unit.test_rules.test_meta as test_meta
    import tests.unit.test_rules.test_header as test_header

    import tests.unit.test_rules.test_parser as test_parser
    import tests.unit.test_rules.test_ruleset as test_ruleset

    test_suite = unittest.TestSuite()
    test_suite.addTests(test_uri.suite())
    test_suite.addTests(test_base.suite())
    test_suite.addTests(test_body.suite())
    test_suite.addTests(test_eval.suite())
    test_suite.addTests(test_full.suite())
    test_suite.addTests(test_meta.suite())
    test_suite.addTests(test_header.suite())

    test_suite.addTests(test_parser.suite())
    test_suite.addTests(test_ruleset.suite())
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
