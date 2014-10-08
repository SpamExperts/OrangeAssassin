#! /usr/bin/env python

from __future__ import absolute_import

import sa
import distutils.core

distutils.core.setup(name='??????',
                     version=sa.__version__,
                     scripts=['scripts/match.py'],
                     packages=['sa', 'sa.rules'],
                     test_suite="tests.suite"
)
