#! /usr/bin/env python

from __future__ import absolute_import

import pad
import distutils.core

distutils.core.setup(name='??????',
                     version=pad.__version__,
                     scripts=['scripts/match.py'],
                     packages=['pad', 'pad.rules'],
                     test_suite="tests.suite"
                     )
