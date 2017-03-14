#! /usr/bin/env python

from __future__ import absolute_import

import sys
import platform

import oa
import distutils.core

with open("requirements/base.txt") as base:
    requirements = base.readlines()
if "pypy" in platform.python_implementation().lower():
    if sys.version_info.major == 3:
        with open("requirements/pypy3-build-requirements.txt") as py3build:
            requirements.extend(py3build.readlines())
        with open("requirements/pypy3.txt") as py3:
            requirements.extend(py3.readlines())
    elif sys.version_info.major == 2:
        with open("requirements/pypy2.txt") as py2:
            requirements.extend(py2.readlines())
else:
    if sys.version_info.major == 3:
        with open("requirements/python3.txt") as py3:
            requirements.extend(py3.readlines())
        if sys.version_info.minor == 2:
            with open("requirements/pypy3-build-requirements.txt") as py3build:
                requirements.extend(py3build.readlines())
            with open("requirements/pypy3.txt") as py3:
                requirements.extend(py3.readlines())
    elif sys.version_info.major == 2:
        with open("requirements/python2.txt") as py2:
            requirements.extend(py2.readlines())

with open("requirements/tests.txt") as test:
    test_requirements = test.readlines()

distutils.core.setup(
    name='OrangeAssassin',
    version=oa.__version__,
    scripts=[
        'scripts/match.py',
        'scripts/oad.py',
        'scripts/compile.py'
    ],
    packages=[
        'oa',
        'oa.rules',
        'oa.plugins',
        'oa.protocol',
    ],
    install_requires=requirements,
    tests_require=test_requirements,
)
