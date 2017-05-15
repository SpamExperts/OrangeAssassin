#!/usr/bin/env python
from __future__ import print_function
import subprocess

OrangeAssassin_args = [
    "./scripts/match.py",
    "-d",
    "-S",
    "./tests/test_match_conf/",
    "-C",
    "./tests/test_match_conf/",
    "-D",
    "-R",
    "tests/data/debug.eml"
]

spamassassin_args = [
    "spamassassin",
    "--siteconfigpath=/dev/null",
    "-C",
    "tests/test_match_conf/",
    "-D",
    "-t",
    "tests/data/debug.eml"
]

for args in (OrangeAssassin_args, spamassassin_args):
    print(" ".join(args))
    output = subprocess.check_output(args)
    print(output)
    print ("#" * 80)
