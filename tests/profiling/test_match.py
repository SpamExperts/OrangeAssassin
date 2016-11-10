from __future__ import print_function

from __future__ import absolute_import, print_function
import os
import unittest

import tests.util

GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"


class MemoryTest(tests.util.TestBase):
    ptype = "memory"
    limits = {
        "test_simple": {
            "ilimit": None,
            "elimit": None,
            "plimit": None,
            "inclimit": None,
        },
        "test_simple_gtube": {
            "ilimit": None,
            "elimit": None,
            "plimit": None,
            "inclimit": None,
        }
    }

    def test_simple(self):
        """Profile simple ham check."""
        limits = self.limits["test_simple"]
        name = "%s: Simple ham message check" % self.ptype.title()
        sname = "simple_%s" % self.ptype
        msg = "Subject: test\n\nTest abcd test."
        self.setup_conf(config="body TEST_RULE /abcd/",
                        pre_config="report _SCORE_")
        self.profile_pad(name, sname, msg, ptype=self.ptype, **limits)

    def test_simple_gtube(self):
        """Profile GTUBE spam check."""
        limits = self.limits["test_simple_gtube"]
        name = "%s: Simple GTUBE message check" % self.ptype.title()
        sname = "gtube_%s" % self.ptype
        msg = "Subject: test\n\n" + GTUBE
        self.setup_conf(pre_config="report _SCORE_")
        self.profile_pad(name, sname, msg, ptype=self.ptype, **limits)


class MemoryUSSTest(MemoryTest):
    ptype = "memory-uss"


class MemoryPSSTest(MemoryTest):
    ptype = "memory-pss"


class CPUTest(MemoryTest):
    ptype = "cpu"


class IOWriteTest(MemoryTest):
    ptype = "io-write"


class IOReadTest(MemoryTest):
    ptype = "io-read"


class IOCountTest(MemoryTest):
    ptype = "io-count"
