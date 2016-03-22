"""Tests for pad.dns_interface """

import logging
import unittest
import ipaddress

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from pad.dns_interface import DNSInterface


class TestDNSInterface(unittest.TestCase):
    """Test dns interface class"""

    def setUp(self):
        super(TestDNSInterface, self).setUp()
        logging.getLogger("pad-logger").handlers = [logging.NullHandler()]
        self.resolver = patch(
            "pad.dns_interface.dns.resolver.Resolver").start().return_value
        self.dns = DNSInterface()

    def tearDown(self):
        patch.stopall()
        super(TestDNSInterface, self).tearDown()

    def test_qname_is_restricted_empty(self):
        """Test a domain that when no restrictions apply"""
        self.assertFalse(
            self.dns._qname_is_restricted("1.2.3.4.5.example.com"))

    def test_qname_is_restricted_true(self):
        """Test an allowed domain."""
        self.dns.restrictions = {"1.2.3.4.5.example.com": True}

        self.assertTrue(
            self.dns._qname_is_restricted("1.2.3.4.5.example.com"))

    def test_qname_is_restricted_false(self):
        """Test a restricted domain"""
        self.dns.restrictions = {"1.2.3.4.5.example.com": False}
        self.assertFalse(
            self.dns._qname_is_restricted("1.2.3.4.5.example.com"))

    def test_qname_parent_is_restricted_true(self):
        """Test a domain with an allowed parent"""
        self.dns.restrictions = {"4.5.example.com": True}
        self.assertTrue(
            self.dns._qname_is_restricted("1.2.3.4.5.example.com"))

    def test_qname_parent_is_restricted_false(self):
        """Test a domain with a restricted parent"""
        self.dns.restrictions = {"4.5.example.com": False}
        self.assertFalse(
            self.dns._qname_is_restricted("1.2.3.4.5.example.com"))

    def test_qname_is_restricted_false_with_parent_true(self):
        """Test an allowed domain with a restricted parent."""
        self.dns.restrictions = {"2.3.4.5.example.com": True,
                                 "4.5.example.com": False}
        self.assertTrue(
            self.dns._qname_is_restricted("1.2.3.4.5.example.com"))

    def test_qname_is_restricted_true_with_parent_false(self):
        """Test a restricted domain with an allowed parent."""
        self.dns.restrictions = {"2.3.4.5.example.com": False,
                                 "4.5.example.com": True}
        self.assertFalse(
            self.dns._qname_is_restricted("1.2.3.4.5.example.com"))

    def test_query(self):
        self.dns.query("example.com", "A")

    def test_query_restricted(self):
        self.dns.restrictions = {"example.com": True}
        result = self.dns.query("example.com", "A")
        self.assertEqual(result, [])

    def test_query_error(self):
        pass

    def test_reverse_ip(self):
        result = self.dns.reverse_ip(ipaddress.ip_address("127.0.0.1"))
        self.assertEqual("1.0.0.127.in-addr", result)
