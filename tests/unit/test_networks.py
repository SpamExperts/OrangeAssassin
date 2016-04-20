
from builtins import str

import unittest
import ipaddress
import pad.networks



class TrustedNetworkTest(unittest.TestCase):

    def setUp(self):
        self.network = pad.networks.TrustedNetworks()

    def tearDown(self):
        pass

    def test_default_accepted(self):
        ip = ipaddress.ip_address(str("127.0.0.1"))
        self.assertTrue(ip in self.network)

    def test_default_missing(self):
        ip = ipaddress.ip_address(str("192.168.0.1"))
        self.assertFalse(ip in self.network)

    def test_new_accepted(self):
        self.network.add(ipaddress.ip_network(str("192.168.0.0/24")), True)
        ip = ipaddress.ip_address(str("192.168.0.1"))
        self.assertTrue(ip in self.network)

    def test_new_excluded(self):
        self.network.add(ipaddress.ip_network(str("192.168.0.0/24")), False)
        ip = ipaddress.ip_address(str("192.168.0.1"))
        self.assertFalse(ip in self.network)

    def test_new_missing(self):
        self.network.add(ipaddress.ip_network(str("192.168.0.0/24")), False)
        ip = ipaddress.ip_address(str("192.168.1.1"))
        self.assertFalse(ip in self.network)

class InternalNetworkTest(unittest.TestCase):

    def setUp(self):
        self.network = pad.networks.InternalNetworks()

    def tearDown(self):
        pass

    def test_default_accepted(self):
        ip = ipaddress.ip_address(str("127.0.0.1"))
        self.assertTrue(ip in self.network)

    def test_default_missing(self):
        ip = ipaddress.ip_address(str("192.168.0.1"))
        self.assertFalse(ip in self.network)

    def test_new_accepted(self):
        self.network.add(ipaddress.ip_network(str("192.168.0.0/24")), True)
        ip = ipaddress.ip_address(str("192.168.0.1"))
        self.assertTrue(ip in self.network)

    def test_new_excluded(self):
        self.network.add(ipaddress.ip_network(str("192.168.0.0/24")), False)
        ip = ipaddress.ip_address(str("192.168.0.1"))
        self.assertFalse(ip in self.network)

    def test_new_missing(self):
        self.network.add(ipaddress.ip_network(str("192.168.0.0/24")), False)
        ip = ipaddress.ip_address(str("192.168.1.1"))
        self.assertFalse(ip in self.network)


class MSANetworkTest(unittest.TestCase):

    def setUp(self):
        self.network = pad.networks.MSANetworks()

    def tearDown(self):
        pass

    def test_default_missing(self):
        ip = ipaddress.ip_address(str("192.168.0.1"))
        self.assertFalse(ip in self.network)

    def test_new_accepted(self):
        self.network.add(ipaddress.ip_network(str("192.168.0.0/24")), True)
        ip = ipaddress.ip_address(str("192.168.0.1"))
        self.assertTrue(ip in self.network)

    def test_new_excluded(self):
        self.network.add(ipaddress.ip_network(str("192.168.0.0/24")), False)
        ip = ipaddress.ip_address(str("192.168.0.1"))
        self.assertFalse(ip in self.network)

    def test_new_missing(self):
        self.network.add(ipaddress.ip_network(str("192.168.0.0/24")), False)
        ip = ipaddress.ip_address(str("192.168.1.1"))
        self.assertFalse(ip in self.network)


class NetworkListTest(unittest.TestCase):

    def setUp(self):
        super(NetworkListTest, self).setUp()
        self.networks = pad.networks.NetworkList()

    def tearDown(self):
        super(NetworkListTest, self).tearDown()

    def test_format_network_string_no_mask(self):
        network = self.networks._format_network_str("127.", "32")
        self.assertEqual(network, "127.0.0.0/32")

    def test_format_network_string_no_mask(self):
        network = self.networks._format_network_str("127.0.0.", "32")
        self.assertEqual(network, "127.0.0.0/32")


    def test_format_network_string_no_mask(self):
        network = self.networks._format_network_str("127.", "")
        self.assertEqual(network, "127.0.0.0/8")

    def test_extract_network(self):
        excluded, network = self.networks._extract_network("!127.")
        self.assertEqual(excluded, "!")
        self.assertEqual(network, ipaddress.ip_network(str("127.0.0.0/8")))

    def test_add_trusted_network(self):
        self.networks.add_trusted_network("192.168./24")
        network = ipaddress.ip_network(str("192.168.0.0/24"))
        self.assertTrue((network, True) in self.networks.trusted._networks)

    def test_exclude_trusted_network(self):
        self.networks.add_trusted_network("!192.168./24")
        network = ipaddress.ip_network(str("192.168.0.0/24"))
        self.assertTrue((network, False) in self.networks.trusted._networks)

    def test_add_internal_network(self):
        self.networks.add_internal_network("192.168./24")
        network = ipaddress.ip_network(str("192.168.0.0/24"))
        self.assertTrue((network, True) in self.networks.internal._networks)

    def test_exclude_internal_network(self):
        self.networks.add_internal_network("!192.168./24")
        network = ipaddress.ip_network(str("192.168.0.0/24"))
        self.assertTrue((network, False) in self.networks.internal._networks)

    def test_add_msa_network(self):
        self.networks.add_msa_network("192.168./24")
        network = ipaddress.ip_network(str("192.168.0.0/24"))
        self.assertTrue((network, True) in self.networks.msa._networks)

    def test_exclude_msa_network(self):
        self.networks.add_msa_network("!192.168./24")
        network = ipaddress.ip_network(str("192.168.0.0/24"))
        self.assertTrue((network, False) in self.networks.msa._networks)

