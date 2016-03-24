import re
import logging
import ipaddress

from builtins import str
from builtins import object

_NETWORK_RE = re.compile(r"""
^(?P<exclude>!?)
    \[?
        (?P<ip>
            [0-9.]+|           # IPv4
            [0-9a-f:]*         # IPv6
        )
    \]?

    /?(?P<port>[0-9]{0,5})$
""", re.I | re.S | re.M | re.X)


class NetworkListBase(object):
    always_accepted = ()
    configured = False
    _networks = []

    def __init__(self):
        self._networks.extend(self.always_accepted)

    def add(self, network, excluded):
        self._networks.append((network, excluded))

    def __contains__(self, query):
        for network, excluded in self._networks:
            if query in network:
                return excluded
        else:
            return False


class TrustedNetworks(NetworkListBase):
    _always_accepted = (
        ipaddress.ip_network(str("127.0.0.0/8")),
        ipaddress.ip_network(str("::1")),
    )


class InternalNetworks(NetworkListBase):
    _always_accepted = (
        ipaddress.ip_network(str("127.0.0.0/8")),
        ipaddress.ip_network(str("::1")),
    )


class MSANetworks(NetworkListBase):
    pass


class NetworkList(object):
    internal = InternalNetworks()
    trusted = TrustedNetworks()
    msa = MSANetworks()

    def __init__(self):
        self.log = logging.getLogger("pad-logger")

    @property
    def configured(self):
        return self.internal.configured or self.trusted.configured

    def _format_network_str(self, network, mask):
        padding = ""
        if network.endswith("."):
            padding = ".".join(["0"] * network.count("."))
        if not mask:
            mask = network.count(".") * 8
        return str("%s%s/%s" % (network, padding, mask))

    def extract_network(self, network_str):
        exclude, network, mask = _NETWORK_RE.match(network_str).groups()
        clean_value = self._format_network_str(network, mask)
        try:
            network = ipaddress.ip_network(clean_value)
        except ValueError:
            return exclude, None
        return exclude, network

    def add_trusted_network(self, network_str):
        self.configured = True
        exclude, network = self.extract_network(network_str)
        self.trusted.configured = True
        self.trusted_networks.add(network, exclude)

    def add_internal_network(self, network_str):
        exclude, network = self.extract_network(network_str)
        self.internal.configured = True
        self.trusted_networks.add(network, exclude)
        self.internal_networks.add(network, exclude)

    def add_msa_network(self, network_str):
        exclude, network = self.extract_network(network_str)
        self.internal.configured = True
        self.msa_networks.add(network, exclude)
