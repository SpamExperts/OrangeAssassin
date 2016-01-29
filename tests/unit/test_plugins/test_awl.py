import unittest
import ipaddress

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import pad.plugins
from pad.plugins import awl


class TestAWLBase(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}
        patch("pad.plugins.awl.getpass.getuser", return_value="test").start()

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
        )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data."
            "side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
        })
        self.mock_msg.msg = None
        get_session = patch("pad.plugins.awl.AutoWhiteListPlugin.get_session").start()
        engine = create_engine("sqlite://")
        awl.Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine)()
        get_session.return_value = self.session
        self.plugin = pad.plugins.awl.AutoWhiteListPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_parsed_metadata(self):

        pass

    def test_ip_to_awl_key_ipv4(self):
        ip = ipaddress.ip_address(u"192.168.1.1")
        result = self.plugin.ip_to_awl_key(ip)
        expected = u"192.168"
        self.assertEqual(result, expected)

    def test_ip_to_awl_key_ipv6(self):
        ip = ipaddress.ip_address(u"2001:0db8:85a3::8a2e:0370:7334")
        result = self.plugin.ip_to_awl_key(ip)
        expected = u"2001:db8:85a3::"
        self.assertEqual(result, expected)

    def check_db(self, username, email, ip, signedby, totscore, count):
        result = self.session.query(awl.AWL).filter(
            username==username,
            signedby==signedby,
            email==email,
            ip==ip).first()
        self.assertEqual(totscore, result.totscore)
        self.assertEqual(count, result.count)

    def test_eval_rule_first_seen_address(self):
        data = {"email": "test@example.com",
                "username": "test",
                "signedby": "",
                "totscore": 5,
                "ip": "8.8",
                "count": 1}

        self.mock_msg.score = 5
        self.plugin.set_local(self.mock_msg, "from", "test@example.com")
        self.plugin.set_local(self.mock_msg, "signedby", "")

        self.plugin.set_local(self.mock_msg, "originip",
                              ipaddress.IPv4Address(u"8.8.8.8"))

        self.plugin.check_from_in_auto_whitelist(self.mock_msg,
                                                 target="header")

        self.assertEqual(self.mock_msg.score, 5)
        self.check_db(**data)

    def test_eval_rule_existing_address(self):
        data = {"email": "test@example.com",
                "username": "test",
                "signedby": "",
                "totscore": 5,
                "ip": "8.8",
                "count": 1}
        self.session.add(awl.AWL(**data))
        self.session.commit()
        self.mock_msg.plugin_tags = dict()

        self.mock_msg.score = 10
        self.plugin.set_local(self.mock_msg, "from", "test@example.com")
        self.plugin.set_local(self.mock_msg, "signedby", "")
        self.plugin.set_local(self.mock_msg, "originip",
                              ipaddress.IPv4Address(u"8.8.8.8"))
        self.plugin.check_from_in_auto_whitelist(self.mock_msg,
                                                 target="header")
        data.update({"totscore":15, "count":2})
        self.check_db(**data)
        self.assertEqual(self.mock_msg.score, 7.5)
