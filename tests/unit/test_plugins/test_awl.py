import unittest
import ipaddress

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    has_sqlalchemy = True
except:
    import pymysql

    has_sqlalchemy = False

import oa.plugins
from oa.plugins import awl

from collections import defaultdict

class TestAWLBase(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.setdefault(
                k, v),
            "username": "test",
        })
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data."
            "side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
        })

        self.plugin = oa.plugins.awl.AutoWhiteListPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

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

    def test_get_origin_ip(self):
        self.mock_msg.trusted_relays = [{
            "rdns": "=mx6-05.smtp.antispamcloud.com", "ip": "9.9.9.9",
            "by": "mx.google.com", "helo": "mx6-05.smtp.antispamcloud.com",
            "ident": "", "id": "", "envfrom": "",
            "auth": ""}]
        self.mock_msg.untrusted_relays = [{
            "rdns": "=mx6-05.smtp.antispamcloud.com", "ip": "8.8.8.8",
            "by": "mx.google.com", "helo": "mx6-05.smtp.antispamcloud.com",
            "ident": "", "id": "", "envfrom": "",
            "auth": ""}]
        result = self.plugin._get_origin_ip(self.mock_msg)
        expected = ipaddress.ip_address(u"8.8.8.8")
        self.assertEqual(result, expected)

    def test_get_origin_ip_no_relays(self):
        self.mock_msg.trusted_relays = []
        self.mock_msg.untrusted_relays = []
        result = self.plugin._get_origin_ip(self.mock_msg)
        expected = None
        self.assertEqual(result, expected)

    def test_get_origin_ip_private_ip(self):
        self.mock_msg.trusted_relays = [{
            "rdns": "=mx6-05.smtp.antispamcloud.com", "ip": "9.9.9.9",
            "by": "mx.google.com", "helo": "mx6-05.smtp.antispamcloud.com",
            "ident": "", "id": "", "envfrom": "",
            "auth": ""}]
        self.mock_msg.untrusted_relays = [{
            "rdns": "=mx6-05.smtp.antispamcloud.com", "ip": "10.0.0.1",
            "by": "mx.google.com", "helo": "mx6-05.smtp.antispamcloud.com",
            "ident": "", "id": "", "envfrom": "",
            "auth": ""}]
        result = self.plugin._get_origin_ip(self.mock_msg)
        expected = ipaddress.ip_address(u"9.9.9.9")
        self.assertEqual(result, expected)

    def test_get_signed_by(self):
        self.mock_msg.msg.get.return_value = "v=1; a=rsa-sha256; " \
                                             "c=relaxed/relaxed; " \
                                             "d=1e100.net; s=20130820;"
        result = self.plugin._get_signed_by(self.mock_msg)
        expected = "1e100.net"
        self.assertEqual(result, expected)

    def test_get_signed_by_no_signature(self):
        self.mock_msg.msg.get.return_value = "v=1; a=rsa-sha256; " \
                                             "c=relaxed/relaxed; " \
                                             "s=20130820;"
        result = self.plugin._get_signed_by(self.mock_msg)
        expected = ""
        self.assertEqual(result, expected)

    def test_get_from(self):
        self.mock_msg.get_addr_header.return_value = ["test@spamexperts.com"]
        result = self.plugin._get_from(self.mock_msg)
        self.mock_msg.get_addr_header.assert_called_with("From")
        self.assertEqual(result, "test@spamexperts.com")

    def test_get_from_IndexError(self):
        self.mock_msg.get_addr_header.side_effect = IndexError
        result = self.plugin._get_from(self.mock_msg)
        self.assertEqual(result, "")

    def test_parsed_metadata(self):
        get_from = patch(
            "oa.plugins.awl.AutoWhiteListPlugin._get_from").start()
        get_signed_by = patch(
            "oa.plugins.awl.AutoWhiteListPlugin._get_signed_by").start()
        get_origin_ip = patch(
            "oa.plugins.awl.AutoWhiteListPlugin._get_origin_ip").start()
        self.plugin.parsed_metadata(self.mock_msg)
        get_from.assert_called_with(self.mock_msg)
        get_signed_by.assert_called_with(self.mock_msg)
        get_origin_ip.assert_called_with(self.mock_msg)

if has_sqlalchemy:
    class TestAWLBaseSQLAlchemy(unittest.TestCase):

        def setUp(self):
            unittest.TestCase.setUp(self)
            self.options = {}
            self.global_data = {}
            self.msg_data = {}

            self.mock_ctxt = MagicMock(**{
                "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
                "set_plugin_data.side_effect": lambda p, k,
                                                      v: self.global_data.setdefault(
                    k, v),
                "username": "test",
            })
            self.mock_msg = MagicMock(**{
                "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
                "set_plugin_data."
                "side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
            })

            # self.mock_msg.msg = None
            get_session = patch(
                "oa.plugins.awl.AutoWhiteListPlugin.get_session").start()
            engine = create_engine("sqlite://")
            awl.Base.metadata.create_all(engine)
            self.session = sessionmaker(bind=engine)()
            get_session.return_value = self.session
            self.plugin = oa.plugins.awl.AutoWhiteListPlugin(self.mock_ctxt)

        def tearDown(self):
            unittest.TestCase.tearDown(self)
            patch.stopall()

        def test_get_entry(self):
            get_engine = patch(
                "oa.plugins.awl.AutoWhiteListPlugin.get_engine").start()
            hasSQLAlchemy = patch(
                "oa.plugins.awl.has_sqlalchemy", True, create=True).start()
            getEntrySQLAlchemy = patch(
                "oa.plugins.awl.AutoWhiteListPlugin.get_sqlalch_entry").start()
            address = ""
            ip = ""
            signed_by = ""
            get_engine.return_value = defaultdict()
            result = self.plugin.get_entry(address, ip, signed_by)
            getEntrySQLAlchemy.assert_called_with(address, ip, signed_by)

        def test_check_from_in_auto_whitelist_with_sqlalchemy(self):
            self.mock_msg.score = 0
            self.global_data["auto_whitelist_factor"] = 0
            getLocal = patch(
                "oa.plugins.awl.AutoWhiteListPlugin.get_local").start()
            getLocal.return_value = ""
            getEntry = patch(
                "oa.plugins.awl.AutoWhiteListPlugin.get_entry").start()
            getEntry.return_value = None
            hasMySQL = patch(
                "oa.plugins.awl.AutoWhiteListPlugin.has_mysql", False, create=True)
            hasMySQL.start()
            pluginTags = patch(
                "oa.plugins.awl.AutoWhiteListPlugin.plugin_tags_sqlalch").start()
            self.plugin.check_from_in_auto_whitelist(self.mock_msg)

            pluginTags.assert_called_with(self.mock_msg, "", "", "", 0, 0, None)

        def check_sa_db(self, username, email, ip, signedby, totscore, count):
            result = self.session.query(awl.AWL).filter(
                username == username,
                signedby == signedby,
                email == email,
                ip == ip).first()
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
            self.plugin.set_local(self.mock_msg, "from", "test@example.com")
            self.plugin.set_local(self.mock_msg, "signedby", "")

            self.plugin.set_local(self.mock_msg, "originip",
                                  ipaddress.IPv4Address(u"8.8.8.8"))

            hasMySQL = patch(
                "oa.plugins.awl.AutoWhiteListPlugin.has_mysql", False, create=True)
            hasMySQL.start()

            get_eng = patch(
                "oa.plugins.awl.AutoWhiteListPlugin.get_engine").start()
            get_eng.return_value = create_engine("sqlite://")

            hasSQLAlchemy = patch(
                "oa.plugins.awl.has_sqlalchemy", True, create=True).start()

            self.plugin.check_from_in_auto_whitelist(self.mock_msg,
                                                     target="header")

            self.assertEqual(self.mock_msg.score, 5)
            self.check_sa_db(**data)

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
            self.plugin.set_local(self.mock_msg, "from",
                                           "test@example.com")
            self.plugin.set_local(self.mock_msg, "signedby", "")
            self.plugin.set_local(self.mock_msg, "originip", ipaddress.IPv4Address(
                                               u"8.8.8.8"))
            hasMySQL = patch(
                "oa.plugins.awl.AutoWhiteListPlugin.has_mysql", False, create=True)
            hasMySQL.start()

            get_eng = patch(
                "oa.plugins.awl.AutoWhiteListPlugin.get_engine").start()
            get_eng.return_value = create_engine("sqlite://")

            self.plugin.check_from_in_auto_whitelist(self.mock_msg,
                                                     target = "header")
            data.update({"totscore": 15, "count": 2})
            self.check_sa_db(**data)
            self.assertEqual(self.mock_msg.score, 7.5)


class TestAWLBasePyMySQL(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k,
                                                  v: self.global_data.setdefault(
                k, v),
            "username": "test",
        })
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data."
            "side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
        })
        self.mock_msg.msg = None
        get_session = patch("oa.plugins.awl.AutoWhiteListPlugin.get_session")
        get_session.start()
        self.plugin = oa.plugins.awl.AutoWhiteListPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_get_entry(self):
        get_engine = patch(
            "oa.plugins.awl.AutoWhiteListPlugin.get_engine").start()
        hasSQLAlchemy = patch(
            "oa.plugins.awl.has_sqlalchemy", False, create=True).start()
        getEntryMySQL = patch(
            "oa.plugins.awl.AutoWhiteListPlugin.get_mysql_entry").start()
        address = ""
        ip = ""
        signed_by = ""
        get_engine.return_value = defaultdict()
        result = self.plugin.get_entry(address, ip, signed_by)
        getEntryMySQL.assert_called_with(address, ip, signed_by)

    def test_check_from_in_auto_whitelist_with_mysql(self):
        self.mock_msg.score = 0
        self.global_data["auto_whitelist_factor"] = 0
        getLocal = patch(
            "oa.plugins.awl.AutoWhiteListPlugin.get_local").start()
        getLocal.return_value = ""
        getEntry = patch(
            "oa.plugins.awl.AutoWhiteListPlugin.get_entry").start()
        getEntry.return_value = None
        hasMySQL = patch(
            "oa.plugins.awl.AutoWhiteListPlugin.has_mysql", True,
            create=True)
        hasMySQL.start()
        plugin_tags = patch(
            "oa.plugins.awl.AutoWhiteListPlugin.plugin_tags_mysql").start()
        self.plugin.check_from_in_auto_whitelist(self.mock_msg)
        getLocal.assert_has_calls([call(self.mock_msg, "originip"),
                                   call(self.mock_msg, "from"),
                                   call(self.mock_msg, "signedby")])
        getEntry.assert_called_with("", "none", "")
        plugin_tags.assert_called_with(self.mock_msg, "", "", "", 0, 0)

    def test_check_from_in_auto_whitelist_with_origin_ip(self):
        self.mock_msg.score = 0
        self.global_data["auto_whitelist_factor"] = 0
        getLocal = patch(
            "oa.plugins.awl.AutoWhiteListPlugin.get_local").start()
        getLocal.return_value = "example"
        awl_key_ip = patch(
            "oa.plugins.awl.AutoWhiteListPlugin.ip_to_awl_key").start()
        awl_key_ip.return_value = None
        getEntry = patch(
            "oa.plugins.awl.AutoWhiteListPlugin.get_entry").start()
        getEntry.return_value = None
        hasMySQL = patch(
            "oa.plugins.awl.AutoWhiteListPlugin.has_mysql", True,
            create=True)
        hasMySQL.start()
        plugin_tags = patch(
            "oa.plugins.awl.AutoWhiteListPlugin.plugin_tags_mysql").start()
        self.plugin.check_from_in_auto_whitelist(self.mock_msg)
        getLocal.assert_has_calls([call(self.mock_msg, "originip"),
                                   call(self.mock_msg, "from"),
                                   call(self.mock_msg, "signedby")])
        getEntry.assert_called_with("example", None, "example")
        plugin_tags.assert_called_with(self.mock_msg, "example", "example",
                                       "example", 0, 0)
