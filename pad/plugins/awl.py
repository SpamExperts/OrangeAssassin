"""

CREATE TABLE `awl` (
  `username` varchar(255) NOT NULL DEFAULT '',
  `email` varchar(200) NOT NULL DEFAULT '',
  `ip` varchar(40) NOT NULL DEFAULT '',
  `count` int(11) NOT NULL DEFAULT '0',
  `totscore` float NOT NULL DEFAULT '0',
  `signedby` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`username`,`email`,`signedby`,`ip`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COMMENT='Used by SpamAssassin for the
 auto-whitelist functionality'


"""
from __future__ import absolute_import

from builtins import str

import re
import email
import getpass
import ipaddress

from collections import defaultdict

try:
    from sqlalchemy import Column
    from sqlalchemy.types import Float
    from sqlalchemy.types import String
    from sqlalchemy.types import Integer
    from sqlalchemy.sql.schema import PrimaryKeyConstraint
    from sqlalchemy.ext.declarative.api import declarative_base
    has_sqlalchemy = True
except:
    has_sqlalchemy = False
    import pymysql
    UNIX_SOCKET = "/var/run/mysqld/mysqld.sock"

import pad.plugins.base

from pad.regex import Regex

Base = declarative_base()

IPV4SUFFIXRE = Regex("(\.0){1,3}$")

AWL_TABLE = (
    "CREATE TABLE `awl` IF NOT EXISTS `%s` (",
    "  `username` varchar(255) NOT NULL, DEFAULT '',",
    "  `email` varchar(255) NOT NULL DEFAULT '',",
    "  `ip` varchar(40) NOT NULL DEFAULT '',",
    "  `count` int(11) NOT NULL DEFAULT '0',",
    "  `totscore` float NOT NULL DEFAULT '0',",
    "  `signedby` varchar(255) NOT NULL DEFAULT '',",
    "  PRIMARY KEY (`username`, `email`, `signedby`, `ip`)",
    ") ENGINE=MyISAM ",
    " DEFAULT CHARSET=latin1",
    "COMMENT='Used by SpamAssassin "
    "for the auto-whitelist functionality'"
)

if has_sqlalchemy:
    class AWL(Base):
        """Schema for the awl table"""

        __tablename__ = 'awl'

        username = Column("username", String(255))
        email = Column("email", String(200))
        ip = Column("ip", String(40))
        count = Column("count", Integer)
        totscore = Column("totscore", Float)
        signedby = Column("signedby", String(255))

        __table_args__ = (
            PrimaryKeyConstraint("username", "email", "signedby", "ip"),)


class AutoWhiteListPlugin(pad.plugins.base.BasePlugin):
    """Reimplementation of the awl spamassassin plugin"""

    dsn_name = "user_awl"
    has_mysql = False
    engine = None

    eval_rules = ("check_from_in_auto_whitelist",)

    options = {
        "auto_whitelist_factor": ("float", 0.5),
        "auto_whitelist_ipv4_mask_len": ("int", 16),
        "auto_whitelist_ipv6_mask_len": ("int", 48),
    }

    def _get_origin_ip(self, msg):
        relays = []
        relays.extend(msg.trusted_relays)
        relays.extend(msg.untrusted_relays)
        relays.reverse()
        for relay in relays:
            if "ip" in relay:
                ip = ipaddress.ip_address(str(relay['ip'])) 
                if not ip.is_private:
                    return ip
        return None

    def _get_signed_by(self, msg):
        dkim = msg.msg.get('DKIM-Signature', "")
        for param in dkim.split(";"):
            if param.strip().startswith("d="):
                return param.split("=", 1)[1].strip(" ;\r\n")
        return ""

    def _get_from(self, msg):
        try:
            return msg.get_addr_header("From")[0]
        except IndexError:
            return ""

    def parsed_metadata(self, msg):
        from_addr = self._get_from(msg)
        self.set_local(msg, "from", from_addr)

        signedby = self._get_signed_by(msg)
        self.set_local(msg, "signedby", signedby)

        origin_ip = self._get_origin_ip(msg)
        self.set_local(msg, "originip", origin_ip)

    def ip_to_awl_key(self, ip):
        if ip.version == 4:
            mask = self["auto_whitelist_ipv4_mask_len"]
        else:
            mask = self["auto_whitelist_ipv6_mask_len"]

        interface = ipaddress.ip_interface("%s/%s" % (ip, mask))
        network = interface.network.network_address
        return IPV4SUFFIXRE.sub("", str(network))

    def get_entry(self, address, ip, signed_by):
        self.engine = self.get_engine()
        if isinstance(self.engine, defaultdict) and not has_sqlalchemy:
            return self.get_mysql_entry(address, ip, signed_by)
        else:
            return self.get_sqlalch_entry(address, ip, signed_by)


    def get_mysql_entry(self, address, ip, signed_by):
        conn = pymysql.connect(host=self.engine["hostname"], port=3306, user=self.engine["user"],
                               passwd=self.engine["password"], db=self.engine["db_name"],
                               unix_socket=UNIX_SOCKET)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM awl WHERE username=%s AND email=%s AND "
                       "signedby=%s AND ip=%s",
                       (self.ctxt.username, address, signed_by, ip))
        try:
            result = cursor.fetchall()
            if result:
                result = result[0]
        except pymysql.DatabaseError:
            result = cursor.execute(
                "SELECT * FROM awl WHERE username=%s AND email=%s AND "
                "signedby=%s AND ip=%s",
                (self.ctxt.username, address, signed_by, "none"))

            if result:
                result = cursor.execute(
                    "UPDATE awl SET ip=%s", (ip))
                conn.commit()
        if not result:
            result = cursor.execute(
                "INSERT INTO awl VALUES (%s, %s, %s, %s, %s, %s) ",
                (self.ctxt.username, address, ip, 0, 0, signed_by))
            conn.commit()

        cursor.close()
        conn.close()
        return result

    def get_sqlalch_entry(self, address, ip, signed_by):
        session = self.get_session()
        result = session.query(AWL).filter(
                AWL.username == self.ctxt.username,
                AWL.email == address,
                AWL.signedby == signed_by,
                AWL.ip == ip).first()

        if not result:
            result = session.query(AWL).filter(
                    AWL.username == self.ctxt.username,
                    AWL.email == address,
                    AWL.signedby == signed_by,
                    AWL.ip == "none").first()
            if result:
                result.ip = ip

        session.close()

        if not result:
            result = AWL()
            result.count = 0
            result.totscore = 0
            result.username = self.ctxt.username
            result.email = address
            result.signedby = signed_by
            result.ip = ip
        return result

    def plugin_tags_sqlalch(self, msg, origin_ip, addr, signed_by, score, factor, entry):
        try:
            mean = entry.totscore / entry.count

            log_msg = ("auto-whitelist: AWL active, pre-score: %s, "
                       "mean: %s, IP: %s, address: %s %s")
            self.ctxt.log.debug(log_msg,
                                msg.score,
                                "%.3f" % mean if mean else "undef",
                                origin_ip if origin_ip else "undef",
                                addr,
                                "signed by %s" % signed_by if signed_by
                                else "(not signed)")
        except ZeroDivisionError:
            mean = None


        if mean:
            delta = mean - score
            delta *= factor
            msg.plugin_tags["AWL"] = "%2.1f" % delta
            msg.plugin_tags["AWLMEAN"] = "%2.1f" % mean
            msg.plugin_tags["AWLCOUNT"] = "%2.1f" % entry.count
            msg.plugin_tags["AWLPRESCORE"] = "%2.1f" % msg.score

            msg.score += delta

        entry.count += 1
        entry.totscore += score

        session = self.get_session()
        session.merge(entry)
        session.commit()
        session.close()

    def plugin_tags_mysql(self, msg, origin_ip, addr, signed_by, score, factor):
        try:
            conn = pymysql.connect(host=self.engine["hostname"], port=3306,
                                   user=self.engine["user"],
                                   passwd=self.engine["password"],
                                   db=self.engine["db_name"],
                                   unix_socket=UNIX_SOCKET)

            cursor = conn.cursor()
            cursor.execute("SELECT totscore, count FROM awl")
            entry_totscore, entry_count = cursor.fetchall()[0]

        except pymysql.Error:
            self.ctxt.log.error("DB connection failed")
            return

        try:
            mean = entry_totscore / entry_count
            log_msg = ("auto-whitelist: AWL active, pre-score: %s, "
                       "mean: %s, IP: %s, address: %s %s")

            self.ctxt.log.debug(log_msg,
                            msg.score,
                            "%.3f" % mean if mean else "undef",
                            origin_ip if origin_ip else "undef",
                            addr,
                            "signed by %s" % signed_by if signed_by
                            else "(not signed)")
        except ZeroDivisionError:
            mean = None


        if mean:
            delta = mean - score
            delta *= factor
            msg.plugin_tags["AWL"] = "%2.1f" % delta
            msg.plugin_tags["AWLMEAN"] = "%2.1f" % mean
            msg.plugin_tags["AWLCOUNT"] = "%2.1f" % entry_count
            msg.plugin_tags["AWLPRESCORE"] = "%2.1f" % msg.score

            msg.score += delta

        entry_count += 1
        entry_totscore += score

        try:
            result = cursor.execute(
                "UPDATE awl SET count=%s, totscore=%s",
                (entry_count, entry_totscore))
        except pymysql.Error:
            return False

        conn.commit()
        cursor.close()
        conn.close()

    def check_from_in_auto_whitelist(self, msg, target=None):
        score = msg.score
        factor = self["auto_whitelist_factor"]
        origin_ip = self.get_local(msg, "originip")
        if origin_ip:
            awl_key_ip = self.ip_to_awl_key(origin_ip)
        else:
            awl_key_ip = "none"
        addr = self.get_local(msg, "from")
        signed_by = self.get_local(msg, "signedby")

        entry = self.get_entry(addr, awl_key_ip, signed_by)

        if self.has_mysql:
            self.plugin_tags_mysql(msg, origin_ip, addr, signed_by, score,
                                   factor)
        else:
            self.plugin_tags_sqlalch(msg, origin_ip, addr, signed_by, score,
                             factor, entry)

        self.ctxt.log.debug("auto-whitelist: post auto-whitelist score %.3f",
                            msg.score)

        return False
