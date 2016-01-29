"""

CREATE TABLE `awl` (
  `username` varchar(255) NOT NULL DEFAULT '',
  `email` varchar(200) NOT NULL DEFAULT '',
  `ip` varchar(40) NOT NULL DEFAULT '',
  `count` int(11) NOT NULL DEFAULT '0',
  `totscore` float NOT NULL DEFAULT '0',
  `signedby` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`username`,`email`,`signedby`,`ip`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COMMENT='Used by SpamAssassin for the auto-whitelist functionality'


"""
from __future__ import absolute_import

from builtins import str

import re
import email
import getpass
import ipaddress

from sqlalchemy import Column
from sqlalchemy.types import Float
from sqlalchemy.types import String
from sqlalchemy.types import Integer
from sqlalchemy.sql.schema import PrimaryKeyConstraint
from sqlalchemy.ext.declarative.api import declarative_base

import pad.plugins.base


Base = declarative_base()

IPV4SUFFIXRE = re.compile("(\.0){1,3}$")

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

    eval_rules = ("check_from_in_auto_whitelist",)

    options = {
        "auto_whitelist_factor": ("float", 0.5),
        "auto_whitelist_ipv4_mask_len": ("int", 16),
        "auto_whitelist_ipv6_mask_len": ("int", 48),
    }


    def _get_origin_ip(self, msg):
        for ip in msg.get_header_ips():
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
            mask = self.get_global("auto_whitelist_ipv4_mask_len")
        else:
            mask = self.get_global("auto_whitelist_ipv6_mask_len")

        interface = ipaddress.ip_interface("%s/%s" % (ip, mask))
        network = interface.network.network_address
        return IPV4SUFFIXRE.sub("", str(network))

    def get_entry(self, address, ip, signed_by):
        session = self.get_session()
        result = session.query(AWL).filter(
            AWL.username==getpass.getuser(),
            AWL.email==address,
            AWL.signedby==signed_by,
            AWL.ip==ip).first()

        if not result:
            result = session.query(AWL).filter(
                AWL.username==getpass.getuser(),
                AWL.email==address,
                AWL.signedby==signed_by,
                AWL.ip=="none").first()
            if result:
                result.ip = ip

        session.close()

        if not result:
            result = AWL()
            result.count = 0
            result.totscore = 0
            result.username = getpass.getuser()
            result.email = address
            result.signedby = signed_by
            result.ip = ip
        return result


    def check_from_in_auto_whitelist(self, msg, target=None):
        score =  msg.score
        factor = self.get_global("auto_whitelist_factor")
        origin_ip = self.get_local(msg, "originip")
        if origin_ip:
            awl_key_ip = self.ip_to_awl_key(origin_ip)
        else:
            awl_key_ip = "none"
        addr = self.get_local(msg, "from")
        signed_by = self.get_local(msg, "signedby")

        entry = self.get_entry(addr, awl_key_ip, signed_by)

        try:
            mean = entry.totscore/entry.count
        except ZeroDivisionError:
            mean = None


        log_msg = ("auto-whitelist: AWL active, pre-score: %s, "
                   "mean: %s, IP: %s, address: %s %s")

        self.ctxt.log.debug(log_msg,
                            msg.score,
                            "%.3f" % mean if mean else "undef",
                            origin_ip if origin_ip else "undef",
                            addr,
                            "signed by %s" % signed_by if signed_by
                            else "(not signed)")

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

        self.ctxt.log.debug("auto-whitelist: post auto-whitelist score %.3f", msg.score)

        return False




