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

import re
import email
import ipaddress
from io import BytesIO
from sqlalchemy.schema import MetaData
from sqlalchemy.ext.declarative.api import declarative_base
from sqlalchemy import Column
from sqlalchemy.types import Text
from sqlalchemy.types import String
from sqlalchemy.types import Integer
from sqlalchemy.types import Unicode
from sqlalchemy.types import Float
from sqlalchemy.sql.schema import PrimaryKeyConstraint


from hashlib import md5
from collections import defaultdict


import pad.regex
import pad.plugins.base

import pprint

pp = pprint.PrettyPrinter()

Base = declarative_base()

class AWL(Base):

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

    dsn_name = "user_awl"

    eval_rules = ("check_from_in_auto_whitelist",)

    options = {
        "auto_whitelist_factor": ("float", 0.5),
        "auto_whitelist_ipv4_mask_len": ("int", 16),
        "auto_whitelist_ipv6_mask_len": ("int", 48),
    }


    def parsed_metadata(self, msg):
        from_addr = msg.msg['From']
        self.set_local(msg, "from", email.utils.parseaddr(from_addr)[1])

        dkim = msg.msg.get('DKIM-Signature', "")
        for param in dkim.split(";"):
            if param.strip().startswith("d="):
                dkim_domain = param.split("=", 1)[1].strip(" ;\r\n")
                break
        else:
            dkim_domain = ""
        self.set_local(msg, "signedby", dkim_domain)

        for ip in msg.get_header_ips():
            if not ip.is_private:
                origin_ip = ip
                break
        else:
            origin_ip = None

        self.set_local(msg, "originip", origin_ip)



    def ip_to_awl_key(self, ip):
        if type(ip) == ipaddress.IPv4Address:
            mask = self.get_global("auto_whitelist_ipv4_mask_len")
        else:
            mask = self.get_global("auto_whitelist_ipv6_mask_len")

        interface = ipaddress.ip_interface("%s/%s" % (ip, mask))
        network = interface.network.network_address
        return network


    def get_entry(self, address, ip, signed_by):
        session = self.get_session()
        meta = MetaData()
        result = session.query(AWL).filter(AWL.email==address,
                                           AWL.signedby==signed_by,
                                           AWL.ip==ip).first()

        session.close()
        if not result:
            result = AWL()
            result.count = 0
            result.totscore = 0
            result.email = address
            result.ip = ip
            result.signedby = signed_by
        return result


    def check_from_in_auto_whitelist(self, msg, target=None):
        score =  msg.score
        factor = self.get_global("auto_whitelist_factor")
        origin_ip = self.get_local(msg, "originip")
        awl_key_ip = self.ip_to_awl_key(origin_ip)
        addr = self.get_local(msg, "from")
        signed_by = self.get_local(msg, "signedby")

        print addr, origin_ip, awl_key_ip, signed_by

        entry = self.get_entry(addr, awl_key_ip, signed_by)

        try:
            mean = entry.totscore/entry.count
        except ZeroDivisionError:
            mean = 0

        entry.count += 1
        entry.totscore += score

        session = self.get_session()
        session.merge(entry)
        session.commit()

        delta = mean - score
        delta *= factor
        #set tags

        msg.score += delta
        print msg.score
        return 0




