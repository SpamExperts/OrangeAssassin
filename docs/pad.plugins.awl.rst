
*******************
AutoWhiteListPlugin
*******************



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



Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.awl.AutoWhiteListPlugin

    user_awl_sql_username username
    user_awl_sql_password password
    user_awl_sql_table tablename
    user_awl_dsn DBI:databasetype:databasename:hostname:port

    body    CheckAWL     eval:check_from_in_auto_whitelist()

Usage
=====

<Description>

Options
=======

**auto_whitelist_ipv4_mask_len** 16 (type `int`)
    <Option description>
**auto_whitelist_factor** 0.5 (type `float`)
    <Option description>
**auto_whitelist_ipv6_mask_len** 48 (type `int`)
    <Option description>

EVAL rules
==========

.. automethod:: pad.plugins.awl.AutoWhiteListPlugin.check_from_in_auto_whitelist
    :noindex:

Tags
====

<Describe TAGS>

