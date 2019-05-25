import pymysql


class Store(object):
    def __init__(self, plugin):
        self.engine = plugin.get_engine()
        self.conn = None
        self.plugin = plugin

    def untie_db(self):
        """Remove the connection to the database."""
        if self.conn:
            self.conn.close()

    def tie_db_readonly(self):
        """Create a read-only connection to the database."""
        # TODO: Being able to distinguish between needing read-only and
        # read-write access to the database is very useful, so I've left
        # that in. However, we don't really support that further down
        # (e.g. in the configuration), so for now, it's just the same.
        return self.tie_db_writeable()

    def tie_db_writeable(self):
        """Create a read/write connection to the database."""
        self.conn = pymysql.connect(host=self.engine["hostname"], port=3306,
                                    user=self.engine["user"],
                                    passwd=self.engine["password"],
                                    db=self.engine["db_name"])
        return True

    def tok_get(self, token):
        """Get the spam and ham counts, and access times for the specified token."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT spam_count, ham_count, atime "
            "FROM bayes_token "
            "WHERE token=%s", (token, )
        )
        result = cursor.fetchone()
        cursor.close()
        return result

    def tok_get_all(self, tokens):
        """Like tok_get, but for all tokens specified.
        Each returned tuple starts with the token."""
        cursor = self.conn.cursor()
        for token in tokens:
            cursor.execute(
                "SELECT token, spam_count, ham_count, atime "
                "FROM bayes_token WHERE token=%s", (token, )
            )
            yield cursor.fetchone()
        cursor.close()

    def seen_get(self, msgid):
        """Get the "seen" flag for the specified message."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT flag FROM bayes_seen WHERE msgid=%s",
                       (msgid,))
        result = cursor.fetchone()[0]
        cursor.close()
        return result

    def seen_delete(self, msgid):
        cursor = self.conn.cursor()
        cursor.execute(
            "DELETE FROM bayes_seen WHERE msgid = %s",
            (msgid,)
        )
        cursor.close()

    def seen_put(self, msgid, flag):
        """Set the "seen" flag for the specified message."""
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE bayes_seen SET flag=%s WHERE msgid=%s", (flag, msgid)
        )
        self.conn.commit()
        cursor.close()

    def cleanup(self):
        """Do any necessary cleanup."""
        pass

    def nspam_nham_get(self):
        """Get the spam and ham counts for the database."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT spam_count, ham_count FROM bayes_vars LIMIT 1"
        )
        result = cursor.fetchone()
        cursor.close()
        return result

    def nspam_nham_change(self, spam, ham):
        """Set the spam and ham counts for the database."""
        cursor = self.conn.cursor()
        cursor.execute("UPDATE bayes_vars SET spam_count=%s, ham_count=%s",
                       (spam, ham))
        self.conn.commit()
        cursor.close()

    def multi_tok_count_change(self, spam, ham, tokens, msgatime):
        """Update the spam and ham counts, and access time for the specified tokens."""
        cursor = self.conn.cursor()
        for token in tokens:
            cursor.execute(
                "UPDATE bayes_token "
                "SET spam_count=%s, ham_count=%s, atime=%s "
                "WHERE token=%s", (spam, ham, msgatime, token))
        self.conn.commit()
        cursor.close()

    def tok_touch_all(self, touch_tokens, msgatime):
        """Update the access time for all the specified tokens."""
        cursor = self.conn.cursor()
        for token in touch_tokens:
            cursor.execute("UPDATE bayes_token SET atime=%s WHERE token=%s",
                           (msgatime, token))
        self.conn.commit()
        cursor.close()

    def get_running_expire_tok(self):
        # We don't do opportunistic expiry at the moment.
        raise NotImplementedError()

    def remove_running_expiry_tok(self):
        # We don't do opportunistic expiry at the moment.
        raise NotImplementedError()

    def expiry_due(self):
        # We don't do opportunistic expiry at the moment.
        raise NotImplementedError()

    def sync_due(self):
        """Return True if a sync is required."""
        pass

    def get_magic_re(self):
        """Not used in the SQL implementation."""
        pass


BAYES_EXPIRE_TABLE = """
CREATE TABLE IF NOT EXISTS `bayes_expire` (
  `id` int(11) NOT NULL default '0',
  `runtime` int(11) NOT NULL default '0',
  KEY `bayes_expire_idx1` (`id`)
)
"""
BAYES_GLOBAL_VARS_TABLE = """
CREATE TABLE IF NOT EXISTS `bayes_global_vars` (
  `variable` varchar(30) NOT NULL default '',
  `value` varchar(200) NOT NULL default '',
  PRIMARY KEY  (`variable`)
)
"""
BAYES_SEEN_TABLE = """
CREATE TABLE IF NOT EXISTS `bayes_seen` (
  `id` int(11) NOT NULL default '0',
  `msgid` varchar(200) character set latin1 collate latin1_bin NOT NULL default '',
  `flag` char(1) NOT NULL default '',
  PRIMARY KEY  (`id`,`msgid`)
)
"""
BAYES_TOKEN_TABLE = """
CREATE TABLE IF NOT EXISTS `bayes_token` (
  `id` int(11) NOT NULL default '0',
  `token` char(5) NOT NULL default '',
  `spam_count` int(11) NOT NULL default '0',
  `ham_count` int(11) NOT NULL default '0',
  `atime` int(11) NOT NULL default '0',
  PRIMARY KEY  (`id`,`token`),
  INDEX bayes_token_idx1 (id, atime)
)
"""
BAYES_VARS_TABLE = """
CREATE TABLE IF NOT EXISTS `bayes_vars` (
  `id` int(11) NOT NULL auto_increment,
  `username` varchar(200) NOT NULL default '',
  `spam_count` int(11) NOT NULL default '0',
  `ham_count` int(11) NOT NULL default '0',
  `token_count` int(11) NOT NULL default '0',
  `last_expire` int(11) NOT NULL default '0',
  `last_atime_delta` int(11) NOT NULL default '0',
  `last_expire_reduce` int(11) NOT NULL default '0',
  `oldest_token_age` int(11) NOT NULL default '2147483647',
  `newest_token_age` int(11) NOT NULL default '0',
  PRIMARY KEY  (`id`),
  UNIQUE KEY `bayes_vars_idx1` (`username`)
)
"""