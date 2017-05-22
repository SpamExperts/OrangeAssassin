from sqlalchemy.ext.declarative.api import declarative_base
from sqlalchemy import Column, Integer, PrimaryKeyConstraint, String


Base = declarative_base()


class BayesExpire(Base):
    """Schema for the bayes_expire table."""

    __tablename__ = 'bayes_expire'

    id = Column("id", Integer)
    runtime = Column("runtime", Integer)

    __table_args__ = (
        PrimaryKeyConstraint("id"),)


class BayesGlobalVars(Base):
    """Schema for the bayes_global_vars table."""

    __tablename__ = "bayes_global_vars"

    variable = Column("variable", String(30))
    value = Column("value", String(200))

    __table_args__ = (
        PrimaryKeyConstraint("variable"),)


class BayesSeen(Base):
    """Schema for the bayes_seen table."""

    __tablename__ = "bayes_seen"

    id = Column("id", Integer)
    msgid = Column("msgid", String(200))
    flag = Column("flag", String(1))

    __table_args__ = (
        PrimaryKeyConstraint("id", "msgid"),)


class BayesToken(Base):
    """Schema for the bayes_token table."""

    __tablename__ = "bayes_token"

    id = Column("id", Integer)
    token = Column("token", String(5))
    spam_count = Column("spam_count", Integer)
    ham_count = Column("ham_count", Integer)
    atime = Column("atime", Integer)

    __table_args__ = (
        PrimaryKeyConstraint("id", "token"),)
    # XXX Should also index on the (id, atime) combination.


class BayesVars(Base):
    """Schema for bayes_vars table."""

    __tablename__ = "bayes_vars"

    id = Column("id", Integer)  # should autoincrement
    username = Column("username", String(200))
    spam_count = Column("spam_count", Integer)
    ham_count = Column("ham_count", Integer)
    token_count = Column("token_count", Integer)
    last_expire = Column("last_expire", Integer)
    last_atime_delta = Column("last_atime_delta", Integer)
    last_expire_reduce = Column("last_expire_reduce", Integer)
    oldest_token_age = Column("oldest_token_age", Integer, default=2147483647)
    newest_token_age = Column("newest_token_age", Integer)

    __table_args__ = (
        PrimaryKeyConstraint("id"),)
    # Should also be a key on username, if we start using that.


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
        self.conn = self.plugin.get_session()
        return True

    def tok_get(self, token):
        """Get the spam and ham counts, and access times for the specified token."""
        return self.conn.execute(
            "SELECT spam_count, ham_count, atime "
            "FROM bayes_token WHERE token=:token",
            {"token": token}
        ).fetchone()

    def tok_get_all(self, tokens):
        """Like tok_get, but for all tokens specified.
        Each returned tuple starts with the token."""
        for token in tokens:
            yield self.conn.execute(
                "SELECT token, spam_count, ham_count, atime "
                "FROM bayes_token WHERE token=:token", {'token': token}
            ).fetchone()

    def seen_get(self, msgid):
        """Get the "seen" flag for the specified message."""
        return self.conn.execute(
            "SELECT flag FROM bayes_seen WHERE msgid=:msgid",
            {'msgid': msgid}).fetchone()[0]

    def seen_delete(self, id, msgid):
        self.conn.execute(
            "DELETE FROM bayes_seen WHERE msgid = :msgid",
            {"msgid": msgid}
        )

    def seen_put(self, msgid, flag):
        """Set the "seen" flag for the specified message."""
        self.conn.execute(
            "UPDATE bayes_seen SET flag=:flag WHERE msgid=:msgid",
            {"flag": flag, "msgid": msgid})
        self.conn.commit()

    def cleanup(self):
        """Do any necessary cleanup."""
        pass

    def nspam_nham_get(self):
        """Get the spam and ham counts for the database."""
        return self.conn.execute(
            "SELECT spam_count, ham_count FROM bayes_vars LIMIT 1"
        ).fetchone()

    def nspam_nham_change(self, spam, ham):
        """Set the spam and ham counts for the database."""
        self.conn.execute(
            "UPDATE bayes_vars "
            "SET spam_count=:spam_count, ham_count=:ham_count",
            {'spam_count': spam, 'ham_count': ham}
        )
        self.conn.commit()

    def multi_tok_count_change(self, spam, ham, tokens, msgatime):
        """Update the spam and ham counts, and access time for the specified tokens."""
        for token in tokens:
            self.conn.execute(
                "UPDATE bayes_token "
                "SET spam_count=:spam_count, ham_count=:ham_count, "
                "atime=:atime WHERE token=:token",
                {
                    'spam_count': spam, 'ham_count': ham,
                    'atime': msgatime, 'token': token
                }
            )
        self.conn.commit()

    def tok_touch_all(self, touch_tokens, msgatime):
        """Update the access time for all the specified tokens."""
        for token in touch_tokens:
            self.conn.execute("UPDATE bayes_token "
                              "SET atime=:atime WHERE token=:token",
                              {'atime': msgatime, 'token': token})
        self.conn.commit()

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