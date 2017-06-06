"""Bayes - determine spam likelihood using a Bayesian classifier.

This is a Bayesian-style probabilistic classifier, using an algorithm
based on the one detailed in Paul Graham's "A Plan For Spam" paper at:

http://www.paulgraham.com/spam.html

It also incorporates some other aspects taken from Graham Robinson's
webpage on the subject at:

http://radio.weblogs.com/0101454/stories/2002/09/16/spamDetection.html

And the chi-square probability combiner as described here:

http://www.linuxjournal.com/print.php?sid=6467

The results are incorporated into SpamAssassin as the BAYES_* rules.
"""

import re
import time
import math
import hashlib

import oa.plugins.base
from oa.regex import Regex

try:
    from oa.db.bayes.sqlalchemy import Store
except ImportError:
    from oa.db.bayes.mysql import Store


GREY_AREA_TOKEN_RE = r"""
^
(?:a
(?:ble|l(?:ready|l)|n[dy]|re)
|
b(?:ecause|oth)|c(?:an|ome)|e(?:ach|mail|ven)
|
f(?:ew|irst|or|rom)|give|h(?:a(?:ve|s)|ttp)|i(?:n(?:formation|to)|t\'s)
|
just|know|l(?:ike|o(?:ng|ok))|m(?:a(?:de|il(?:(?:ing|to))?|ke|ny)
|
o(?:re|st)|uch)|n(?:eed|o[tw]|umber)|o(?:ff|n(?:ly|e)|ut|wn)|p(?:eople|lace)
|
right|s(?:ame|ee|uch)|t(?:h(?:at|is|rough|e)|ime)|using
|
w(?:eb|h(?:ere|y)|ith(?:out)?|or(?:ld|k))|y(?:ears?|ou(?:(?:\'re|r))?)
)$"""

ADDR_HEADERS = {
    u"return-path", u"from", u"to", u"cc", u"reply-to", u"errors-to",
    u"mail-followup-to", u"sender", u"x-return-path", u"x-from", u"x-to",
    u"x-cc", u"x-reply-to", u"x-errors-to", u"x-mail-followup-to", u"x-sender",
    u"resent-return-path", u"resent-from", u"resent-to", u"resent-cc",
    u"resent-reply-to", u"resent-errors-to", u"resent-mail-followup-to",
    u"resent-sender", }


class Chi(object):
    """Chi-squared probability combining and related constants."""

    # Pre-calculating this saves a lot of work, because this is used
    # extremely frequently.
    LN2 = math.log(2)

    # Value for 'x' in Gary Robinson's f(w) equation.
    # "Let x = the number used when n [hits] is 0."
    # Essentially, the probability given to a word that has never been seen
    # before. SpamAssassin uses 0.538, and SpamBayes uses 0.5.
    FW_X_CONSTANT = 0.538

    # Value for 's' in the f(w) equation. "We can see s as the "strength"
    # (hence the use of "s") of an original assumed expectation ... relative
    # to how strongly we want to consider our actual collected data".
    # Low 's' means trust collected data more strongly. This adjusts how
    # much weight to give the prior assumption relative to the probabilities
    # estimated by counting. At 0, the counting estimates are believes 100%
    # even to the extent of assigning certainty (0 or 1) to a word that has
    # appeared in only ham or only spam. This is a disaster.
    # As FW_S_CONSTANT tends towards infinity, all probabilities tend
    # toward FW_X_CONSTANT. SpamAsassin uses 0.030, and SpamBayes uses 0.45.
    FW_S_CONSTANT = 0.030

    # (s . x) for the f(w) equation.
    FW_S_DOT_X = FW_X_CONSTANT * FW_S_CONSTANT

    # When scoring a message, ignore all words with abs(spamprob - 0.5) <
    # min_prob_strength. SpamAssassin uses 0.346, and SpamBayes uses 0.1.
    MIN_PROB_STRENGTH = 0.346

    @classmethod
    def combine(cls, ns, nn, sortedref):
        """Return best-guess probability that sortedref is spam.
        
        ns is nspam (the number of spam messages).
        nn is nham (the number of ham messages).
        sortedref is an iterable object producing probabilities.
        
        The return value is a float in [0.0, 1.0].
        """
        # Avoid dictionary lookups in inner loops.
        frexp = math.frexp
        ln = math.log

        # SpamBayes uses an initial value of 1.0 for both H and S.
        # SpamAssassin uses nspam/(nham+nspam) for S and nham/(nham+nspam)
        # for H. The SA code has a reference to bug 3118, but I can't find
        # that online, so I'm not sure what it is.
        n = ns + nn
        if not n:
            return 0.5
        S = ns / n
        H = nn / n

        Hexp = Sexp = 0

        for prob in sortedref:
            S *= 1.0 - prob
            H *= prob
            if S < 1e-200:
                S, e = frexp(S)
                Sexp += e
            if H < 1e-200:
                H, e = frexp(H)
                Hexp += e

        S = ln(S) + Sexp * cls.LN2
        H = ln(H) + Hexp * cls.LN2

        S = 1.0 - cls.chi2Q(-2.0 * S, len(sortedref))
        H = 1.0 - cls.chi2Q(-2.0 * H, len(sortedref))
        prob = (S - H + 1.0) / 2.0
        return prob

    @staticmethod
    def chi2Q(x2, halfv, exp=math.exp):
        """Return prob(chisq >= x2, with v degrees of freedom)."""
        # XXX If x2 is very large, exp(-m) will underflow to 0.
        m = x2 / 2.0
        total = term = exp(-m)
        for i in range(1, halfv):
            term *= m / i
            total += term
        # With small x2 and large v, accumulated roundoff error, plus error
        # in the platform exp(), can cause this to spill a few ULP above
        # 1.0. For example, chi2Q(100, 300) on my box has
        # total == 1.0000000000000009 at this point. Returning a value even
        # a teensy bit over 1.0 is no good.
        return min(total, 1.0)


class NaiveBayes(object):
    """Naive-Bayesian-style probability combining and related constants."""

    # Value for 'x' in Gary Robinson's f(w) equation.
    # "Let x = the number used when n [hits] is 0."
    FW_X_CONSTANT = 0.600

    # Value for 's' in the f(w) equation. "We can see s as the "strength"
    # (hence the use of "s") of an original assumed expectation ... relative
    # to how strongly we want to consider our actual collected data."
    # Low 's' means trust collected data more strongly.
    FW_S_CONSTANT = 0.160

    # (s . x) for the f(w) equation.
    FW_S_DOT_X = FW_X_CONSTANT * FW_S_CONSTANT

    # Should we ignore tokens with probs very close to the middle ground
    # (.5)? tokens need to be outside the [ .5-MPS, .5+MPS ] range to be
    # used.
    MIN_PROB_STRENGTH = 0.430

    @staticmethod
    def combine(ns, nn, sortedref):
        """Combine probabilities using Gary Robinson's naive-Bayesian-style
        combiner."""
        wc = len(sortedref)
        if not wc:
            return 0.5
        P = 1
        Q = 1
        for pw in sortedref:
            P *= (1 - pw)
            Q *= pw
        P = 1 - (P ** (1 / wc))
        Q = 1 - (Q ** (1 / wc))
        return (1 + (P - Q) / (P + Q)) / 2.0


# Pick ONLY ONE of these combining implementations.
_combiner = Chi()
# _combiner = NaiveBayes

combine = _combiner.combine
FW_S_DOT_X = _combiner.FW_S_DOT_X
FW_S_CONSTANT = _combiner.FW_S_CONSTANT
MIN_PROB_STRENGTH = _combiner.MIN_PROB_STRENGTH

# XXX Should some of these options be controllable in the configuration
# XXX file? I don't think SA allows that, and they are generally quite
# XXX complex to understand and get right.

# Which headers should we scan for tokens? Don't use all of them, as
# it's easy to pick up spurious clues from some. What we now do is use
# all of them *less* these well-known headers; that way we can pick up
# spammers' tracking headers (which are obviously not well-known in
# advance!).

# Received is handled specially.
# XXX This could use a lot of modernisation.
IGNORED_HEADERS = {header.lower() for header in {
    u"Sender",  # Misc noise.
    u"X-Sender",  # Misc noise.
    u"Delivered-To",
    u"Delivery-Date",
    u"Envelope-To",
    u"X-Envelope-To",
    u"X-MIME-AutoConverted",
    u"X-Converted-To-Plain-Text",
    u"Subject",  # Not worth a tiny gain vs. to DB size increase.
    # Date: can provide invalid cues if your spam corpus is older /
    # newer than ham.
    u"Date",
    # List headers: ignore. A spam-filtering mailing list will become a
    # ham sign.
    u"X-List",
    u"Mailing-List",
    u"X-Mailing-List",
    u"List-Archive",
    u"List-Help",
    u"List-Id",
    u"List-Owner",
    u"List-Post",
    u"List-Subscribe",
    u"List-Unsubscribe",
    u"List-Host",
    u"List-Id",
    u"List-Manager",
    u"List-Admin",
    u"List-Comment",
    u"List-Name",
    u"List-Url",
    u"X-List-Archive",
    u"X-List-Help",
    u"X-List-Id",
    u"X-List-Owner",
    u"X-List-Post",
    u"X-List-Subscribe",
    u"X-List-Unsubscribe",
    u"X-List-Host",
    u"X-List-Id",
    u"X-List-Manager",
    u"X-List-Admin",
    u"X-List-Comment",
    u"X-List-Name",
    u"X-List-Url",
    u"X-Unsub",
    u"X-Unsubscribe",
    u"X-Mailman-Version",
    u"X-BeenThere",
    u"X-Loop",
    u"Mail-Followup-To",
    u"X-eGroups-From",
    u"X-eGroups-Return",
    u"X-MDMailing-List",
    u"X-XEmacs-List",

    # Gatewayed through mailing list (thanks to Allen Smith).
    u"Resent-To",
    u"Resent-Date",
    u"Resent-From",
    u"Original-To",
    u"Original-Date",
    u"Original-From",
    u"X-Resent-To",
    u"X-Resent-Date",
    u"X-Resent-From",
    u"X-Original-To",
    u"X-Original-Date",
    u"X-Original-From",

    # Spam filter / virus-scanner headers: too easy to chain from these.
    u"X-MailScanner",
    u"X-MailScanner-SpamCheck",
    u"X-Spam",
    u"X-Spam-Status-Version",
    u"X-Spam-Level-Version",
    u"X-Spam-Flag-Version",
    u"X-Spam-Report-Version",
    u"X-Spam-Hits-Version",
    u"X-Spam-Score-Version",
    u"X-Spam-Checker-Version",
    u"X-Antispam",
    u"X-RBL-Warning",
    u"X-Mailscanner",
    u"X-MDaemon-Deliver-To",
    u"X-Virus-Scanned",
    u"X-Mass-Check-Id",
    u"X-Pyzor",
    # XXX This needs a regular expression, but it doesn't seem worth having this
    # XXX whole check work with regular expressions just for this.
    # ur"X-DCC-\S{2,25}-Metrics",
    u"X-Filtered-By",
    u"X-Scanned-By",
    u"X-Scanner",
    u"X-AP-Spam-Score",
    u"X-AP-Spam-Status",
    u"X-RIPE-Spam-Status",
    # XXX This needs a regular expression, but it doesn't seem worth having this
    # XXX whole check work with regular expressions just for this.
    # ur"X-SpamCop-[^:]+",
    u"X-SMTPD",
    u"X-SMTPD Spam-Apparently-To",
    u"X-SMTPD X-Spam-Apparently-To",
    u"SPAM",
    u"X-Perlmx-Spam",
    u"X-Bogosity",

    # Some noisy Outlook headers that add no good clues:
    u"Content-Class",
    u"Thread-Index",
    u"Thread-Topic",
    u"X-OriginalArrivalTime",

    # Annotations from IMAP, POP, and MH:
    u"Status",
    u"X-Status",
    u"X-Flags",
    u"X-Keywords",
    u"Replied",
    u"Forwarded",
    u"Lines",
    u"Content-Length",
    u"X-UID",
    u"X-UIDL",
    u"X-IMAPbase",

    # Annotations from Bugzilla.
    # XXX This needs a regular expression, but it doesn't seem worth having this
    # XXX whole check work with regular expressions just for this.
    # ur"X-Bugzilla-[^:]+",

    # Annotations from VM: (thanks to Allen Smith).
    u"X-VM-Bookmark",
    u"X-VM-POP-Retrieved",
    u"X-VM-IMAP-Retrieved",
    u"X-VM-Labels",
    u"X-VM-Last-Modified",
    u"X-VM-Summary-Format",
    u"X-VM-VHeader",
    u"X-VM-Message-Order",
    u"X-VM-v0-Data",
    u"X-VM-v1-Data",
    u"X-VM-v2-Data",
    u"X-VM-v3-Data",
    u"X-VM-v4-Data",
    u"X-VM-v5-Data",
    u"X-VM-v6-Data",
    u"X-VM-v7-Data",
    u"X-VM-v8-Data",
    u"X-VM-v9-Data",

    # Annotations from Gnus:
    u"X-Gnus-Mail-Source",
    u"Xref",
}}

# Note only the presence of these headers, in order to reduce the
# hapaxen they generate.
MARK_PRESENCE_ONLY_HEADERS = {header.lower() for header in {
    u"X-Face",
    u"X-GPG-Fingerprint",
    u"X-GPG-Key-Fingerprint",
    u"X-PGP-Fingerprint",
    u"X-PGP-Key-Fingerprint",
    u"X-GnuPG-Fingerprint",
    u"X-GnuPG-Key-Fingerprint",
    u"X-Gnu-PG-Fingerprint",
    u"X-Gnu-PG-Key-Fingerprint",
    u"DKIM-Signature",
    u"DomainKey-Signature",
}}

# Tweaks tested as of Nov 18 2002 by jm: see SpamAssassin-devel list
# archives for results. The winners are now the default settings.
IGNORE_TITLE_CASE = True
TOKENIZE_LONG_8BIT_SEQS_AS_TUPLES = True
TOKENIZE_LONG_TOKENS_AS_SKIPS = True

# Tweaks of May 12 2003, see SpamAssassin-devel archives again.
PRE_CHEW_ADDR_HEADERS = True
CHEW_BODY_URIS = True
CHEW_BODY_MAILADDRS = True
HEADERS_TOKENIZE_LONG_TOKENS_AS_SKIPS = True
BODY_TOKENIZE_LONG_TOKENS_AS_SKIPS = True
URIS_TOKENIZE_LONG_TOKENS_AS_SKIPS = False
IGNORE_MSGID_TOKENS = False

# Tweaks of 12 March 2004, see SpamAssassin bug 2129.
DECOMPOSE_BODY_TOKENS = True
MAP_HEADERS_MID = True
MAP_HEADERS_FROMTOCC = True
MAP_HEADERS_USERAGENT = True

# Tweaks, see http://issues.apache.org/SpamAssassin/show_bug.cgi?id=3173#c26
ADD_INVIZ_TOKENS_I_PREFIX = True
ADD_INVIZ_TOKENS_NO_PREFIX = False

# We store header-mined tokens in the db with a "HHeaderName:val"
# format. Some headers may contain lots of gibberish tokens, so allow a
# little basic compression by mapping the header name here.
# These are the headers that appear with the most frequency in jm's DB.
# Note: this doesn't have to be 2-way (ie. LHSes that map to the same
# RHS are not a problem), but mixing tokens from multiple different
# headers may impact accuracy, so might as well avoid this if possible.
# These are the top ones from jm's corpus.
HEADER_NAME_COMPRESSION = {
    u"Message-Id": u"*m",
    u"Message-ID": u"*M",
    u"Received": u"*r",
    u"User-Agent": u"*u",
    u"References": u"*f",
    u"In-Reply-To": u"*i",
    u"From": u"*F",
    u"Reply-To": u"*R",
    u"Return-Path": u"*p",
    u"Return-path": u"*rp",
    u"X-Mailer": u"*x",
    u"X-Authentication-Warning": u"*a",
    u"Organization": u"*o",
    u"Organisation": u"*o",
    u"Content-Type": u"*c",
    u"x-spam-relays-trusted": u"*RT",
    u"x-spam-relays-untrusted": u"*RU",
}

# Should we use the Robinson f(w) equation from
# http://radio.weblogs.com/0101454/stories/2002/09/16/spamDetection.html ?
# It gives better results, in that scores are more likely to distribute
# into the <0.5 range for nonspam and >0.5 for spam.
USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS = True

# How many of the most significant tokens should we use for the p(w)
# calculation?
# SpamAssassin and SpamBayes both default to 150.
N_SIGNIFICANT_TOKENS = 150

# How many significant tokens are required for a classifier score to be
# considered usable?
REQUIRE_SIGNIFICANT_TOKENS_TO_SCORE = -1

# How long a token should we hold onto? (Note: German speakers typically
# will require a longer token than English ones).
# SpamAssassin defaults to 15, SpamBayes defaults to 12.
MAX_TOKEN_LENGTH = 15


class BayesPlugin(oa.plugins.base.BasePlugin):
    """Implement a somewhat Bayesian plug-in."""

    learn_caller_will_untie = False
    learn_no_relearn = False
    use_hapaxes = False
    use_ignores = True

    options = {
        u"use_bayes": (u"bool", True),
        u"use_learner": (u"bool", True),
        u"use_bayes_rules": (u"bool", True),
        u"detailed_bayes_score": (u"bool", False),
        u"bayes_min_spam_num": (u"int", 200),
        u"bayes_min_ham_num": (u"int", 200),
        u"bayes_ignore_headers": (u"list", []),
        u'bayes_use_hapaxes': (u'bool', True),
        u'bayes_sql_dsn': ('str', ''),
        u'bayes_sql_username': ('str', ''),
        u'bayes_sql_password': ('str', ''),
        u'bayes_auto_expire': ('int', 0),
        u'bayes_token_sources': ('split', 'header visible invisible uri'),
    }

    eval_rules = ("check_bayes",)
    store = None

    @property
    def dsn(self):
        return self['bayes_sql_dsn']

    @property
    def sql_username(self):
        # XXX need to figure out what's the deal with override username
        return self['bayes_sql_username']

    @property
    def sql_password(self):
        return self['bayes_sql_password']

    def check_start(self, msg):
        self['rendered'] = [msg.msg['subject'] or '\n']
        self['visible_rendered'] = [msg.msg['subject'] or '\n']
        self['invisible_rendered'] = []

    def extract_metadata(self, msg, payload, text, part):
        if part.get_content_type() == 'text/plain':
            self['rendered'].append(text)
            self['visible_rendered'].append(text)
        if part.get_content_type() == 'text/html':
            # XXX SA parses these and checks for [in]visible content
            pass

    def parsed_metadata(self, msg):
        self.ctxt.log.debug("rendered body %s", self['rendered'])
        self.ctxt.log.debug("invisible body %s", self['invisible_rendered'])
        self['rendered'] = "\n".join(self['rendered'])
        self['invisible_rendered'] = "\n".join(self['invisible_rendered'])
        self[u"bayes_token_body"] = self.get_body_text_array_common(self["rendered"])
        self[u'bayes_token_inviz'] = self.get_body_text_array_common(self["invisible_rendered"])
        self[u'bayes_token_uris'] = []  # self.get_uri_list()

    def finish_parsing_end(self, ruleset):
        super(BayesPlugin, self).finish_parsing_end(ruleset)
        self.store = Store(self)

    def check_end(self, ruleset, msg):
        learned = self.get_local(msg, "learned")
        tchammy = len(self.get_local(msg, "bayes_token_info_hammy"))
        tcspammy = len(self.get_local(msg, "bayes_token_info_spammy"))
        count = self.get_local(msg, "count")
        summary = "Tokens new, {}; hammy, {}; neutral, {}; spammy, {}.".format(
            count - learned, tchammy, learned-tchammy-tcspammy, tcspammy
        )
        msg.plugin_tags.update({
            "BAYESTCHAMMY": tchammy,
            "BAYESTCSPAMMY": tcspammy,
            "BAYESTCLEARNED": learned,
            "BAYESTC": count,  # XXX This is still different than SA
            "HAMMYTOKENS": self.bayes_report_make_list(msg, self.get_local(msg, "bayes_token_info_hammy")),
            "SPAMMYTOKENS": self.bayes_report_make_list(msg, self.get_local(msg, "bayes_token_info_spammy")),
            "TOKENSUMMARY": summary,
        })

    def finish(self):
        """Finish processing the message."""
        if self.store:
            self.store.untie_db()

    def parse_list(self, list_name):
        parsed_list = []
        characters = ["?", "@", ".", "*@"]
        for addr in self[list_name]:
            if len([e for e in characters if e in addr]):
                address = re.escape(addr).replace(r"\*", ".*").replace(r"\?",
                                                                       ".?")
                if "@" in address:
                    parsed_list.append(address)
                else:
                    parsed_list.append(".*@"+address)
        return parsed_list

    def check_address_in_list(self, addresses, list_name):
        """Check if addresses match the regexes from list_name.
        """
        for address in addresses:
            for regex in self[list_name]:
                if Regex(regex).search(address):
                    return True
        return False

    def get_body_text_array_common(self, text):
        """Common method for rendered, visible_rendered, 
        and invisible_rendered methods. """
        # Whitespace handling (warning: small changes have large effects!).
        # Double newlines => form feed.
        text = re.sub(r"\n+\s*\n+", r"\f", text)
        # whitespace (incl. VT) => space.
        text = re.sub(r" \t\n\r\x0b", r" ", text)
        # Form feeds => newline.
        text = re.sub(r"\f", "\n", text)

        return self.split_into_array_of_short_lines(text)

    @staticmethod
    def split_into_array_of_short_lines(text):
        """Split the text into a list of short lines."""
        # SA tries to avoid splitting things into pieces here, but we keep it
        # a bit simpler and just split on lines.
        return text.splitlines()

    def plugin_report(self, msg):
        """Train the message as spam."""
        super(BayesPlugin, self).plugin_report(msg)
        self.learn_message(msg, True)

    def plugin_revoke(self, msg):
        """Train the message as ham."""
        super(BayesPlugin, self).plugin_revoke(msg)
        self.learn_message(msg, False)

    def learn_message(self, msg, isspam):
        """Learn the message has spam or ham."""
        if not self["use_bayes"]:
            return
        # XXX In SA, there is a time limit set here.
        if self.store.tie_db_writeable():
            ret = self._learn_trapped(isspam, msg)
            if not self.learn_caller_will_untie:
                self.store.untie_db()
            return ret
        return None

    def _learn_trapped(self, isspam, msg):
        """Do the actual training work.
        
        In SA this is "trapped", in that it is wrapped inside of a timeout.
        Here, it is not currently, but we may add that in the future."""
        msgid = msg.msgid
        seen = self.store.seen_get(msgid)
        if seen:
            if (seen == "s" and isspam) or (seen == "h" and not isspam):
                self.ctxt.log.debug(
                    "bayes: %s already learnt correctly, not learning twice",
                    msgid
                )
                return False
            elif seen not in {"h", "s"}:
                self.ctxt.log.warn(
                    "bayes: db_seen corrupt: value='%s' for %s, ignored",
                    seen, msgid
                )
            else:
                # Bug 3704: If the message was already learned, don't try
                # learning it again. this prevents, for instance, manually
                # learning as spam, then autolearning as ham, or visa versa.
                if self.learn_no_relearn:
                    self.ctxt.log.debug(
                        "bayes: %s already learnt as opposite, not re-learning",
                        msgid
                    )
                    return False
            self.ctxt.log.debug(
                "bayes: %s already learnt as opposite, forgetting first", msgid
            )
            # Kluge so that forget() won't untie the db on us ...
            orig = self.learn_caller_will_untie
            try:
                self.learn_caller_will_untie = True
                fatal = self.forget_message(msg, msgid)
            finally:
                # Reset the value post-forget() ...
                self.learn_caller_will_untie = orig

            # Forget() gave us a fatal error, so propagate that up.
            if fatal is None:
                self.ctxt.log.debug("bayes: forget() returned a fatal error, "
                                    "so learn() will too")
                return

        # Now that we're sure we haven't seen this message before ...
        msgatime = msg.receive_date
        # If the message atime comes back as being more than 1 day in the
        # future, something's messed up and we should revert to current time as
        # a safety measure.
        if msgatime - time.time() > 86400:
            msgatime = time.time()
        tokens = self.tokenise(msg)
        # XXX SA puts this in a timer.
        if isspam:
            self.store.nspam_nham_change(1, 0)
            self.store.multi_tok_count_change(1, 0, tokens, msgatime)
        else:
            self.store.nspam_nham_change(0, 1)
            self.store.multi_tok_count_change(0, 1, tokens, msgatime)
        self.store.seen_put(msgid, "s" if isspam else "h")
        self.store.cleanup()

        self.ctxt.log.debug("bayes: learned '%s', atime: %s", msgid, msgatime)
        return True

    def forget_message(self, msg, msgid):
        """Unlearn a message."""
        if not self["use_bayes"]:
            return
        # XXX SA wraps this in a timer.
        if self.store.tie_db_writeable():
            ret = self._forget_trapped(msg, msgid)
            if not self.learn_caller_will_untie:
                self.store.untie_db()
            return ret
        return None

    def _forget_trapped(self, msg, msgid):
        """Do the actual unlearning work.

        In SA this is "trapped", in that it is wrapped inside of a timeout.
        Here, it is not currently, but we may add that in the future."""
        if not msgid:
            msgid = msg.msgid
        seen = self.store.seen_get(msgid)
        if seen:
            if seen == "s":
                isspam = True
            elif seen == "h":
                isspam = False
            else:
                self.ctxt.log.debug("bayes: forget: msgid %s seen entry "
                                    "is neither ham nor spam but '%s', ignored",
                                    msgid, seen)
                return False
        else:
            self.ctxt.log.debug("bayes: forget: msgid %s not learnt, ignored",
                                msgid)
            return False
        tokens = self.tokenise(msg)
        if isspam:
            self.store.nspam_nham_change(-1, 0)
            self.store.multi_tok_count_change(-1, 0, tokens, msg.receive_date)
        else:
            self.store.nspam_nham_change(0, -1)
            self.store.multi_tok_count_change(0, -1, tokens, msg.receive_date)
        # XXX check
        self.store.seen_delete(msgid)
        self.store.cleanup()
        return True

    def learner_is_scan_available(self, params=None):
        """Check to make sure we can tie() the DB, and we have enough entries 
        to do a scan. If we're told the caller will untie(), go ahead and 
        leave the db tied. """
        if not self["use_bayes"]:
            return False
        if not self.store.tie_db_readonly():
            return False

        ns, nn = self.store.nspam_nham_get()
        if ns < self["bayes_min_spam_num"]:
            self.ctxt.log.debug(
                "bayes: not available for scanning, only %s spam(s) in "
                "bayes DB < %s", ns, self["bayes_min_spam_num"]
            )
            if not self.learn_caller_will_untie:
                self.store.untie_db()
            return False
        if nn < self["bayes_min_ham_num"]:
            self.ctxt.log.debug(
                "bayes: not available for scanning, only %s ham(s) "
                "in bayes DB < %s", nn, self["bayes_min_ham_num"])
            if not self.learn_caller_will_untie:
                self.store.untie_db()
            return False
        return True

    def tokenise(self, msg):
        """Convert the message to a sequence of tokens."""
        tokens = []
        for line in self["bayes_token_body"]:
            tokens.extend(self._tokenise_line(line, "", 1))
        for line in self['bayes_token_uris']:
            tokens.extend(self._tokenise_line(line, "", 2))
        for line in self['bayes_token_inviz']:
            if ADD_INVIZ_TOKENS_I_PREFIX:
                tokens.extend(self._tokenise_line(line, "I*:", 1))
            if ADD_INVIZ_TOKENS_NO_PREFIX:
                tokens.extend(self._tokenise_line(line, "", 1))
        hdrs = self._tokenise_headers(msg)
        for prefix, value in hdrs.values():
            tokens.extend(self._tokenise_line(value, "H%s:" % prefix, 0))
        # Remove duplicates, skip empty tokens (this happens sometimes),
        # generate a SHA1 hash, and take the lower 40 bits as the token.
        # XXX It would be better if we could refactor all of this so that we
        # XXX yielded tokens as they were generated.
        for token in set(tuple(tokens)):
            if not token:
                continue
            yield hashlib.sha1(token.encode("utf8")).digest()[-5:], token

    def _tokenise_line(self, line, tokprefix, region):
        # Include quotes, .'s and -'s for URIs, and [$,]'s for Nigerian-scam
        # strings, and ISO-8859-15 alphas. Do not split on @'s; better
        # results keeping it.
        # Some useful tokens: "$31,000,000" "www.clock-speed.net" "f*ck" "Hits!"
        matches = re.findall(r"""([A-Za-z0-9,@*!_'"\$.\s-]+|
                           [\xC0-\xDF][\x80-\xBF]|
                           [\xE0-\xEF][\x80-\xBF]{2}|
                           [\xF0-\xF4][\x80-\xBF]{3}|
                           [\xA1-\xFF])|\s.""",  line, re.S | re.X)
        line = " ".join(matches)

        # DO split on "..." or "--" or "---"; common formatting error
        # resulting in hapaxes. Keep the separator itself as a token, though,
        # as long ones can be good spam signs.
        line = re.sub(r"(\w)(\.{3,6})(\w)", r"\1 \2 \3", line)
        line = re.sub(r"(\w)(\-{2,6})(\w)", r"\1 \2 \3", line)

        if IGNORE_TITLE_CASE:
            if region == 1 or region == 2:
                # Lower-case Title Case at start of a full-stop-delimited
                # line (as would be seen in a Western language).

                # XXX I don't think this can be done in a Python regular
                # XXX expression. We should evaluate whether it's worth the
                # XXX complexity of doing this.
                pass

        magic_re = self.store.get_magic_re()

        rettokens = set()
        for token in line.split():
            # Trim non-alphanumeric characters at the start of end.
            token = re.sub(r"^[-'\"\.,]+", "", token)
            # So we don't get loads of '"foo' tokens
            token = re.sub(r"[-'\"\.,]+$", "", token)

            # Skip false magic tokens.
            # TVD: we need to do a defined() check since SQL doesn't have magic
            # tokens, so the SQL BayesStore returns undef. I really want a way
            # of optimizing that out, but I haven't come up with anything yet.
            #
            if magic_re and re.match(magic_re, token):
                continue

            # *Do* keep 3-byte tokens; there are some solid signs in there -
            length = len(token)
            if length < 3:
                continue

            # - but extend the stop-list. These are squarely in the grey area,
            # and it just slows us down to record them. See
            # http://wiki.apache.org/spamassassin/BayesStopList for more info.
            if re.match(GREY_AREA_TOKEN_RE, token, re.VERBOSE):
                continue

            # Are we in the body? If so, apply some body-specific breakouts.
            if region in (1, 2):
                if CHEW_BODY_MAILADDRS and re.match(r"\S\@\S", token):
                    rettokens.add(self._tokenise_mail_addrs(token))
                elif CHEW_BODY_URIS and re.match(r"\S\.[a-z]", token, re.I):
                    rettokens.add(u"UD:" + token)  # The full token.
                    bit = token
                    while True:
                        bit = re.sub(r"^[^\.]+\.(.+)$", "\1", bit)
                        if not bit:
                            break
                        rettokens.add("UD:" + bit)  # UD = URL domain

            # Note: do not trim down overlong tokens if they contain '*'.
            # This is used as part of split tokens such as "HTo:D*net"
            # indicating that the domain ".net" appeared in the To header.
            if length > MAX_TOKEN_LENGTH and "*" not in token:
                if TOKENIZE_LONG_8BIT_SEQS_AS_TUPLES and re.match(r"[\xa0-\xff]{2}", token):
                    # Matt sez: "Could be Asian? Autrijus suggested doing
                    # chracter ngrams, but I'm doing tuples to keep the dbs
                    # small(er)." Sounds like a plan to me! (jm)
                    while True:
                        token = re.sub(r"^(..?)", "", token)
                        if not token:
                            break
                        rettokens.add("8:" + token)
                    continue

                if (region == 0 and HEADERS_TOKENIZE_LONG_TOKENS_AS_SKIPS) or (region == 1 and BODY_TOKENIZE_LONG_TOKENS_AS_SKIPS) or (region == 2 and URIS_TOKENIZE_LONG_TOKENS_AS_SKIPS):
                    # SpamBayes trick via Matt: Just retain 7 chars. Do not
                    # retain the length, it does not help; see my mail to
                    # -devel of Nov 20 2002. "sk:" stands for "skip".
                    token = "sk:" + token[:7]

            # Decompose tokens? Do this after shortening long tokens.
            if region in (1, 2) and DECOMPOSE_BODY_TOKENS:
                decomposed = re.sub(r"[^\w:\*]", u"", token)
                rettokens.add(tokprefix + decomposed)  # "Foo"
                rettokens.add(tokprefix + decomposed.lower())  # "foo"
                rettokens.add(tokprefix + token.lower())  # "foo!"

            rettokens.add(tokprefix + token)
        return rettokens

    def _tokenise_headers(self, msg):
        """Tokenise the headers of the message.
        
        Return a dictionary that maps the case-sensitive header name to
        a normalised value.
        :type msg: pad.message.Message
        """
        parsed = {}
        user_ignore = {header.lower()
                       for header in self[u"bayes_ignore_headers"]}

        headers = {
            header
            for header in msg.raw_headers
            if header.lower() not in IGNORED_HEADERS and (not IGNORE_MSGID_TOKENS or header.lower() != "message-id")
        }
        # TODO: SA adds in all of the message's metadata as additional
        # headers here. It's possible that we might want to do that as well,
        # but we'll need to ensure that everything is suitable (e.g. not
        # huge) and can be appropriately converted to a string.

        for header in headers:
            values = msg.msg.get_all(header)
            if header.lower() == u"received":
                # Use only the last 2 received lines: usually a good source of
                # spamware tokens and HELO names.
                values = values[-2:]
            for val in values:
                # Prep the header value.
                val = val.rstrip()
                l_header = header.lower()

                # Remove user-specified headers here.
                if l_header in user_ignore:
                    continue

                # Special tokenisation for some headers:
                header = self._parse_special_header(header, l_header,
                                                    parsed, val)
        return parsed

    def _parse_special_header(self, header, l_header, parsed, val):
        if l_header in (u"message-id", u"x-message-id", u"resent-message-id"):
            val = self._pre_chew_message_id(val)
        elif PRE_CHEW_ADDR_HEADERS and l_header in ADDR_HEADERS:
            val = self._pre_chew_addr_header(val)
        elif l_header == u"received":
            val = self._pre_chew_received(val)
        elif l_header == u"content-type":
            val = self._pre_chew_content_type(val)
        elif l_header == u"mime-version":
            val = val.replace(u"1.0", u"")  # Totally innocuous.
        elif l_header in MARK_PRESENCE_ONLY_HEADERS:
            val = "1"  # Just mark the presence, they create lots of hapaxen.
        if MAP_HEADERS_MID and l_header in {u"in-reply-to", u"references",
                                            u"message-id"}:
            parsed[u"*MI"] = val
        if MAP_HEADERS_FROMTOCC and l_header in {u"from", u"to", u"cc"}:
            parsed[u"*Ad"] = val
        if MAP_HEADERS_USERAGENT and l_header in {u"x-mailer", u"user-agent"}:
            parsed[u"*UA"] = val

        # Replace header name with "compressed" version if possible.
        header = HEADER_NAME_COMPRESSION.get(header, header)
        if header in parsed:
            parsed[header] = u"%s %s" % (parsed[header], val)
        else:
            parsed[header] = val
        self.ctxt.log.debug(
            u'bayes: header tokens for %s = "%s"' % (header, parsed[header]))
        return header

    @staticmethod
    def _pre_chew_content_type(val):
        """Normalise the Content-Type header."""
        # Hopefully this will retain good bits without too many hapaxen.
        mo = re.search(r"""boundary=[\"\'](.*?)[\"\']""", val, re.I)
        if mo:
            # Replace all hex with literal "H".
            boundary = re.sub(r"[a-fA-F0-9]", "H", mo.groups()[0])
            # Break up blocks of separator chars so they become their own tokens.
            boundary = re.sub(r"([-_\.=]+)", " \1 ", boundary)
            val = val + boundary
        # Stop-list words for Content-Type header: these wind up totally grey.
        return re.sub(r"\b(?:text|charset)\b", "", val)

    @staticmethod
    def _pre_chew_message_id(val):
        """Normalise the Message-ID header."""
        # We can (a) get rid of a lot of hapaxen and (b) increase the token
        # specificity by pre-parsing some common formats.

        # Outlook Express format:
        val = re.sub(
            r"<([0-9a-f]{4})[0-9a-f]{4}[0-9a-f]{4}\$"
            r"([0-9a-f]{4})[0-9a-f]{4}\$"
            r"([0-9a-f]{8})\@(\S+)>",
            r" OEA\1 OEB\2 OEC\3 \4 ", val)

        # Exim:
        val = re.sub(r"<[A-Za-z0-9]{7}-[A-Za-z0-9]{6}-0[A-Za-z0-9]\@", "", val)

        # Sendmail:
        val = re.sub(r"<20\d\d[01]\d[0123]\d[012]\d[012345]"
                     r"\d[012345]\d\.[A-F0-9]{10,12}\@", "", val)

        # Try to split Message-ID segments on probable ID boundaries. Note that
        # Outlook message-ids seem to contain a server identifier ID in the last
        # 8 bytes before the @. Make sure this becomes its own token, it's a
        # great spam-sign for a learning system! Be sure to split on ".".
        val = re.sub(r"[^_A-Za-z0-9]", " ", val)
        return val

    @staticmethod
    def _pre_chew_received(val):
        # Thanks to Dan for these. Trim out "useless" tokens; sendmail-ish IDs
        # and valid-format RFC-822/2822 dates.
        val = re.sub(r"\swith\sSMTP\sid\sg[\dA-Z]{10,12}\s", " ", val)  # Sendmail
        val = re.sub(r"\swith\sESMTP\sid\s[\dA-F]{10,12}\s", " ", val)  # Sendmail
        val = re.sub(r"\bid\s[a-zA-Z0-9]{7,20}\b", " ", val)  # Sendmail
        val = re.sub(r"\bid\s[A-Za-z0-9]{7}-[A-Za-z0-9]{6}-0[A-Za-z0-9]",
                     " ", val)  # Exim

        val = re.sub(
            r"(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s)?"
            r"[0-3\s]?[0-9]\s"
            r"(?:Jan|Feb|Ma[ry]|Apr|Ju[nl]|Aug|Sep|Oct|Nov|Dec)\s"
            r"(?:19|20)?[0-9]{2}\s"
            r"[0-2][0-9](?:\:[0-5][0-9]){1,2}\s"
            r"(?:\s*\(|\)|\s*(?:[+-][0-9]{4})|\s*(?:UT|[A-Z]{2,3}T))*", "", val)

        # IPs: break down to nearest /24, to reduce hapaxes -- EXCEPT for
        # IPs in the 10 and 192.168 ranges, they gets lots of significant tokens
        # (on both sides).
        # Also make a dup with the full IP, as fodder for
        # bayes_dump_to_trusted_networks: "H*r:ip*aaa.bbb.ccc.ddd"
        # XXX It's complicated to do this with a regular expression in Python.
        # XXX It would probably be better to use ipaddress or similar to do
        # XXX it instead.

        # Trim these: they turn out as the most common tokens, but with a
        # prob of about 0.5. Waste of space!
        val = re.sub(r"\b(?:with|from|for|SMTP|ESMTP)\b", " ", val)
        return val

    def _pre_chew_addr_header(self, val):
        addrs = []
        for addr in self.find_all_addrs_in_line(val):
            addrs.extend(self._tokenise_mail_addrs(addr))
        return " ".join(addrs)

    @staticmethod
    def _tokenise_mail_addrs(addr):
        if "@" not in addr:
            return
        local, domain = addr.rsplit("@", 1)
        yield "U*%s" % local
        yield "D*%s" % domain
        while "." in domain:
            domain = domain.split(".", 1)[1]
            yield domain

    def check_bayes(self, msg, min_score, max_score=float('inf'), target=None):
        """Check the message against the active Bayes classifier."""
        min_score = float(min_score)
        max_score = float(max_score)
        if not self["use_learner"]:
            return False
        if not self["use_bayes"]:
            return False
        if not self["use_bayes_rules"]:
            return False

        # XXX SA has a timer here.
        bayes_score = self.scan(msg)
        if bayes_score and (min_score < bayes_score <= max_score):

            # TODO: Find test_log implementation.
            if self["detailed_bayes_score"]:
                pass
                # XXX This seems to append to the report output
                # XXX when the -t parameter is given
                # test_log("score: %3.4f, hits: %s" % (bayes_score, bayes_hits))
            else:
                pass
                # XXX This seems to append to the report output
                # XXX when the -t parameter is given
                # test_log("score: %3.4f" % bayes_score)
            return True
        return False

    def _compute_prob_for_all_tokens(self, tokensdata, ns, nn):
        """Compute the probability that a token is spammy for each
        token."""
        if not ns or not nn:
            return

        # Ignore low-freq tokens below this s+n threshold.
        threshold = 1
        if not USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS:
            threshold = 10
        if not self['bayes_use_hapaxes']:
            threshold = 2

        probabilities = []
        for tokendata in tokensdata:
            prob = None
            if tokendata:
                s = tokendata[1]  # spam count.
                n = tokendata[2]  # ham count.
                if s + n >= threshold:
                    # Ignoring low-freq tokens, also covers the (s==n==0) case.
                    # We want to calculate:
                    # ratio_s = s / ns
                    # ratio_n = n / nn
                    # prob = ratio_s / (ratio_n + ratio_s)
                    # This does the same thing, but faster.
                    prob = (s * nn) / (n * ns + s * nn)

                    if USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS:
                        # Use Robinson's f(x) equation for low-n tokens,
                        # instead of just ignoring them.
                        robn = s + n
                        prob = (FW_S_DOT_X + (robn * prob)) / (FW_S_CONSTANT + robn)
            probabilities.append(prob)
        return probabilities

    def _skip_scan(self, permsgstatus, score, caller_untie):
        if score is None:
            self.ctxt.log.debug("bayes: not scoring message, returning undef")
        # Do any cleanup we need to do.
        self.store.cleanup()

        # Reset the value accordingly.
        self.learn_caller_will_untie = caller_untie

        # If our caller won't untie the db, we need to do it.
        if not caller_untie:
            self.store.untie_db()
        return score

    def scan(self, msg):
        if not self["use_learner"]:
            return
        # When we're doing a scan, we'll guarantee that we'll do the untie,
        # so override the global setting until we're done.
        caller_untie = self.learn_caller_will_untie
        self.learn_caller_will_untie = True

        if self.ignore_message(msg):
            return self._skip_scan(msg, None, caller_untie)
        if not self.learner_is_scan_available():
            return self._skip_scan(msg, None, caller_untie)
        ns, nn = self.store.nspam_nham_get()
        self.ctxt.log.debug("bayes: corpus size: nspam = %s, nham = %s", ns, nn)
        # XXX This has a timer in SA.
        msgtokens = dict(t for t in self.tokenise(msg))
        tokensdata = list(d for d in self.store.tok_get_all(msgtokens) if d is not None)
        probabilities_ref = (ref for ref in self._compute_prob_for_all_tokens(tokensdata, ns, nn) if ref is not None)
        pw = {}
        for tokendata, prob in zip(tokensdata, probabilities_ref):
            if prob is None:
                continue
            token, tok_spam, tok_ham, atime = tokendata
            pw[token] = {"prob": prob, "spam_count": tok_spam,
                         "ham_count": tok_ham, "atime": atime}
        # If none of the tokens were found in the DB, we're going to skip
        # this message...
        if not pw:
            self.ctxt.log.debug("bayes: cannot use bayes on this message; "
                                "none of the tokens were found in the database")
            return self._skip_scan(msg, None, caller_untie)

        tcount_total = len(msgtokens)
        self.set_local(msg, "count", tcount_total)
        tcount_learned = len(pw)
        self.set_local(msg, "learned", tcount_learned)

        # Figure out the message receive time (used as atime below)
        # If the message atime comes back as being in the future, something's
        # messed up and we should revert to current time as a safety measure.
        msgatime = msg.receive_date
        now = time.time()
        if msgatime > now:
            msgatime = now

        tinfo_spammy = []
        self.set_local(msg, "bayes_token_info_spammy", tinfo_spammy)
        tinfo_hammy = []
        self.set_local(msg, "bayes_token_info_hammy", tinfo_hammy)

        tok_strength = {key: abs(value["prob"] - 0.5)
                        for key, value in pw.items()}

        # Now take the most significant tokens and calculate probs using
        # Robinson's formula.
        pw_keys = pw.keys()
        # XXX This is really inefficient.
        pw_keys = sorted(pw_keys, key=tok_strength.get)
        # pw_keys.sort(cmp=lambda a, b: tok_strength(b) > tok_strength(a))
        pw_keys = pw_keys[:N_SIGNIFICANT_TOKENS]

        sorted_tokens = []
        touch_tokens = []
        for tok in pw_keys:
            if tok_strength[tok] < MIN_PROB_STRENGTH:
                continue
            pw_tok = pw.get(tok)
            pw_prob = pw_tok["prob"]

            # What's more expensive, scanning headers for HAMMYTOKENS and
            # SPAMMYTOKENS tags that aren't there or collecting data that
            # won't be used?  Just collecting the data is certainly simpler.
            raw_token = msgtokens.get(tok.tobytes(), "(unknown)")
            s = pw_tok["spam_count"]
            n = pw_tok["ham_count"]
            a = pw_tok["atime"]

            if pw_prob < 0.5:
                tinfo_hammy.append((raw_token, pw_prob, s, n, a))
            else:
                tinfo_spammy.append((raw_token, pw_prob, s, n, a))

            sorted_tokens.append(pw_prob)

            # Update the atime on this token; it proved useful.
            touch_tokens.append(tok)

            self.ctxt.log.debug("bayes: token '%s' => %s", raw_token, pw_prob)

        if not sorted_tokens or (0 < len(sorted_tokens) <= REQUIRE_SIGNIFICANT_TOKENS_TO_SCORE):
            self.ctxt.log.debug("bayes: cannot use bayes on this message; "
                                "not enough usable tokens found")
            return self._skip_scan(msg, None, caller_untie)

        score = combine(ns, nn, sorted_tokens)
        if score is None:
            return self._skip_scan(msg, score, caller_untie)

        self.ctxt.log.debug("bayes: score = %s", score)

        # No need to call tok_touch_all unless there were significant
        # tokens and a score was returned.
        # We don't really care about the return value here.
        self.store.tok_touch_all(touch_tokens, msgatime)

        self.set_local(msg, "bayes_nspam", ns)
        self.set_local(msg, "bayes_nham", nn)

        return self._skip_scan(msg, score, caller_untie)

    def ignore_message(self, msg):
        """Checks if the message should be ignored
        :type msg: pad.message.Message
        :return: bool
        """
        if not self.use_ignores:
            return False

        # XXX Although it is possible to do this by calling the wlbleval plugin
        # XXX I think it's better if we copy that small function and not
        # XXX depend on it, or even better move the code somewhere common
        ig_from = self.check_address_in_list(msg.get_from_addresses(),
                                             "bayes_ignore_from")
        ig_to = self.check_address_in_list(msg.get_to_addresses(),
                                           "bayes_ignore_to")

        ignore = ig_from or ig_to

        if ignore:
            self.ctxt.log.debug("bayes: not using bayes, "
                                "bayes_ignore_from or _to rule")

        return ignore

    def _compute_prob_for_token(self, token, ns, nn, s, n):
        """Compute the probability that a token is spammy."""
        # We allow the caller to give us the token information, just
        # to save a potentially expensive lookup.
        if s is None or n is None:
            s, n = self.store.tok_get(token)[:2]
        if not s and not n:
            return
        probabilities_ref = self._compute_prob_for_all_tokens(
            [[token, s, n, 0]], ns, nn
        )
        return probabilities_ref[0]

    def _compute_declassification_distance(self, Ns, Nn, ns, nn, prob):
        """If a token is neither hammy nor spammy, return 0.
        For a spammy token, return the minimum number of additional ham
        messages it would have had to appear in to no longer be spammy.
        Hammy tokens are handled similarly.
        
        That's what the function does (at the time of this writing,
        31 July 2003, 16:02:55 CDT). It would be slightly more useful
        if it returned the number of /additional/ ham messages a spammy
        token would have to appear in to no longer be spammy but I fear
        that might require the solution to a cubic equation, and I just
        don't have the time for that now."""
        if ns == 0 and nn == 0:
            return 0

        if not USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS and (ns + nn) < 10:
            return 0
        if not self['bayes_use_hapaxes'] and ns + nn < 2:
            return 0

        if Ns == 0 or Nn == 0:
            return 0

        if abs(prob - 0.5) < MIN_PROB_STRENGTH:
            return 0

        Na, na, Nb, nb = (Nn, nn, Ns, ns) if prob > 0.5 else (Ns, ns, Nn, nn)
        p = 0.5 - MIN_PROB_STRENGTH

        if not USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS:
            return int(1.0 - 1e-6 + nb * Na * p / (Nb * (1 - p))) - na

        s = FW_S_CONSTANT
        sx = FW_S_DOT_X
        a = Nb * (1 - p)
        b = Nb * (sx + nb * (1 - p) - p * s) - p * Na * nb
        c = Na * nb * (sx - p * (s + nb))
        discrim = b * b - 4 * a * c
        disc_max_0 = 0 if discrim < 0 else discrim
        dd_exact = (1.0 - 1e-6 + (-b + math.sqrt(disc_max_0)) / (2 * a)) - na

        # This shouldn't be necessary. Should not be < 1.
        return 1 if dd_exact < 1 else int(dd_exact)

    def bayes_report_make_list(self, msg, info, param=None):
        if not info:
            return "Tokens not available."

        limit, ftm_arg, more = (param or "5,,").split(",")

        # f strings would have been nice here
        formats = {
            "short": "{t}",
            "Short": 'Token: "{t}"',
            "compact": "{p}-{D}--{t}",
            "Compact": 'Probability {p} -declassification distance {D} '
                       '("+" means > 9) --token: "{t}"',
            "medium": "{p}-{D}-{N}--{t}",
            "long": "{p}-{d}--{h}h-{s}s--{a}d--{t}",
            "Long": 'Probability {p} -declassification distance {D} --in {h} '
                    'ham messages -and {s} spam messages --{a} days old'
                    '--token:"{t}"'
        }

        try:
            fmt = formats[ftm_arg] if ftm_arg else "{p}-{D}--{t}"
        except KeyError:
            return "Invalid format, must be one of: %s" % (",".join(formats))

        amt = min((int(limit), len(info)))
        if not amt:
            return ""

        ns = self.get_local(msg, 'bayes_nspam')
        nh = self.get_local(msg, 'bayes_nham')
        now = time.time()

        def f(token, prob, spam_count, ham_count, atime):
            a = int((now - atime) / (3600 * 24))
            d = self._compute_declassification_distance(ns, nh, spam_count, ham_count, prob)
            p = "%.3f" % prob
            n = spam_count + ham_count
            if prob < 0.5:
                c = ham_count
                o = spam_count
            else:
                c = spam_count
                o = ham_count
            D,S,H,C,O,N = (float(x) for x in (d,spam_count,ham_count,c,o,n))
            return fmt.format(D=D, S=S, H=H, C=C, O=O, N=N,
                              s=spam_count, p=p, h=ham_count, t=token)

        return ", ".join(f(*x) for x in info)
