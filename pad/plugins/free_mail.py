"""
FreeMail Plugin
The FreeMail plugin checks the headers for indication
that sender's domain is that of a site offering free email services.
"""

import re
import pad.plugins.base


EMAIL_WHITELIST = re.compile(r"""
  ^(?:
      abuse|support|sales|info|helpdesk|contact|kontakt
    | (?:post|host|domain)master
    | undisclosed.*			# yahoo.com etc(?)
    | request-[a-f0-9]{16}		# live.com
    | bounced?-				# yahoo.com etc
    | [a-f0-9]{8}(?:\.[a-f0-9]{8}|-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}) # gmail msgids?
    | .+=.+=.+				# gmail forward
  )\@
""", re.X | re.I)
SKIP_REPLYTO_FROM = re.compile(r"""
  (?:
      ^(?:post|host|domain)master
    | ^double-bounce
    | ^(?:sentto|owner|return|(?:gr)?bounced?)-.+
    | -(?:request|bounces?|admin|owner)
    | \b(?:do[._-t]?)?no[._-t]?repl(?:y|ies)
    | .+=.+
  )\@
""", re.X | re.I)


class FreeMail(pad.plugins.base.BasePlugin):
    eval_rules = (
        "check_freemail_replyto",
        "check_freemail_from",
        "check_freemail_header",
        "check_freemail_body"
    )
    options = {
        "freemail_max_body_emails": ("int", 5),
        "freemail_max_body_freemails": ("int", 3),
        "freemail_skip_when_over_max": ("bool", True),
        "freemail_skip_bulk_envfrom": ("bool", True),
        "freemail_add_describe_email": ("bool", True),
        "freemail_domains": ("append_split", []),
        "freemail_whitelist": ("append_split", []),
        "util_rb_tld": ("append_split", []),
        "util_rb_2tld": ("append_split", []),
        "util_rb_3tld": ("append_split", [])
    }

    def check_start(self, msg):
        """Verify if the domains are valid and
        separate wildcard domains from the rest"""
        domain_re = re.compile(r'^[a-z0-9.*?-]+$')
        freemail_domains = self.get_global('freemail_domains')
        freemail_temp_wc = list()
        for index, domain in enumerate(freemail_domains):
            if not domain_re.search(domain):
                freemail_domains.remove(domain)
                self.ctxt.log.warn("FreeMail::Plugin Invalid freemail domain: %s", domain)
            if '*' in domain:
                temp = domain.replace('.', '\.')
                temp = temp.replace('?', '.')
                temp = temp.replace('*', '[^.]*')
                freemail_temp_wc.append(temp)
        if freemail_temp_wc:
            wild_doms = r'\@(?:{0})$'.format('|'.join(freemail_temp_wc))
            self.set_global('freemail_domains_re', re.compile(wild_doms))
        self.set_global('freemail_domains', freemail_domains)
        valid_tlds = (self.get_global('util_rb_tld') +
                      self.get_global('util_rb_2tld') +
                      self.get_global('util_rb_3tld'))
        tlds_re = r'(?:{0})'.format("|".join(valid_tlds))
        email_re = re.compile(r"""
              (?=.{{0,64}}\@)				# limit userpart to 64 chars (and speed up searching?)
              (?<![a-z0-9!#\$%&'*+\/=?^_`{{|}}~-])	# start boundary
              (						# capture email
              [a-z0-9!#\$%&'*+\/=?^_`{{|}}~-]+		# no dot in beginning
              (?:\.[a-z0-9!#\$%&'*+\/=?^_`{{|}}~-]+)*	# no consecutive dots, no ending dot
              \@
              (?:[a-z0-9](?:[a-z0-9-]{{0,59}}[a-z0-9])?\.){{1,4}} # max 4x61 char parts (should be enough?)
              {tld}   # ends with valid tld
              )
              (?!(?:[a-z0-9-]|\.[a-z0-9]))		# make sure domain ends here
        """.format(tld=tlds_re), re.X|re.I)
        self.set_global('email_re', email_re)
        self.set_global('body_emails', set())
        self.set_global("check_if_parsed", False)

    def extract_metadata(self, msg, payload, text, part):
        """Parse all emails from text/plain and text/html parts
        """
        if part.get_content_type() in ("text/plain", "text/html"):
            body_emails = self.get_global('body_emails')
            for email in self.get_global('email_re').findall(part.get_payload()):
                body_emails.add(email)
            self.set_global('body_emails', body_emails)

    def check_freemail_replyto(self, msg, option=None, target=None):
        """Checks/compares freemail addresses found from headers and body
        Possible options:
            - replyto	From: or body address is different than Reply-To
                        (this is the default)
            - reply     as above, but if no Reply-To header is found,
                        compares From: and body
        """
        if option and option not in ('replyto', 'reply'):
            self.ctxt.log.warn("FreeMail::Plugin check_freemail_replyto"
                               " invalid option: %s", option)
            return False
        elif not option:
            option = 'replyto'
        if self.get_global('freemail_skip_bulk_envfrom'):
            header_emails = self.get_global('email_re').findall(msg.msg['EnvelopeFrom'] or '')
            for email in header_emails:
                if SKIP_REPLYTO_FROM.search(email):
                    self.ctxt.log.warn("FreeMail::Plugin check_freemail_replyto"
                                       " envelope sender looks bulk skipping "
                                       "check: %s", email)
                    return False
        try:
            from_email = self.get_global('email_re').search(msg.msg['From']).group()
        except (AttributeError, TypeError, KeyError):
            from_email = ''
        try:
            reply_to = self.get_global('email_re').search(msg.msg['Reply-To']).group()
        except (AttributeError, TypeError, KeyError):
            reply_to = ''
        from_email_frm = self._is_freemail(from_email)
        reply_to_frm = self._is_freemail(reply_to)
        if (from_email_frm and reply_to_frm and
                from_email != reply_to):
            self.ctxt.log.warn("FreeMail::Plugin check_freemail_replyto"
                               " HIT! From and Reply-To are different freemails")
            return True
        if option == 'replyto' and not reply_to_frm:
            self.ctxt.log.warn("FreeMail::Plugin check_freemail_replyto"
                               " Reply-To is not freemail, skipping check")
            return False
        elif option == 'reply':
            if reply_to and not reply_to_frm:
                self.ctxt.log.warn("FreeMail::Plugin check_freemail_replyto"
                                   " Reply-To is defined but is not freemail, "
                                   "skipping check")
                return False
            elif not from_email_frm:
                self.ctxt.log.warn("FreeMail::Plugin check_freemail_replyto"
                                   " No Reply-To and From is not freemail, "
                                   "skipping check")
                return False
        if not self._parse_body():
            return False
        reply = reply_to if reply_to_frm else from_email
        check = reply_to if option == 'replyto' else reply
        for email in self.get_global("freemail_body_emails"):
            if email != check:
                self.ctxt.log.warn("FreeMail::Plugin check_freemail_replyto"
                                   " HIT! %s and %s are different freemails",
                                   check, email)
                return True
        return False

    def check_freemail_from(self, msg, regex=None, target=None):
        """Check if in specified header gave as parameter
        is a freemail or no. It is possible to provide a regex
        rule to match against too.

        Returns True if it is or False otherwise
        """
        self.ctxt.log.debug("FreeMail::Plugin Eval rule check_freemail_from"
                            " %s", 'with regex: ' + regex if regex else '')
        all_from_headers = ['From', 'Envelope-Sender',
                            'Resent-Sender', 'X-Envelope-From',
                            'EnvelopeFrom', 'Resent-From']
        header_emails = []
        if regex:
            try:
                check_re = re.compile(regex)
            except re.error:
                self.ctxt.log.warn("FreeMail::Plugin check_freemail_from"
                                   " regex error")
                return False
        else:
            check_re = None

        for header in all_from_headers:
            if msg.msg.get(header, None):
                header_emails = header_emails + self.get_global('email_re').findall(msg.msg[header])
        header_emails = sorted(set(header_emails))
        if not header_emails:
            self.ctxt.log.debug("FreeMail::Plugin check_freemail_from"
                                " no emails found in from headers: %s",
                                all_from_headers)
            return False
        for email in header_emails:
            if self._is_freemail(email):
                if check_re and not check_re.search(email):
                    return False
                elif check_re and check_re.search(email):
                    self.ctxt.log.debug("FreeMail::Plugin check_freemail_from"
                                        " HIT! %s is freemail and matches regex", email)
                    return True
                self.ctxt.log.debug("FreeMail::Plugin check_freemail_from"
                                    " HIT! %s is freemail", email)
                return True
        return False

    def check_freemail_header(self, msg, header, regex=None, target=None):
        """Check all possible 'from' headers to see if sender
        is freemail. It is possible to provide a regex
        rule to match against too.

        Returns True if it is or False otherwise
        """
        self.ctxt.log.debug("FreeMail::Plugin check_freemail_header"
                            " %s", 'with regex: ' + regex if regex else '')
        if not header:
            self.ctxt.log.warn("FreeMail::Plugin check_freemail_header"
                               " requires an argument")
            return False
        if regex:
            try:
                check_re = re.compile(regex)
            except re.error:
                self.ctxt.log.warn("FreeMail::Plugin check_freemail_header"
                                   " regex error")
                return False
        else:
            check_re = None
        if not msg.msg.get(header, None):
            self.ctxt.log.debug("FreeMail::Plugin check_freemail_header"
                                " header: %s not found", header)
            return False
        header_emails = self.get_global('email_re').findall(msg.msg[header])
        if not header_emails:
            self.ctxt.log.debug("FreeMail::Plugin check_freemail_header"
                                " no emails found in header: %s", header)
            return False
        for email in header_emails:
            if self._is_freemail(email):
                if check_re and not check_re.search(email):
                    return False
                elif check_re and check_re.search(email):
                    self.ctxt.log.debug("FreeMail::Plugin check_freemail_header"
                                        " HIT! %s is freemail and matches regex", email)
                    return True
                self.ctxt.log.debug("FreeMail::Plugin check_freemail_header"
                                    " HIT! %s is freemail", email)
                return True
        return False

    def check_freemail_body(self, msg, regex=None, target=None):
        """
        Check if there are free emails in body parts
        of the message
        """
        self.ctxt.log.debug("FreeMail::Plugin check_freemail_body"
                            " %s", 'with regex: ' + regex if regex else '')
        body_emails = self.get_global('body_emails')
        if not len(body_emails):
            self.ctxt.log.debug("FreeMail::Plugin check_freemail_body "
                                "No emails found in body of the message")
            return False
        if regex:
            try:
                check_re = re.compile(regex)
            except re.error:
                self.ctxt.log.warn("FreeMail::Plugin check_freemail_from"
                                   " regex error")
                return False
        else:
            check_re = None
        if not self._parse_body():
            return False
        if check_re:
            for email in self.get_global("freemail_body_emails"):
                if check_re.search(email):
                    self.ctxt.log.debug("FreeMail::Plugin check_freemail_body"
                                        " HIT! %s is freemail and matches regex", email)
                    return True
        else:
            if len(self.get_global("freemail_body_emails")):
                emails = " ,".join(self.get_global("freemail_body_emails"))
                self.ctxt.log.debug("FreeMail::Plugin check_freemail_body"
                                    " HIT! body has freemails: %s", emails)
                return True
        return False

    def _parse_body(self):
        """Parse all the emails from body and check
        if all conditions are accepted
        """
        if self.get_global("check_if_parsed"):
            return True
        body_emails = self.get_global('body_emails')
        freemail_body_emails = []
        if (len(body_emails) >= self.get_global("freemail_max_body_emails") and
                not self.get_global("freemail_skip_when_over_max")):
            self.ctxt.log.debug("FreeMail::Plugin check_freemail_body "
                                "too many unique emails found in body")
            return False
        freemail_count = 0
        for email in body_emails:
            if self._is_freemail(email):
                freemail_count += 1
                freemail_body_emails.append(email)
            if freemail_count == self.get_global("freemail_max_body_freemails"):
                self.ctxt.log.debug("FreeMail::Plugin check_freemail_body "
                                    "too many unique free emails found in body")
                return False
        self.set_global("freemail_body_emails", freemail_body_emails)
        self.set_global("check_if_parsed", True)
        return True

    def _is_freemail(self, email):
        """Check if the email is in freemail_domains list
        If the email is whitelisted than we skip the check
        """
        if not email:
            return False
        email_domain = email.rsplit('@')[1]
        try:
            freemail_re = self.get_global('freemail_domains_re')
        except KeyError:
            freemail_re = None
        freemail_whitelist = self.get_global('freemail_whitelist')
        freemail_domains = self.get_global('freemail_domains')

        if email in freemail_whitelist:
            self.ctxt.log.warn("FreeMail::Plugin whitelisted email: %s", email)
            return False
        if email_domain in freemail_whitelist:
            self.ctxt.log.warn("FreeMail::Plugin whitelisted domain: %s", email_domain)
            return False
        if EMAIL_WHITELIST.search(email):
            self.ctxt.log.warn("FreeMail::Plugin whitelisted domain, default: %s", email_domain)
            return False
        if (email_domain in freemail_domains or
                (freemail_re and freemail_re.search(email))):
            return True
        return False
