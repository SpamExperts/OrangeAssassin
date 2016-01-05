"""Rules that check email headers."""

import pad.regex
import pad.rules.base


class MimeHeaderRule(pad.rules.base.BaseRule):
    """Abstract class for all MIME header rules."""
    _rule_type = "BODY: "

    def match(self, msg):
        raise NotImplementedError()

    @classmethod
    def get_rule(cls, name, data):
        kwargs = cls.get_rule_kwargs(data)
        value = data["value"].strip()

        match_op = None
        if "=~" in value:
            match_op = "=~"
        elif "!~" in value:
            match_op = "!~"

        header_name, pattern = value.split(match_op, 1)
        header_name = header_name.strip()
        kwargs["pattern"] = pad.regex.perl2re(pattern, match_op)
        if ":" in header_name:
            header_name, mod = header_name.rsplit(":", 1)
            kwargs["header_name"] = header_name.strip()
            if mod == "raw":
                return _PatternMimeRawHeaderRule(name, **kwargs)
        else:
            kwargs["header_name"] = header_name.strip()
            return _PatternMimeHeaderRule(name, **kwargs)


class _PatternMimeHeaderRule(MimeHeaderRule):
    """Matches a MIME header by name and a regular expression for the value.
    The headers are decoded, and the header name is NOT included.
    """
    def __init__(self, name, pattern=None, header_name=None, score=None,
                 desc=None):
        super(_PatternMimeHeaderRule, self).__init__(name, score=score,
                                                     desc=desc)
        self._header_name = header_name
        self._pattern = pattern

    def match(self, msg):
        for value in msg.get_decoded_mime_header(self._header_name):
            if self._pattern.match(value):
                return True
        return False


class _PatternMimeRawHeaderRule(_PatternMimeHeaderRule):
    """Matches a header by name and a regular expression for the value. The
    headers are NOT decoded, and the header name is NOT included.
    """
    def match(self, msg):
        for value in msg.get_raw_mime_header(self._header_name):
            if self._pattern.match(value):
                return True
        return False


class HeaderRule(pad.rules.base.BaseRule):
    """Abstract base class for all header rules."""
    def match(self, msg):
        raise NotImplementedError()

    @classmethod
    def get_rule(cls, name, data):
        kwargs = cls.get_rule_kwargs(data)
        value = data["value"]

        match_op = None
        if "=~" in value:
            match_op = "=~"
        elif "!~" in value:
            match_op = "!~"

        if match_op is not None:
            header_name, pattern = value.split(match_op, 1)
            header_name = header_name.strip()
            kwargs["pattern"] = pad.regex.perl2re(pattern, match_op)
            if header_name == "ALL":
                return _AllHeaderRule(name, **kwargs)
            if header_name == "ToCc":
                return _ToCcHeaderRule(name, **kwargs)
            if header_name == "MESSAGEID":
                return _MessageIDHeaderRule(name, **kwargs)

            if ":" in header_name:
                header_name, mod = header_name.rsplit(":", 1)
                kwargs["header_name"] = header_name.strip()
                if mod == "raw":
                    return _PatternRawHeaderRule(name, **kwargs)
                if mod == "addr":
                    return _PatternAddrHeaderRule(name, **kwargs)
                if mod == "name":
                    return _PatternNameHeaderRule(name, **kwargs)
            else:
                kwargs["header_name"] = header_name.strip()
                return _PatternHeaderRule(name, **kwargs)
        elif value.startswith("exists:"):
            kwargs["header_name"] = value.lstrip("exists:").strip()
            return _ExistsHeaderRule(name, **kwargs)


class _ExistsHeaderRule(HeaderRule):
    """Simple check if header exists."""
    def __init__(self, name, header_name, score=None, desc=None):
        HeaderRule.__init__(self, name, score=score, desc=desc)
        self._header_name = header_name

    def match(self, msg):
        return self._header_name in msg.raw_headers


class _PatternHeaderRule(HeaderRule):
    """Matches a header by name and a regular expression for the value. The
    headers are decoded, and the header name is NOT included.
    """
    def __init__(self, name, pattern=None, header_name=None, score=None,
                 desc=None):
        super(_PatternHeaderRule, self).__init__(name, score=score, desc=desc)
        self._header_name = header_name
        self._pattern = pattern

    def match(self, msg):
        for value in msg.get_decoded_header(self._header_name):
            if self._pattern.match(value):
                return True
        return False


class _PatternRawHeaderRule(_PatternHeaderRule):
    """Matches a header by name and a regular expression for the value. The
    headers are NOT decoded, and the header name is NOT included.
    """
    def match(self, msg):
        for value in msg.get_raw_header(self._header_name):
            if self._pattern.match(value):
                return True
        return False


class _PatternAddrHeaderRule(_PatternHeaderRule):
    """Matches a header by name and a regular expression for the value. The
    value checked is the first address that appears in the header's value.
    """
    def match(self, msg):
        for value in msg.get_addr_header(self._header_name):
            if self._pattern.match(value):
                return True
        return False


class _PatternNameHeaderRule(_PatternHeaderRule):
    """Matches a header by name and a regular expression for the value. The
    value checked is the first name that appears in the header's value.
    """
    def match(self, msg):
        for value in msg.get_name_header(self._header_name):
            if self._pattern.match(value):
                return True
        return False


class _MultiplePatternHeaderRule(HeaderRule):
    """Does a simple pattern check against multiple decoded headers."""
    _headers = None

    def __init__(self, name, pattern, score=None, desc=None):
        HeaderRule.__init__(self, name, score=score, desc=desc)
        self._pattern = pattern

    def match(self, msg):
        for header_name in self._headers or ():
            for value in msg.get_decoded_header(header_name):
                if self._pattern.match(value):
                    return True
        return False


class _ToCcHeaderRule(_MultiplePatternHeaderRule):
    """Matches the To and Cc headers by  a regular expression. The headers are
    decoded, and the header name is NOT included.
    """
    _headers = ("To", "Cc")


class _MessageIDHeaderRule(_MultiplePatternHeaderRule):
    """Matches various MessageID headers by  a regular expression. The headers
    are decoded, and the header name is NOT included.
    """
    _headers = ("Message-Id", "Resent-Message-Id", "X-Message-Id")


class _AllHeaderRule(HeaderRule):
    """Matches the pattern against all headers. In this case the header
    name IS included in the search, and headers are decoded.
    """
    def __init__(self, name, pattern, score=None, desc=None):
        HeaderRule.__init__(self, name, score=score, desc=desc)
        self._pattern = pattern

    def match(self, msg):
        for header in msg.iter_decoded_headers():
            if self._pattern.match(header):
                return True
        return False
