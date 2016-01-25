"""Detect the language of the message.

Current available languages:

af ar bg bn ca cs cy da de el en es et fa fi fr gu
he hi hr hu id it ja kn ko lt lv mk ml mr ne nl no
pa pl pt ro ru sk sl so sq sv sw ta te th tl tr uk
ur vi zh-cn zh-tw
"""

from __future__ import absolute_import

import pad.errors

try:
    import langdetect
except ImportError:
    raise pad.errors.PluginLoadError(
            "TextCat not loaded. You must install langdetect to use this "
            "plugin")

import pad.plugins.base


class TextCatPlugin(pad.plugins.base.BasePlugin):
    """This plugin will detect the language of the
    message.
    """
    options = {
        "ok_languages": ("list", "all"),
        "textcat_max_languages": ("int", 5),
        "textcat_acceptable_prob": ("float", 0.70),
        # The rest of these are not used, and are
        # just here for backwards compatibility
        # XXX We should add a warning here if these
        # XXX are used.
        "inactive_languages": ("list", ""),
        "textcat_optimal_ngrams": ("int", 0),
        "textcat_max_ngrams": ("int", 400),
        # We cannot really apply this with our method here.
        # We use the probability config.
        "textcat_acceptable_score": ("float", 1.05),
    }
    eval_rules = ("check_language",)

    def set_list_option(self, global_key, value, separator=None):
        super(TextCatPlugin, self).set_list_option(global_key, value,
                                                   separator)

    def check_language(self, msg, target=None):
        """Check the language of the message.

        Add the result to the metadata and and trigger the
        rule if it is present in the config and the languages
        are not in the ok list.

        :return True if the message language is unwanted and False
        otherwise
        """
        prob = self.get_global("textcat_acceptable_prob")
        langs = [lang.lang for lang in langdetect.detect_langs(msg.body)
                 if lang.prob > prob]
        if len(langs) > self.get_global("textcat_max_languages"):
            self.ctxt.dbg("Too many languages.")
            return False
        msg.plugin_tags["LANGUAGES"] = " ".join(langs)
        ok_languages = self.get_global("ok_languages")
        if "all" in ok_languages:
            # All good.
            return False
        for lang in langs:
            if lang not in ok_languages:
                return True
        return False
