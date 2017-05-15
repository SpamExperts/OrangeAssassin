"""Plugin that doesn't do anything. Can be used to silence warnings."""

from __future__ import print_function, absolute_import


import oa.plugins.base


class NoOPPlugin(oa.plugins.base.BasePlugin):
    options = {}


class MIMEHeaderPlugin(NoOPPlugin):
    """This has been integrated into the main core, so no need
    for an separate plugin.
    """
    options = {}


class CheckPlugin(NoOPPlugin):
    """This has been integrated into the main core, so no need
    for an separate plugin.
    """
    options = {}
