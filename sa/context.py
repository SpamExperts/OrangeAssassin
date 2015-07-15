"""Defines global and per-message context."""

from builtins import dict
from builtins import object

from future import standard_library
standard_library.install_hooks()

try:
    import importlib.machinery
except ImportError:
    pass

import os
import imp
import logging
import importlib
import collections

import future.utils

import sa.errors
import sa.plugins.base


class _Context(object):
    """Base class for all context types."""

    def __init__(self):
        self.plugin_data = collections.defaultdict(dict)
        self.log = logging.getLogger("sa-logger")

    def set_plugin_data(self, plugin_name, key, value):
        """Store data for the specified plugin under the given key."""
        self.plugin_data[plugin_name][key] = value

    def get_plugin_data(self, plugin_name, key=None):
        """Get data for the specified plugin under the given key. Raises
        KeyError if no data is found.

        If no key is given return a dictionary with all the data stored for
        this plugin.
        """
        if key is None:
            return self.plugin_data[plugin_name]
        return self.plugin_data[plugin_name][key]

    def del_plugin_data(self, plugin_name, key=None):
        """Delete data for the specified plugin under the given key. Raises
        KeyError if no data is found.

        If no key is given delete all the data stored for this plugin.
        """
        if key is None:
            del self.plugin_data[plugin_name]
        else:
            del self.plugin_data[plugin_name][key]

    def pop_plugin_data(self, plugin_name, key=None):
        """Extract and remove data for the specified plugin under the given key.
        Returns None if no data is found.

        If no key is given delete all the data stored for this plugin.
        """
        if key is None:
            return self.plugin_data.pop(plugin_name, None)
        return self.plugin_data[plugin_name].pop(key, None)


def _callback_chain(func):
    """Decorate the function as a callback chain ignores any InhibitCallbacks
    exceptions.
    """
    def wrapped_func(*args, **kwargs):
        """Ignore any InhibitCallbacks exceptions."""
        try:
            func(*args, **kwargs)
        except sa.errors.InhibitCallbacks:
            return True
        return False
    return wrapped_func


class GlobalContext(_Context):
    """Context available globally."""

    def __init__(self):
        super(GlobalContext, self).__init__()
        self.plugins = dict()
        self.eval_rules = dict()

    def load_plugin(self, name, path=None):
        """Load the specified plugin from the given path."""
        class_name = name.rsplit(".", 1)[-1]
        if class_name in self.plugins:
            self.log.warning("Redefining plugin %s.", class_name)
            self.unload_plugin(class_name)

        if path is None:
            # The plugin should be sys.path already
            module_name, class_name = name.rsplit(".", 1)
            try:
                module = importlib.import_module(module_name)
            except ImportError as e:
                raise sa.errors.PluginLoadError("Unable to load %s: %s" %
                                                (module_name, e))
        elif future.utils.PY3:
            module = self._load_module_py3(path)
        else:
            module = self._load_module_py2(path)

        plugin_class = getattr(module, class_name)
        if plugin_class is None:
            raise sa.errors.PluginLoadError("Missing plugin %s in %s" %
                                            (class_name, path))
        if not issubclass(plugin_class, sa.plugins.base.BasePlugin):
            raise sa.errors.PluginLoadError("%s is not a subclass of "
                                            "BasePlugin" % class_name)
        plugin = plugin_class(self)

        for rule in plugin.eval_rules:
            if rule in self.eval_rules:
                self.log.warning("Redefining eval rule: %s", rule)
            eval_rule = getattr(plugin, rule)
            if eval_rule is None:
                raise sa.errors.PluginLoadError("Undefined eval rule %s in "
                                                "%s" % (rule, class_name))
            self.eval_rules[rule] = eval_rule

        self.plugins[class_name] = plugin

    def unload_plugin(self, name):
        """Unload the specified plugin and remove any data stored in this
        context.
        """
        if name not in self.plugins:
            raise sa.errors.PluginLoadError("Plugin %s not loaded." % name)

        plugin = self.plugins[name]
        # Delete any defined rules
        for rule in plugin.eval_rules:
            self.eval_rules.pop(rule, None)
        self.pop_plugin_data(name)
        del self.plugins[name]

    @staticmethod
    def _load_module_py3(path):
        """Load module in Python 3."""
        modulename = os.path.basename(path).rstrip(".py").rstrip(".pyc")

        loader = importlib.machinery.SourceFileLoader(modulename, path)
        return loader.load_module()

    @staticmethod
    def _load_module_py2(path):
        """Load module in Python 2."""
        modulename = os.path.basename(path).rstrip(".py").rstrip(".pyc")

        for suffix, open_type, file_type in imp.get_suffixes():
            if path.endswith(suffix):
                with open(path, open_type) as sourcef:
                    return imp.load_module(modulename, sourcef, path,
                                           (suffix, open_type, file_type))
        raise sa.errors.PluginLoadError("Unable to load module %s from %s" %
                                        (modulename, path))

    @_callback_chain
    def hook_parse_config(self, key, value):
        """Hook for the parsing configuration files."""
        for plugin in self.plugins.values():
            if plugin.parse_config(key, value):
                break

    @_callback_chain
    def hook_parsing_end(self, ruleset):
        """Hook after the parsing has finished."""
        for plugin in self.plugins.values():
            plugin.finish_parsing_end(ruleset)

    @_callback_chain
    def hook_check_end(self, msg):
        """Hook after the message is checked."""
        for plugin in self.plugins.values():
            plugin.check_end(msg)

    @_callback_chain
    def hook_report(self, msg):
        """Hook when the message should be reported as spam."""
        for plugin in self.plugins.values():
            plugin.plugin_report(msg)

    @_callback_chain
    def hook_revoke(self, msg):
        """Hook when the message should be reported as ham."""
        for plugin in self.plugins.values():
            plugin.plugin_revoke(msg)


class MessageContext(_Context):
    """Per-message context."""

    def __init__(self, _global_context):
        super(MessageContext, self).__init__()
        self._global_ctxt = _global_context

    @_callback_chain
    def _hook_check_start(self):
        """Hook before the message is checked."""
        for plugin in self._global_ctxt.plugins.values():
            plugin.check_start(self)

    @_callback_chain
    def _hook_extract_metadata(self, payload, part):
        """Hook before the message is checked."""
        for plugin in self._global_ctxt.plugins.values():
            plugin.extract_metadata(self, payload, part)
