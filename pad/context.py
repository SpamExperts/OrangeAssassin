"""Defines global and per-message context."""

from builtins import dict
from builtins import object

import sys

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

import pad.errors
import pad.rules.base
import pad.plugins.base


class _Context(object):
    """Base class for all context types."""

    def __init__(self):
        self.plugin_data = collections.defaultdict(dict)
        self.log = logging.getLogger("pad-logger")

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
        except pad.errors.InhibitCallbacks:
            return True
        return False

    return wrapped_func


class GlobalContext(_Context):
    """Context available globally.

    Stores the global plugin data currently loaded including:
     * plugins - the actual code loaded
     * eval_rules - the methods for the "eval" rules currently
      defined
     * cmds - additional RULES that are handled by plugins.
      This maps the rule type (e.g. "body") to the Rule class.
      These must inherit from pad.rules.base.BaseRule.
    """

    def __init__(self, paranoid=False, ignore_unknown=True):
        super(GlobalContext, self).__init__()
        self.plugins = dict()
        self.paranoid = paranoid
        self.ignore_unknown = ignore_unknown
        self.eval_rules = dict()
        self.cmds = dict()

    def err(self, *args, **kwargs):
        """Log a error according to the paranoid and
        ignore_unknown.

        If paranoid is True the log to ERROR, if the
        ignore_unknown flag is set to False the log
        to WARN and to DEBUG otherwise.
        """
        if self.paranoid:
            self.log.error(*args, **kwargs)
        elif not self.ignore_unknown:
            self.log.warn(*args, **kwargs)
        else:
            self.log.debug(*args, **kwargs)

    def load_plugin(self, name, path=None):
        """Load the specified plugin from the given path."""
        self.log.debug("Loading plugin %s from %s", name, path)
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
                raise pad.errors.PluginLoadError("Unable to load %s: %s" %
                                                 (module_name, e))
        elif sys.version_info[0] == 3 and sys.version_info[1] > 2:
            # For Python 3.3+
            module = self._load_module_py3(path)
        else:
            # For Python 2 and < 3.3
            module = self._load_module_py2(path)

        plugin_class = getattr(module, class_name)
        if plugin_class is None:
            raise pad.errors.PluginLoadError("Missing plugin %s in %s" %
                                             (class_name, path))
        if not issubclass(plugin_class, pad.plugins.base.BasePlugin):
            raise pad.errors.PluginLoadError("%s is not a subclass of "
                                             "BasePlugin" % class_name)
        # Initialize the plugin and load any additional data
        plugin = plugin_class(self)
        self._load_cmds(plugin, class_name)
        self._load_eval_rules(plugin, class_name)
        self.log.info("Plugin %s loaded", name)
        # Store the plugin instance in the dictionary
        self.plugins[class_name] = plugin

    def _load_eval_rules(self, plugin, class_name):
        """Get all the eval rules defined by this plugin and store
        a reference in the eval_rules dictionary.
        """
        for rule in plugin.eval_rules:
            self.log.debug("Registering eval rule: %s.%s", class_name, rule)
            if rule in self.eval_rules:
                self.log.warning("Redefining eval rule: %s", rule)
            eval_rule = getattr(plugin, rule)
            if eval_rule is None:
                raise pad.errors.PluginLoadError("Undefined eval rule %s in "
                                                 "%s" % (rule, class_name))
            self.eval_rules[rule] = eval_rule

    def _load_cmds(self, plugin, class_name):
        """Load any new RULES that are handled by this plugin. These
        must inherit from pad.rules.base.BaseRule.
        """
        if not plugin.cmds:
            return
        for rule_type, rule_class in plugin.cmds.items():
            self.log.debug("Registering CMD rule: %s.%s", class_name,
                           rule_type)
            if rule_type in self.cmds:
                self.log.warning("Redefining CMD rule: %s", rule_type)
            if not issubclass(rule_class, pad.rules.base.BaseRule):
                raise pad.errors.PluginLoadError("%s is not a subclass of "
                                                 "BasePlugin" % class_name)
            self.cmds[rule_type] = rule_class

    def unload_plugin(self, name):
        """Unload the specified plugin and remove any data stored in this
        context.
        """
        if name not in self.plugins:
            raise pad.errors.PluginLoadError("Plugin %s not loaded." % name)

        plugin = self.plugins[name]
        # Delete any defined rules
        for rule in plugin.eval_rules:
            self.eval_rules.pop(rule, None)
        for rule_type in plugin.cmds or ():
            self.cmds.pop(rule_type, None)
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
        raise pad.errors.PluginLoadError("Unable to load module %s from %s" %
                                         (modulename, path))

    @_callback_chain
    def hook_parse_config(self, key, value):
        """Hook for the parsing configuration files."""
        for plugin in self.plugins.values():
            if plugin.parse_config(key, value):
                break

    @_callback_chain
    def hook_parsing_start(self, results):
        """Hook after the parsing has finished but the ruleset
        is not initialized.
        """
        for plugin in self.plugins.values():
            plugin.finish_parsing_start(results)

    @_callback_chain
    def hook_parsing_end(self, ruleset):
        """Hook after the parsing has finished but and the
        rulest is initialized.
        """
        for plugin in self.plugins.values():
            plugin.finish_parsing_end(ruleset)

    @_callback_chain
    def hook_check_end(self, ruleset, msg):
        """Hook after the message is checked."""
        for plugin in self.plugins.values():
            plugin.check_end(ruleset, msg)

    @_callback_chain
    def hook_report(self, msg, spam=True, local=True, remote=True):
        """Hook when the message should be reported as spam."""
        for plugin in self.plugins.values():
            plugin.plugin_report(msg)

    @_callback_chain
    def hook_revoke(self, msg, spam=False, local=True, remote=True):
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

    @_callback_chain
    def _hook_parsed_metadata(self):
        """Hook before the message is checked."""
        for plugin in self._global_ctxt.plugins.values():
            plugin.parsed_metadata(self)
