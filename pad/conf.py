"""Manage configuration option parsing."""

import pad.errors


class Conf(object):
    """Parses and stores values for options in the global
    context. The options must be defined in the `options`
    class attribute in the following format::

        {
            "my_option": ("str", "default value"),
        }

    Support types are:

    * int
    * float
    * bool
    * str
    * list
    * append
    * append_split
    * clear

    See the corresponding `set_*_option` method for details
    on each of them.
    """
    options = None

    def __init__(self, context):
        """Initialize the plugin and parses all options specified in
        options.
        """
        self.ctxt = context
        self._plugin_name = self.__class__.__name__
        if self.options:
            for key, (dummy, value) in self.options.items():
                self.set_global(key, value)

    def __setitem__(self, key, value):
        self.set_global(key, value)

    def __getitem__(self, item):
        return self.get_global(item)

    def __delitem__(self, key):
        self.del_global(key)

    def set_global(self, key, value):
        """Store data in the global context"""
        self.ctxt.set_plugin_data(self._plugin_name, key, value)

    def get_global(self, key=None):
        """Get data from the global context"""
        return self.ctxt.get_plugin_data(self._plugin_name, key)

    def del_global(self, key=None):
        """Delete data from the global context"""
        return self.ctxt.del_plugin_data(self._plugin_name, key)

    def set_local(self, msg, key, value):
        """Store data in the local message context"""
        msg.set_plugin_data(self._plugin_name, key, value)

    def get_local(self, msg, key=None):
        """Get data from the local message context"""
        return msg.get_plugin_data(self._plugin_name, key)

    def del_local(self, msg, key=None):
        """Delete data from the local message context"""
        return msg.del_plugin_data(self._plugin_name, key)

    def set_int_option(self, global_key, value):
        """Parse and set a integer option."""
        try:
            if value:
                self.set_global(global_key, int(value))
        except ValueError:
            raise pad.errors.PluginError("Invalid value for %s: %s" %
                                         (global_key, value))

    def set_float_option(self, global_key, value):
        """Parse and set a float option."""
        try:
            self.set_global(global_key, float(value))
        except ValueError:
            raise pad.errors.PluginError("Invalid value for %s: %s" %
                                         (global_key, value))

    def set_bool_option(self, global_key, value):
        """Parse and set a bool option."""
        self.set_global(global_key, value.lower() in ("1", "true"))

    def set_str_option(self, global_key, value):
        """Parse and set a string option."""
        self.set_global(global_key, value)

    def set_list_option(self, global_key, value, separator=","):
        """Parse and set a list option."""
        self.set_global(global_key, value.split(separator))

    def set_append_option(self, key, value):
        """This option can be specified multiple times and the
        result are appended to the list.
        """
        self.get_global(key).append(value)

    def set_append_split_option(self, key, value, separator=None):
        """This option can be specified multiple times and the
        result are appended to the list.

        The values themselves can also be list of separated by
        whitespace.
        """
        # WHY?! :/ Who would think this is a good idea?
        self.get_global(key).extend(value.split(separator))

    def set_clear_option(self, key, value):
        """Clear the current option's value and replace it
        with the default.
        """
        real_keys = self.options[key][1]
        for real_key in real_keys:
            default = self.options[real_key][1]
            self.set_global(real_key, default)

    def inhibit_further_callbacks(self):
        """Tells the plugin handler to inhibit calling into other plugins in
        the plugin chain for the current callback.
        """
        raise pad.errors.InhibitCallbacks()

    def parse_config(self, key, value):
        """Parse a config line that the normal parses doesn't know how to
        interpret.

        Use self.inhibit_further_callbacks to stop other plugins from
        processing this line.

        May be overridden.
        """
        if self.options and key in self.options:
            set_func = getattr(self, "set_%s_option" % self.options[key][0])
            set_func(key, value)
            self.inhibit_further_callbacks()


class PADConf(Conf):
    """Main configuration of SpamPAD"""

    options = {
        "report": ("append", []),
        "clear_report_template": ("clear", ["report"]),
        "report_contact": ("str", ""),
        "report_safe": ("int", 1),
        "add_header": ("append", []),
        "remove_header": ("append", []),
        "clear_headers": ("clear", ["add_header", "remove_header"]),
        "required_score": ("float", 5.0),
        "use_bayes": ("bool", True),
        "use_network": ("bool", True),
        "envelope_sender_header": ("append", []),
        "dns_server": ("append", []),
        "clear_dns_servers": ("clear", ["dns_server"]),
        "default_dns_lifetime": ("float", 10.0),
        "default_dns_timeout": ("float", 2.0),
        "allow_user_rules": ("bool", False),
        "skip_rbl_checks": ("bool", 0),
        "trusted_networks": ("append_split", []),
        "clear_trusted_networks": ("clear", ["trusted_networks"]),
        "internal_networks": ("append_split", []),
        "clear_internal_networks": ("clear", ["internal_networks"]),
        "msa_networks": ("append_split", []),
        "clear_msa_networks": ("clear", ["msa_networks"]),
        "originating_ip_headers": ("append_split", []),
        "clear_originating_ip_headers": ("clear", ["originating_ip_headers"]),
        "clear_dns_query_restriction": ("clear", ["dns_query_restriction"]),
        "always_trust_envelope_sender": ("int", 0),
        "dns_available": ("str", "yes"),
        "dns_local_ports_permit": ("append_split", []),
        "dns_local_ports_avoid": ("append_split", []),
        "dns_test_interval": ("str", "600"),
        "dns_options": ("str", "norotate, nodns0x20, edns=4096"),
        "dns_query_restriction": ("append", []),
        "autolearn": ("bool", False),
        "training": ("bool", False),
        "user_config": ("bool", True),
    }
