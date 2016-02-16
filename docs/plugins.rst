*******
Plugins
*******

To load a plugin you must add the `loadplugin` command in the configuration
file. For example::

    loadplugin pad.plugin.pyzor.PyzorPlugin

If the plugin is not located in the python path then you can also specify the
full path to the file::

    loadplugin MyCustomPlugin /home/pad/my_plugins/custom_plugin.py

Some plugins are reimplementing existing ones from SA. The full list can be
seen in :py:mod:`pad.plugins`::

    loadplugin Mail::SpamAssassin::Plugin::Pyzor


Available plugins
=================

.. toctree::
    :maxdepth: 1

    pad.plugins.body_eval
    pad.plugins.short_circuit

Plugin reference
================

.. toctree::

    pad.plugins


