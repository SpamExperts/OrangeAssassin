"""Generates a documentation file for one SpamPAD plugin.

Example usage:

python doc/generate_plugin_doc.py pad.plugins.body_eval BodyEval
"""

from __future__ import absolute_import

import sys
import importlib

import jinja2

TEMPLATE = """
{{ "*"* plugin.__name__|length }}
{{ plugin.__name__ }}
{{ "*"* plugin.__name__|length }}

{{ module.__doc__ }}
Example usage
=============

.. code-block:: none

    loadplugin      {{ plugin.__module__ }}.{{ plugin.__name__ }}

Usage
=====

<Description>

Options
=======
{% if not plugin.options %}
None
{% else %}{% for name, value in plugin.options.items() %}
**{{ name }}** {{ value[1] }} (type `{{ value[0] }}`)
    <Option description>{% endfor %}
{% endif %}
EVAL rules
==========
{% if not plugin.eval_rules %}
None
{% else %}{% for name in plugin.eval_rules %}
.. automethod:: {{ plugin.__module__ }}.{{ plugin.__name__ }}.{{ name }}
    :noindex:{% endfor %}
{% endif %}
Tags
====

<Describe TAGS>

"""

module = sys.argv[1]
klass = sys.argv[2]

module = importlib.import_module(module)
klass = getattr(module, klass)

print(jinja2.Template(TEMPLATE).render(
    plugin=klass,
    module=module
))
