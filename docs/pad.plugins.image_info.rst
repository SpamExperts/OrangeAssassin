
***************
ImageInfoPlugin
***************

Image Info plugin.

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.image_info.ImageInfoPlugin

    body         DC_IMAGE001_GIF         eval:image_named('image001.gif')
    describe     DC_IMAGE001_GIF         Contains image named image001.gif

Usage
=====

This plugin exposes various methods to check image information with
eval rules.

Options
=======

None

EVAL rules
==========

.. automethod:: pad.plugins.image_info.ImageInfoPlugin.image_count
    :noindex:
.. automethod:: pad.plugins.image_info.ImageInfoPlugin.image_named
    :noindex:
.. automethod:: pad.plugins.image_info.ImageInfoPlugin.pixel_coverage
    :noindex:
.. automethod:: pad.plugins.image_info.ImageInfoPlugin.image_size_exact
    :noindex:
.. automethod:: pad.plugins.image_info.ImageInfoPlugin.image_size_range
    :noindex:
.. automethod:: pad.plugins.image_info.ImageInfoPlugin.image_to_text_ratio
    :noindex:

Tags
====

None

