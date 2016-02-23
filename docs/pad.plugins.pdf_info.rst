
*************
PDFInfoPlugin
*************

This plugin helps to detect spam using attached PDF files

Example usage
=============

.. code-block:: none

    loadplugin      pad.plugins.pdf_info.PDFInfoPlugin

    body            PDF_MIME_COUNT_1        eval:pdf_count(1,3)
    describe        PDF_MIME_COUNT_1        Message contains at least 1 PDF file, maximum 3.

    body            PDF_IMAGE_COUNT         eval:pdf_image_count(3, 10)
    describe        PDF_IMAGE_COUNT         Total number of images in PDF is between 3 and 10 

    body            PDF_PIX_COV             eval:pdf_pixel_coverage(100, 450)
    describe        PDF_PIX_COV             Contains between 100 and 450 pixel in images

    body            PDF_NAMED               eval:pdf_named('some_file.pdf')
    describe        PDF_NAMED               Check if a pdf named "some_file.pdf" exists in the message.

    body            PDF_NAMED_REGEX         eval:pdf_named_regex('/^(?:my|your)test\.pdf$/')
    describe        PDF_NAMED_REGEX         Match if pdf is "mytest.pdf" or "yourtest.pdf"

    body            PDF_MATCH_MD5           eval:pdf_match_md5('C359F8F89B290DA99DC997ED50117CDF')
    describe        PDF_MATCH_MD5           Match with the PDF with that md5 hash

    body            PDF_FUZZY_MD5           eval:pdf_match_fuzzy_md5('7340821445D975EEF6F5BDE2EC257900')
    describe        PDF_FUZZY_MD5           Match if md5hash is in the fuzzy md5 hashes
    
    body            PDF_MATCH_DETAIL        eval:pdf_match_details('author', '/^mobile$/')
    describe        PDF_MATCH_DETAIL        Match if "mobile" is the author of the PDF file.

    body            PDF_IS_ENCRYPTED        eval:pdf_is_encrypted()
    describe        PDF_IS_ENCRYPTED        Match if one of the PDF files is encrypted.

    body            PDF_IS_EMPTY_BODY       eval:pdf_is_empty_body(100)
    describe        PDF_IS_EMPTY_BODY       Interested in PDF files larger than 100 bytes.
    

Usage
=====

This plugin only has EVAL methods. See :ref:`eval-rule` for general
details on how to use such methods.

Options
=======

None

EVAL rules
==========

.. automethod:: pad.plugins.pdf_info.PDFInfoPlugin.pdf_count
    :noindex:
.. automethod:: pad.plugins.pdf_info.PDFInfoPlugin.pdf_image_count
    :noindex:
.. automethod:: pad.plugins.pdf_info.PDFInfoPlugin.pdf_pixel_coverage
    :noindex:
.. automethod:: pad.plugins.pdf_info.PDFInfoPlugin.pdf_named
    :noindex:
.. automethod:: pad.plugins.pdf_info.PDFInfoPlugin.pdf_name_regex
    :noindex:
.. automethod:: pad.plugins.pdf_info.PDFInfoPlugin.pdf_match_md5
    :noindex:
.. automethod:: pad.plugins.pdf_info.PDFInfoPlugin.pdf_match_fuzzy_md5
    :noindex:
.. automethod:: pad.plugins.pdf_info.PDFInfoPlugin.pdf_match_details
    :noindex:
.. automethod:: pad.plugins.pdf_info.PDFInfoPlugin.pdf_is_encrypted
    :noindex:
.. automethod:: pad.plugins.pdf_info.PDFInfoPlugin.pdf_is_empty_body
    :noindex:

Tags
====

<Describe TAGS>

