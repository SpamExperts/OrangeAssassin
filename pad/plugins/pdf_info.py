
""" PDFInfo Plugin. """

from __future__ import absolute_import

import collections
from io import BytesIO
from hashlib import md5

import pad.errors
try:
    import PyPDF2
except ImportError:
    raise pad.errors.PluginLoadError(
        "PDFInfoPlugin not loaded. You must install PyPDF2 to use this "
        "plugin")

import pad.regex
import pad.plugins.base


class PDFInfoPlugin(pad.plugins.base.BasePlugin):

    """PDFInfoPlugin
    """
    eval_rules = (
        "pdf_count",
        "pdf_image_count",
        "pdf_pixel_coverage",
        "pdf_named",
        "pdf_name_regex",
        "pdf_match_md5",
        "pdf_match_details",
        "pdf_is_encrypted",
        "pdf_is_empty_body",
    )
    options = {}

    def _get_count(self, msg):
        """Get the number of PDF files in the message
        """
        try:
            return self.get_local(msg, "counts")
        except KeyError:
            return 0

    def _update_counts(self, msg, incr):
        """Update the cumulative pdf counts"""
        try:
            counts = self.get_local(msg, "counts")
        except KeyError:
            counts = 0
        counts += incr
        self.set_local(msg, "counts", counts)

    def pdf_count(self, msg, minimum, maximum=None, target=None):
        """Check the number of pdf files in the message

        :param minimum: required, message contains at least x pdf mime parts
        :param maximum: optional, if specified, must not contain more than x pdf mime
        parts.
        :return: True if the number of PDF files are more or equal to 'minimum' and
        less or equal than 'maximum' (if set)
        """
        count = self._get_count(msg)
        return minimum <= count <= (maximum or float("inf"))

    def _get_image_count(self, msg):
        """Get the number of Images in PDF attachments"""
        try:
            return self.get_local(msg, "image_counts")
        except KeyError:
            return 0

    def _update_image_counts(self, msg, incr):
        """Update the cumulative image counts"""
        try:
            counts = self.get_local(msg, "image_counts")
        except KeyError:
            counts = 0
        counts += incr
        self.set_local(msg, "image_counts", counts)

    def pdf_image_count(self, msg, minimum, maximum=None, target=None):
        """Check the number of images in the pdf attachments
        :param minimum: required, message contains at least x images in pdf
        attachments.
        :param maximum: optional, if specified, must not contain more than x pdf
        images

        :return: True if the number of images is more or equal to 'minimum' and
        less or equal than 'maximum'.
        """
        count = self._get_image_count(msg)
        return minimum <= count <= (maximum or float("inf"))

    def _get_pixel_coverage(self, msg):
        """Return the cumulative pixel coverage"""
        try:
            return self.get_local(msg, "pixel_coverage")
        except KeyError:
            return 0

    def _update_pixel_coverage(self, msg, incr):
        """Update the cumulative pixel coverage
        "incr" is the area of the image in pixels
        """
        try:
            pixels = self.get_local(msg, "pixel_coverage")
        except KeyError:
            pixels = 0
        pixels += incr
        self.set_local(msg, "pixel_coverage", pixels)

    def pdf_pixel_coverage(self, msg, minimum, maximum=None, target=None):
        """Check the pixel coverage in the PDF files.

        :param minimum: required, message contains at least this much pixel area
        :param maximum: optional, if specified, message must not contain more
        than this much pixel area

        :return: True if the pixel cummulative coverage is more or equal to
        'minimum' and less or equal to 'maximum'.
        """
        coverage = self._get_pixel_coverage(msg)
        return minimum <= coverage <= (maximum or float("inf"))

    def _get_pdf_names(self, msg):
        try:
            return self.get_local(msg, "names")
        except KeyError:
            return []

    def _add_name(self, msg, name):
        """Add a name to the names list."""
        try:
            names = self.get_local(msg, "names")
        except KeyError:
            names = set()
        names.add(name)
        self.set_local(msg, "names", names)

    def pdf_named(self, msg, name, target=None):
        """Check if a PDF file in the message have the exact name.

        :param name: exact file name match, if you need partial match, see
        pdf_name_regex(). Please note that this string match is case
        sensitive.

        :return: True if there is a PDF file with that name.
        """
        return name in self._get_pdf_names(msg)

    def pdf_name_regex(self, msg, regex, target=None):
        """The same than pdf_named but you can use regular expressions to
        do partial matches.

        :param regex: regular expression, see examples in ruleset.

        :return: True if there is a PDF file name that matches that regular
        expression.
        """
        name_re = pad.regex.perl2re(regex)
        names = self._get_pdf_names(msg)
        for name in names:
            if name_re.match(name):
                return True
        return False

    def _get_pdf_hashes(self, msg):
        try:
            return self.get_local(msg, "md5hashes")
        except KeyError:
            return set()

    def _update_pdf_hashes(self, msg, newhash):
        try:
            hashes = self.get_local(msg, "md5hashes")
        except KeyError:
            hashes = set()
        hashes.add(newhash)
        self.set_local(msg, "md5hashes", hashes)

    def pdf_match_md5(self, msg, md5hash, target=None):
        """Check the PDF md5 hash.

        :param md5hash: 32-byte md5 hex.

        :return: True if the md5hash is in the PDF hashes
        """
        return md5hash in self._get_pdf_hashes(msg)

    def _update_fuzzy_md5(self, msg, texthash):
        """Add a md5 hash for text in a PDF"""
        hashes = self._get_fuzzy_md5(msg)
        hashes.add(texthash.lower())
        self.set_local(msg, "fuzzy_md5_hashes", hashes)

    def _get_fuzzy_md5(self, msg):
        """Return the set with the md5 hashes for fuzzy text"""
        try:
            return self.get_local(msg, "fuzzy_md5_hashes")
        except KeyError:
            return set()

    def pdf_match_fuzzy_md5(self, msg, md5hash, target=None):
        """Check if the md5hash is in the fuzzy md5 list.
        Please note that in order to get the fuzzy md5 hash the plugin
        extracts the string from each page of the PDF file then create a
        hash per page. The match is done to each of this hashes

        :param mdm5hash: 32-byte md5 hex

        :return: True if the md5hash is in the list of fuzzy md5 hashes
        """
        hashes = self._get_fuzzy_md5(msg)
        return md5hash in hashes

    def _update_details(self, msg, pdfid, detail, value):
        """Update the details for the PDF attachments"""
        try:
            details = self.get_local(msg, "details")
        except KeyError:
            details = collections.defaultdict()
        try:
            details[pdfid]
        except KeyError:
            details[pdfid] = collections.defaultdict()
        details[pdfid][detail] = value
        self.set_local(msg, "details", details)

    def pdf_match_details(self, msg, detail, regex, target=None):
        """Match if the detail match with any of the PDF files in the
        message.

        :param detail: author, creator, created, modified, producer, title
        :param regex: regular expression, see examples in ruleset

        :return: True if the detail matches in at least one PDF file.
        """
        try:
            details = self.get_local(msg, "details")
        except KeyError:
            details = []
        detail_re = pad.regex.perl2re(regex)
        # There might be several pdf files, dig in all of them
        for pdfid in details:
            allpdfs = details[pdfid]
            for pdf in allpdfs:
                value = allpdfs[pdf]
                if detail_re.match(value):
                    return True
        return False

    def _update_is_encrypted(self, msg, enc):
        try:
            encrypted = self.get_local(msg, "pdf_encrypted")
        except KeyError:
            encrypted = set()
        encrypted.add(enc)
        self.set_local(msg, "pdf_encrypted", encrypted)

    def pdf_is_encrypted(self, msg, target=None):
        """Check if any of the PDF attachments is encrypted

        :return: True if at least one PDF file is encrypted
        """
        try:
            return True in self.get_local(msg, "pdf_encrypted")
        except KeyError:
            return False

    def _update_pdf_size(self, msg, incr):
        """Update the cummulative size of PDFs"""
        try:
            pdfbytes = self.get_local(msg, "pdf_bytes")
        except KeyError:
            pdfbytes = 0
        pdfbytes += incr
        self.set_local(msg, "pdf_bytes", pdfbytes)

    def pdf_is_empty_body(self, msg, byts, target=None):
        """Check if the PDF files are empty (cummulative size).

        :param byts: maximum byte count to allow and still consider it
        empty
        :return: True if the cummulative PDF size is less than byts."""
        try:
            pdfbytes = self.get_local(msg, "pdf_bytes")
        except KeyError:
            return 0
        return pdfbytes <= byts

    def _save_stats(self, msg, payload):
        """Extracts and saves the PDF stats once per unique file"""
        # Use the md5 as ID to avoid duplicated PDFs
        pdf_id = md5(payload).hexdigest()
        self._update_pdf_hashes(msg, pdf_id)
        pdffobject = BytesIO(payload)
        self._update_pdf_size(msg, incr=len(pdffobject.getvalue()))
        pdfobject = PyPDF2.PdfFileReader(pdffobject)
        self._update_is_encrypted(msg, pdfobject.isEncrypted)
        if pdfobject.isEncrypted:
            # Can't get any of the other data, the document is encrypted
            return
        document_info = pdfobject.getDocumentInfo()
        if document_info is not None:
            self._update_details(msg, pdf_id, "author", document_info.author)
            self._update_details(msg, pdf_id, "creator", document_info.creator)
            self._update_details(
                msg, pdf_id, "producer", document_info.producer)
            self._update_details(msg, pdf_id, "title", document_info.title)
        for page in pdfobject.pages:
            # Get the text for the corrent page, get the md5 for fuzzy md5
            text = page.extractText().encode("utf8")
            if text:
                fuzzy_md5 = md5(text).hexdigest()
                self._update_fuzzy_md5(msg, fuzzy_md5)
            try:
                resources = page["/Resources"]
            except KeyError:
                continue
            if "/XObject" not in resources:
                continue
            for key in resources["/XObject"]:
                obj = resources["/XObject"][key]
                typ = obj["/Subtype"]
                if typ != "/Image":
                    continue
                self._update_image_counts(msg, incr=1)
                width = obj["/Width"]
                height = obj["/Height"]
                self._update_pixel_coverage(msg, incr=width * height)

    def extract_metadata(self, msg, payload, text, part):
        """Extend to extract the PDF metadata"""
        if part.get_content_type() == "application/pdf":
            name = part.get_param("name")
            self._add_name(msg, name)
            self._update_counts(msg, incr=1)
            self._save_stats(msg, part.get_payload(decode=True))
