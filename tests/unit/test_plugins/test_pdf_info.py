"""Tests for pad.plugins.pdf_info."""
import unittest
import collections

from hashlib import md5
from tests.util.pdf_utils import new_email, new_pdf, PDFWithAttachments
from tests.util.image_utils import new_image_string

try:
    from unittests.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins

class PDFInfoBase(unittest.TestCase):
    """Test for the PDFInfo plugin"""
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}
        patch("pad.plugins.pdf_info.PDFInfoPlugin.options",
              self.options).start()
        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data."
            "side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
            })
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data."
            "side_effect": lambda p, k, v: self.msg_data.update({k:v}),
        })
        self.mock_msg.msg = None
        self.plugin = pad.plugins.pdf_info.PDFInfoPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()


class TestPDFInfo(PDFInfoBase):
    def test_extract_metadata(self):
        patch("pad.plugins.pdf_info.PDFInfoPlugin._add_name").start()
        patch("pad.plugins.pdf_info.PDFInfoPlugin._update_counts").start()
        patch("pad.plugins.pdf_info.PDFInfoPlugin._save_stats").start()

        add_name_calls = []
        update_counts_calls = []
        save_stats_calls = []
        pdfs = {}
        allpdfinfo = (
                {"details": {"/Author":"Author1", "/Creator":"unittest",
                    "/Created":"2016-02-11", "/Title": "pdftest"}},
                {"details": {"/Author":"Author2", "/Creator":"unittest",
                    "/Created":"2016-02-11", "/Title": "pdftest2"}},
                {"details": {"/Author":"Author3", "/Creator":"unittest",
                    "/Created":"2016-02-11", "/Title": "pdftest3"}},
                {"details": {"/Author":"Author4", "/Creator":"unittest",
                    "/Created":"2016-02-11", "/Title": "pdftest4"}, 
                    "images": ("image1", (100,100))},
                )
        for x in iter(range(len(allpdfinfo))):
            pdfinfo = allpdfinfo[x]
            name = "%d.pdf" % x
            if "images" not in pdfinfo:
                pdfobj = new_pdf(details = pdfinfo["details"], name=name)
            else:
                pdfc = PDFWithAttachments(details = pdfinfo["details"], name=name)
                image = new_image_string(pdfinfo["images"][1])
                pdfc.addAttachment(pdfinfo["images"][0], image)
                pdfobj = {"data": pdfc.as_file(), "name": name}
            pdfs.update({x: pdfobj})
            add_name_calls.append(call(self.mock_msg, name))
            update_counts_calls.append(call(self.mock_msg, incr=1))
            save_stats_calls.append(call(self.mock_msg, pdfobj["data"].read()))

        self.mock_msg.msg = new_email(pdfs)

        for part in self.mock_msg.msg.walk():
            payload = part.get_payload(decode=True)
            self.plugin.extract_metadata(self.mock_msg, payload, None, part)

        self.plugin._add_name.assert_has_calls(add_name_calls)
        self.plugin._update_counts.assert_has_calls(update_counts_calls)
        self.plugin._save_stats.assert_has_calls(save_stats_calls)

    def test_update_stats(self):
        patch("pad.plugins.pdf_info.PDFInfoPlugin._update_details").start()
        patch("pad.plugins.pdf_info.PDFInfoPlugin._update_image_counts").start()
        patch("pad.plugins.pdf_info.PDFInfoPlugin._update_pixel_coverage").start()

        update_details_calls= []
        update_image_count_calls = []
        update_pixel_coverage_calls = []
        pdfs = {}
        allpdfinfo = (
                {"details": {"/Author":"Author1", "/Creator":"unittest",
                    "/Producer":"2016-02-11", "/Title": "pdftest"}},
                {"details": {"/Author":"Author2", "/Creator":"unittest",
                    "/Producer":"2016-02-11", "/Title": "pdftest2"}},
                {"details": {"/Author":"Author3", "/Creator":"unittest",
                    "/Producer":"2016-02-11", "/Title": "pdftest3"}},
                {"details": {"/Author":"Author4", "/Creator":"unittest",
                    "/Producer":"2016-02-11", "/Title": "pdftest4"}, 
                    "images": ("image1", (100,100))},
                )
        for x in range(len(allpdfinfo)):
            pdfinfo = allpdfinfo[x]
            name = "%d.pdf" % x
            if "images" not in pdfinfo:
                pdfobj = new_pdf(details = pdfinfo["details"], name=name)
            else:
                pdfc = PDFWithAttachments(details = pdfinfo["details"], name=name)
                image = new_image_string(pdfinfo["images"][1])
                pdfc.addAttachment(pdfinfo["images"][0], image)
                pdfobj = {"data": pdfc.as_file(), "name": name}
            pdfs.update({x: pdfobj})
            pdf_id = md5(pdfobj["data"].getvalue()).hexdigest()
            for det in ("/Author", "/Creator","/Producer", "/Title"):
                value  = pdfinfo["details"][det]
                update_details_calls.append(call(self.mock_msg, pdf_id, det.lower()[1:],
                    value))
            if "images" in pdfinfo:
                update_image_count_calls.append(call(self.mock_msg, incr = 1))
                width, height = pdfinfo["images"][1]
                update_pixel_coverage_calls.append(call(self.mock_msg, width * height))

        self.mock_msg.msg = new_email(pdfs)

        for part in self.mock_msg.msg.walk():
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            self.plugin._save_stats(self.mock_msg, payload)

        self.plugin._update_details.assert_has_calls(update_details_calls)
        # I need to know how to attach an image to the PDF seems like I need 
        # to draw the PDF in ReportLab then write it to PDF
        #self.plugin._update_image_counts.assert_has_calls(update_image_count_calls)
        #self.plugin._update_pixel_coverage.assert_has_calls(update_pixel_coverage_calls)

    def test_pdf_count(self):
        """Test the pdf_count"""
        self.plugin.set_local(self.mock_msg, "counts", 1)
        self.assertEqual(self.plugin._get_count(self.mock_msg), 1)

    def test_pdf_count_zero(self):
        """Test the pdf_count when there are no images"""
        self.assertEqual(self.plugin._get_count(self.mock_msg), 0)

    def test_update_pdf_count(self):
        """Test updating the image count"""
        expected = 10
        self.plugin._update_counts(self.mock_msg, incr = 1)
        self.plugin._update_counts(self.mock_msg, incr = 2)
        self.plugin._update_counts(self.mock_msg, incr = 7)
        self.assertEqual(self.plugin.get_local(self.mock_msg, 
            "counts"), expected)

    def test_pdf_count_match(self):
        """Test pdf_image_count (extract the images from the PDF and count them)
        """
        self.plugin.set_local(self.mock_msg, "counts", 3)       
        self.assertTrue(self.plugin.pdf_count(self.mock_msg,3, 5))
    
    def test_image_count(self):
        """Test the pdf_image_count"""
        self.plugin.set_local(self.mock_msg, "image_counts", 1)
        self.assertEqual(self.plugin._get_image_count(self.mock_msg), 1)

    def test_image_count_zero_images(self):
        """Test the pdf_image_count when there are no images"""
        self.assertEqual(self.plugin._get_image_count(self.mock_msg), 0)

    def test_update_image_count(self):
        """Test updating the image count"""
        expected = 10
        self.plugin._update_image_counts(self.mock_msg, incr = 1)
        self.plugin._update_image_counts(self.mock_msg, incr = 2)
        self.plugin._update_image_counts(self.mock_msg, incr = 7)
        self.assertEqual(self.plugin.get_local(self.mock_msg, 
            "image_counts"), expected)

    def test_pdf_image_count(self):
        """Test pdf_image_count (extract the images from the PDF and count them)
        """
        self.plugin.set_local(self.mock_msg, "image_counts", 3)       
        self.assertTrue(self.plugin.pdf_image_count(self.mock_msg,3, 5))

    def test_pixel_coverage(self):
        """Test the pdf_pixel_coverage"""
        self.plugin.set_local(self.mock_msg, "pixel_coverage", 100)
        self.assertEqual(self.plugin._get_pixel_coverage(self.mock_msg), 100)

    def test_pixel_coverage_no_images(self):
        """Test the pdf_pixel_coverage when there are no images"""
        self.assertEqual(self.plugin._get_pixel_coverage(self.mock_msg), 0)

    def test_update_pixel_coverage(self):
        """Test updating the image count"""
        expected = 1000
        self.plugin._update_pixel_coverage(self.mock_msg, incr = 100)
        self.plugin._update_pixel_coverage(self.mock_msg, incr = 200)
        self.plugin._update_pixel_coverage(self.mock_msg, incr = 700)
        self.assertEqual(self.plugin.get_local(self.mock_msg, 
            "pixel_coverage"), expected)

    def test_pdf_pixel_coverage(self):
        """Test pdf_pixel_coverage
        """
        self.plugin.set_local(self.mock_msg, "pixel_coverage", 3)       
        self.assertTrue(self.plugin.pdf_pixel_coverage(self.mock_msg, 3, 5))

    def test_add_name(self):
        """Test the pdf_add_name"""
        self.plugin.set_local(self.mock_msg, "names", "pdf.pdf")
        self.assertEqual(self.plugin._get_pdf_names(self.mock_msg), "pdf.pdf")

    def test_pdf_named_no_name(self):
        """Test the pdf_named with no pdfs in the results"""
        self.assertEqual(self.plugin._get_pdf_names(self.mock_msg), [])

    def test_pdf_add_name(self):
        """Test updating the image count"""
        expected = set(["first", "second", "third"])
        self.plugin._add_name(self.mock_msg, name = "first")
        self.plugin._add_name(self.mock_msg, name = "second")
        self.plugin._add_name(self.mock_msg, name = "third")
        self.assertEqual(self.plugin.get_local(self.mock_msg, 
            "names"), expected)

    def test_pdf_named(self):
        """Test pdf_named 
        """
        self.plugin.set_local(self.mock_msg, "names", set(["first"]))       
        self.assertTrue(self.plugin.pdf_named(self.mock_msg, "first"))

    def test_pdf_named_regex(self):
        """Test pdf_named_regex 
        (extract the images from the PDF and count them)
        """
        names = ["test.pdf", "test..pdf", "test...pdf"]
        self.plugin.set_local(self.mock_msg, "names", names)       
        self.assertTrue(self.plugin.pdf_name_regex(self.mock_msg, 
            "/^\w{1,9}\.\.pdf$/i"))

    def test_pdf_update_md5hash(self):
        """Test adding several hashes to the "md5hashes local value"""
        hashes = ["1234567890","0987654321","12345"]
        expected = set()
        for tmphash in hashes:
            expected.add(tmphash)
            self.plugin._update_pdf_hashes(self.mock_msg, tmphash)
        self.assertEqual(self.plugin.get_local(self.mock_msg, "md5hashes"),
                         expected)

    def test_pdf_get_pdf_hashes_no_hash(self):
        """Test getting the md5hashes"""
        expected = set()
        self.assertEqual(self.plugin._get_pdf_hashes(self.mock_msg),
                         expected)

    def test_pdf_match_md5(self):
        """Test pdf_match_md5 with a single match"""
        self.plugin.set_local(self.mock_msg, "md5hashes", ["1234567890",])
        self.assertTrue(self.plugin.pdf_match_md5(self.mock_msg, "1234567890"))

    def test_pdf_match_md5_no_match(self):
        """Test pdf_match_md5 when there is no match"""
        self.plugin.set_local(self.mock_msg, "md5hashes", ["1234567890",])
        self.assertFalse(self.plugin.pdf_match_md5(self.mock_msg, "123456789"))

    #XXX Still need to get the fuzzy md5 tests

    def test_pdf_update_details(self):
        """Test the _update_details method"""
        # Details are stored per pdf file (in practice identified by the md5) 
        # then by the detail key (author, creator, created, modified, 
        # producer, title)
        pdfid = "1234567890"
        details = {"author": "testauthor", "creator": "test creator",
                "created": "1970-01-01 00:00:00", "modified": "None",
                "producer": "unittest", "title": "Pdf Test"}
        for key in details:
            self.plugin._update_details(self.mock_msg, pdfid, key, 
                    details[key])

        plugin_values = self.plugin.get_local(self.mock_msg, "details")[pdfid]
        for key in details:
            self.assertEqual(plugin_values[key], details[key])

    def test_pdf_match_details(self):
        """Test the match_details method"""
        pdfid = "1234567890"
        self.plugin._update_details(self.mock_msg, pdfid, "author",
                "TestAuthor")
        self.assertTrue(self.plugin.pdf_match_details(self.mock_msg, "author",
            "/^tes\w{1,9}$/i"))

    def test_pdf_is_encrypted(self):
        """Test pdf_is_encrypted"""
        encrypted = set()
        encrypted.add(True)
        encrypted.add(False)
        self.plugin.set_local(self.mock_msg, "pdf_encrypted", encrypted)
        self.assertTrue(self.plugin.pdf_is_encrypted(self.mock_msg))

    def test_pdf_is_encrypted_no_encrypted(self):
        """Test pdf_is_encrypted"""
        encrypted = set()
        encrypted.add(False)
        self.plugin.set_local(self.mock_msg, "pdf_encrypted", encrypted)
        self.assertFalse(self.plugin.pdf_is_encrypted(self.mock_msg))

    def test_update_pdf_size(self):
        """Test the update function for the pdf_bytes"""
        self.plugin._update_pdf_size(self.mock_msg, 100)
        self.plugin._update_pdf_size(self.mock_msg, 200)
        self.plugin._update_pdf_size(self.mock_msg, 300)
        self.assertEqual(self.plugin.get_local(self.mock_msg, "pdf_bytes"),
                600)

    def test_pdf_is_empty_body(self):
        """Test is_empty_body with 100 bytes, minimum 110, should be 
        considered empty"""
        self.plugin._update_pdf_size(self.mock_msg, 100)
        self.assertTrue(self.plugin.pdf_is_empty_body(self.mock_msg, 110))

    def test_pdf_is_empty_body_false(self):
        """Test is_empty_body with 120 bytes, minimum 110, should not be 
        considered empty"""
        self.plugin._update_pdf_size(self.mock_msg, 120)
        self.assertFalse(self.plugin.pdf_is_empty_body(self.mock_msg, 110))





def suite():
    """Gather all the tests from this module in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestPDFInfo, "test"))
    return test_suite

if __name__ == "__main__":
    unittest.main(defaultTest="suite")

