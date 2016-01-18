"""Tests for pad.plugins.image_info."""
import unittest
from io import BytesIO
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

from PIL import Image

import pad.plugins
from pad.plugins import image_info

class TestImageInfoBase(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}
        patch("pad.plugins.whitelist_subject.WhiteListSubjectPlugin.options", self.options).start()
        patch("pad.plugins.whitelist_subject.WhiteListSubjectPlugin.inhibit_further_callbacks").start()

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.setdefault(k, v)}
        )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.msg_data.setdefault(k, v),
        })
        self.mock_msg.msg = None
        self.plugin = pad.plugins.image_info.ImageInfoPlugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def new_image(self, width, height, subtype, name):
        image = Image.new("RGB", (width,height))
        img_io = BytesIO()
        image.save(img_io, format="JPEG")
        img_io.seek(0)
        return {"data": img_io,
                "name": name,
                "subtype": subtype,
                "width": width,
                "height": height,
                "coverage": width*height}

    def new_email(self, images):
        msg = MIMEMultipart()
        for image in images.values():
            mimg = MIMEImage(image['data'].read(), _subtype=image['subtype'],
                             name=image['name'])
            mimg.add_header("Content-Disposition", "attachment",
                            filename=image["name"])
            msg.attach(mimg)
        return msg

    def new_image_string(self, size, mode="RGB"):
        image = Image.new(mode, size)
        img_io = BytesIO()
        image_io = image.save(img_io, format="JPEG")
        image.close()
        img_io.seek(0)
        return img_io.read()


class TestImageInfoPlugin(TestImageInfoBase):

    def test_extract_metadata(self):
        patch("pad.plugins.image_info.ImageInfoPlugin._add_name").start()
        patch("pad.plugins.image_info.ImageInfoPlugin._update_counts").start()
        patch("pad.plugins.image_info.ImageInfoPlugin._save_stats").start()

        add_name_calls = []
        update_counts_calls = []
        save_stats_calls = []
        images = {}
        for x in range(5):
            images.update({
                x: self.new_image(1,1,"jpg", "%s.jpg"%x)
            })
            add_name_calls.append(call(self.mock_msg, "%s.jpg" % x))
            update_counts_calls.append(call(self.mock_msg, "jpg", by=1))
            save_stats_calls.append(call(self.mock_msg,
                                         self.new_image_string((1,1), "RGB"),
                                         "jpg"))

        self.mock_msg.msg = self.new_email(images)

        for part in self.mock_msg.msg.walk():
            payload = part.get_payload(decode=True)
            self.plugin.extract_metadata(self.mock_msg, payload, part)

        self.plugin._add_name.assert_has_calls(add_name_calls)
        self.plugin._update_counts.assert_has_calls(update_counts_calls)
        self.plugin._save_stats.assert_has_calls(save_stats_calls)



class TestImageCount(TestImageInfoBase):


    def test_min_true(self):
        self.plugin._update_counts(self.mock_msg, "jpg", 5)
        self.assertTrue(self.plugin.image_count(self.mock_msg, "all", 2))

    def test_min_false(self):
        self.plugin._update_counts(self.mock_msg, "jpg", 5)
        self.assertFalse(self.plugin.image_count(self.mock_msg, "all", 7))

    def test_max_true(self):
        self.plugin._update_counts(self.mock_msg, "jpg", 5)
        self.assertTrue(self.plugin.image_count(self.mock_msg, "all", 2, 6))

    def test_max_false(self):
        self.plugin._update_counts(self.mock_msg, "jpg", 5)
        self.assertFalse(self.plugin.image_count(self.mock_msg, "all", 2, 3))


class TestImageNamed(TestImageInfoBase):

    def test_true(self):
        for x in ["test1.jpg", "test2.jpg", "test3.jpg"]:
            self.plugin._add_name(self.mock_msg, x)
        self.assertTrue(self.plugin.image_named(self.mock_msg, "test1.jpg"))

    def test_false(self):
        for x in ["test1.jpg", "test2.jpg", "test3.jpg"]:
            self.plugin._add_name(self.mock_msg, x)
        self.assertFalse(self.plugin.image_named(self.mock_msg, "notexisting.jpg"))

class TestImageNameRegex(TestImageInfoBase):

    def test_true(self):
        names = ["test.gif", "test..gif", "test...gif"]
        self.plugin.set_local(self.mock_msg, "names", names)
        doubledot_regex = "/^\w{1,9}\.\.gif$/i"
        self.assertTrue(self.plugin.image_name_regex(self.mock_msg,
                                                    doubledot_regex))

    def test_false(self):
        names = ["test.gif", "test.gif", "test.gif"]
        self.plugin.set_local(self.mock_msg, "names", names)
        doubledot_regex = "/^\w{2,9}\.\.gif$/i"
        self.assertFalse(self.plugin.image_name_regex(self.mock_msg,
                                                    doubledot_regex))

class TestPixelCoverage(TestImageInfoBase):

    def test_min_true(self):
        image = self.new_image_string((2,2))
        self.plugin._save_stats(self.mock_msg, image, "jpg")
        self.assertTrue(self.plugin.pixel_coverage(self.mock_msg, "all", 3))

    def test_min_false(self):
        image = self.new_image_string((2,2))
        self.plugin._save_stats(self.mock_msg, image, "jpg")
        self.assertFalse(self.plugin.pixel_coverage(self.mock_msg, "all", 5))

    def test_max_true(self):
        image = self.new_image_string((2,2))
        self.plugin._save_stats(self.mock_msg, image, "jpg")
        self.assertTrue(self.plugin.pixel_coverage(self.mock_msg, "all", 3, 5))

    def test_max_false(self):
        image = self.new_image_string((2,2))
        self.plugin._save_stats(self.mock_msg, image, "jpg")
        self.assertFalse(self.plugin.pixel_coverage(self.mock_msg, "all", 3, 2))


class TestImageSizeExact(TestImageInfoBase):

    def test_true(self):
        image = self.new_image_string((2,2))
        self.plugin._save_stats(self.mock_msg, image, "jpg")
        self.assertTrue(self.plugin.image_size_exact(self.mock_msg, "all", 2, 2))

    def test_false(self):
        image = self.new_image_string((2,2))
        self.plugin._save_stats(self.mock_msg, image, "jpg")
        self.assertFalse(self.plugin.image_size_exact(self.mock_msg, "all", 3, 2))

class TestImageSizeRange(TestImageInfoBase):

    def test_min_true(self):
        image = self.new_image_string((2,2))
        self.plugin._save_stats(self.mock_msg, image, "jpg")
        self.assertTrue(self.plugin.image_size_range(self.mock_msg, "all", 1, 1))

    def test_min_false(self):
        image = self.new_image_string((2,2))
        self.plugin._save_stats(self.mock_msg, image, "jpg")
        self.assertFalse(self.plugin.image_size_range(self.mock_msg, "all", 3, 3))

    def test_max_true(self):
        image = self.new_image_string((2,2))
        self.plugin._save_stats(self.mock_msg, image, "jpg")
        self.assertTrue(self.plugin.image_size_range(self.mock_msg, "all", 1,
                                                     1, 3, 3))

    def test_max_false(self):
        image = self.new_image_string((2,2))
        self.plugin._save_stats(self.mock_msg, image, "jpg")
        self.assertFalse(self.plugin.image_size_range(self.mock_msg, "all", 3,
                                                      3, 1, 1))

class TestImageToTextRatio(TestImageInfoBase):

    def test_min_true(self):
        self.mock_msg.text = "A"*12
        self.plugin._update_coverage(self.mock_msg, "jpg", 4)
        self.assertTrue(self.plugin.image_to_text_ratio(self.mock_msg, "all",
                                                        2, target="body"))

    def test_min_false(self):
        self.mock_msg.text = "A"*12
        self.plugin._update_coverage(self.mock_msg, "jpg", 4)
        self.assertFalse(self.plugin.image_to_text_ratio(self.mock_msg, "all",
                                                         4, target="body"))

    def test_max_true(self):
        self.mock_msg.text = "A"*12
        self.plugin._update_coverage(self.mock_msg, "jpg", 4)
        self.assertTrue(self.plugin.image_to_text_ratio(self.mock_msg, "all",
                                                        2, 4, target="body"))

    def test_max_false(self):
        self.mock_msg.text = "A"*12
        self.plugin._update_coverage(self.mock_msg, "jpg", 4)
        self.assertFalse(self.plugin.image_to_text_ratio(self.mock_msg, "all",
                                                        1, 2, target="body"))

def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestImageInfoPlugin, "test"))
    test_suite.addTest(unittest.makeSuite(TestImageCount, "test"))
    test_suite.addTest(unittest.makeSuite(TestImageNamed, "test"))
    test_suite.addTest(unittest.makeSuite(TestPixelCoverage, "test"))
    test_suite.addTest(unittest.makeSuite(TestImageNameRegex, "test"))
    test_suite.addTest(unittest.makeSuite(TestImageSizeExact, "test"))
    test_suite.addTest(unittest.makeSuite(TestImageSizeRange, "test"))
    test_suite.addTest(unittest.makeSuite(TestImageToTextRatio, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
