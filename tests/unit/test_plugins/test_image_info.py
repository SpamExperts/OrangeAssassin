"""Tests for pad.plugins.image_info."""
import unittest
from io import BytesIO
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart

try:
    from unittest.mock import patch, Mock, MagicMock
except ImportError:
    from mock import patch, Mock, MagicMock

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


class TestImageInfoPlugin(TestImageInfoBase):

    def test_extract_metadata(self):
        images = {
            x: self.new_image(1,1,"jpg", "%s.jpg"%x) for x in range(1)
        }
        self.mock_msg.msg = self.new_email(images)

        for part in self.mock_msg.msg.walk():
            payload = part.get_payload(decode=True)
            self.plugin.extract_metadata(self.mock_msg, payload, part)

        for image in images.values():
            image.pop("data", None)

        extracted_images = self.plugin.get_local(self.mock_msg, "images")
        self.assertListEqual(images.values(), extracted_images.values())


    def test_get_local_images_empty(self):
        images = self.plugin._get_local_images(self.mock_msg)
        self.assertDictEqual({}, images)

    def test_get_local_images(self):
        expected = {x: self.new_image(1, 1, "jpg", "test") for x in range(5)}
        self.plugin.set_local(self.mock_msg, "images", expected)

        images = self.plugin._get_local_images(self.mock_msg)
        self.assertDictEqual(images, expected)

    def test_image_info(self):
        img = Image.new("RGB", (3,4))
        content = BytesIO()
        img.save(content, format="JPEG")
        content.seek(0)
        result = self.plugin._image_info(content.read())
        self.assertEquals(result, {"width":3, "height":4, "coverage":12})


class TestImageCount(TestImageInfoBase):

    def test_min_true(self):
        images = {x: self.new_image(1, 1, "jpg", "test") for x in range(5)}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(self.plugin.image_count(self.mock_msg, "all", 2))

    def test_min_false(self):
        images = {x: self.new_image(1, 1, "jpg", "test") for x in range(5)}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(self.plugin.image_count(self.mock_msg, "all", 7))

    def test_max_true(self):
        images = {x: self.new_image(1, 1, "jpg", "test") for x in range(5)}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(self.plugin.image_count(self.mock_msg, "all", 2, 6))

    def test_max_false(self):
        images = {x: self.new_image(1, 1, "jpg", "test") for x in range(5)}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(self.plugin.image_count(self.mock_msg, "all", 2, 3))


class TestImageNamed(TestImageInfoBase):

    def test_true(self):
        images = {1: self.new_image(1, 1, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(self.plugin.image_named(self.mock_msg, "test.jpg"))

    def test_false(self):
        images = {1: self.new_image(1, 1, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(self.plugin.image_named(self.mock_msg, "test2.jpg"))

class TestImageNameRegex(TestImageInfoBase):

    def test_true(self):
        pass

    def test_false(self):
        pass

class TestPixelCoverage(TestImageInfoBase):

    def test_min_true(self):
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(self.plugin.pixel_coverage(self.mock_msg, "all", 3))

    def test_min_false(self):
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(self.plugin.pixel_coverage(self.mock_msg, "all", 5))

    def test_max_true(self):
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(self.plugin.pixel_coverage(self.mock_msg, "all", 3, 5))

    def test_max_false(self):
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(self.plugin.pixel_coverage(self.mock_msg, "all", 3, 2))


class TestImageSizeExact(TestImageInfoBase):

    def test_true(self):
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(self.plugin.image_size_exact(self.mock_msg, "all", 2, 2))

    def test_false(self):
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(self.plugin.image_size_exact(self.mock_msg, "all", 3, 2))

class TestImageSizeRange(TestImageInfoBase):

    def test_min_true(self):
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(self.plugin.image_size_range(self.mock_msg, "all", 1, 1))

    def test_min_false(self):
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(self.plugin.image_size_range(self.mock_msg, "all", 3, 3))

    def test_max_true(self):
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(self.plugin.image_size_range(self.mock_msg, "all", 1,
                                                     1, 3, 3))

    def test_max_false(self):
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(self.plugin.image_size_range(self.mock_msg, "all", 3,
                                                      3, 1, 1))

class TestImageToTextRatio(TestImageInfoBase):

    def test_min_true(self):
        self.mock_msg.text = "A"*12
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(self.plugin.image_to_text_ratio(self.mock_msg, "all", 2))

    def test_min_false(self):
        self.mock_msg.text = "A"*12
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(self.plugin.image_to_text_ratio(self.mock_msg, "all", 4))

    def test_max_true(self):
        self.mock_msg.text = "A"*12
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(self.plugin.image_to_text_ratio(self.mock_msg, "all",
                                                        2, 4))

    def test_max_false(self):
        self.mock_msg.text = "A"*12
        images = {1: self.new_image(2, 2, "jpg", "test.jpg")}
        self.plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(self.plugin.image_to_text_ratio(self.mock_msg, "all",
                                                        1, 2))

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
