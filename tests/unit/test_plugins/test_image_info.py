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

class TestImageInfo(unittest.TestCase):

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

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def new_image(self, width, height, subtype, name):
        image = Image.new("RGB", (width,height))
        img_io = BytesIO()
        image.save(img_io, format="JPEG")
        return {"data": img_io,
                "name": name,
                "subtype": subtype,
                "width": width,
                "height": height,
                "coverage": width*height}

    def new_email(self, images):
        msg = MIMEMultipart()
        for image in images:
            mimg = MIMEImage(image['data'].read(), _subtype=image['subtype'])
            mimg.add_header("Content-Disposition", "inline", filename="name")
            msg.attach(mimg)
        return msg


class TestImageCount(TestImageInfo):

    def test_min_true(self):
        self.mock_msg.msg = None
        plugin = pad.plugins.image_info.ImageInfoPlugin(self.mock_ctxt)
        images = {x: self.new_image(1, 1, "jpg", "test") for x in range(5)}
        plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(plugin.image_count(self.mock_msg, "all", 2))

    def test_min_false(self):
        self.mock_msg.msg = None
        plugin = pad.plugins.image_info.ImageInfoPlugin(self.mock_ctxt)
        images = {x: self.new_image(1, 1, "jpg", "test") for x in range(5)}
        plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(plugin.image_count(self.mock_msg, "all", 7))

    def test_max_true(self):
        self.mock_msg.msg = None
        plugin = pad.plugins.image_info.ImageInfoPlugin(self.mock_ctxt)
        images = {x: self.new_image(1, 1, "jpg", "test") for x in range(5)}
        plugin.set_local(self.mock_msg, "images", images)
        self.assertTrue(plugin.image_count(self.mock_msg, "all", 2, 6))

    def test_max_false(self):
        self.mock_msg.msg = None
        plugin = pad.plugins.image_info.ImageInfoPlugin(self.mock_ctxt)
        images = {x: self.new_image(1, 1, "jpg", "test") for x in range(5)}
        plugin.set_local(self.mock_msg, "images", images)
        self.assertFalse(plugin.image_count(self.mock_msg, "all", 2, 3))


class TestImageNamed(TestImageInfo):

    def test_true(self):
        pass

    def test_false(self):
        pass


class TestImageNameRegex(TestImageInfo):

    def test_true(self):
        pass

    def test_false(self):
        pass

class TestPixelCoverage(TestImageInfo):

    def test_min_true(self):
        pass

    def test_min_false(self):
        pass

    def test_max_true(self):
        pass

    def test_max_false(self):
        pass

class TestImageSizeExact(TestImageInfo):

    def test_min_true(self):
        pass

    def test_min_false(self):
        pass

    def test_max_true(self):
        pass

    def test_max_false(self):
        pass


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestImageCount, "test"))
    test_suite.addTest(unittest.makeSuite(TestImageNamed, "test"))
    test_suite.addTest(unittest.makeSuite(TestImageNameRegex, "test"))
    test_suite.addTest(unittest.makeSuite(TestImageSizeExact, "test"))
    test_suite.addTest(unittest.makeSuite(TestPixelCoverage, "test"))
    return test_suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
