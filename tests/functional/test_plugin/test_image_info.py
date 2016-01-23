"""Test the image_info plugin"""
import os
import unittest
import tests.util
from tests.util.image_utils import new_email, new_image

CONFIG_NAMED = r"""
body         DC_IMAGE001_GIF         eval:image_named('image001.gif')
describe     DC_IMAGE001_GIF         Contains image named image001.gif
"""

CONFIG_SIZED = r"""
body         DC_GIF_264_127          eval:image_size_exact('gif','264','127')
describe     DC_GIF_264_127          Found 264x127 pixel gif, possible pillz
"""

CONFIG_COUNT = r"""
body            GIF_ATTACH_1          eval:image_count('gif','1','1')
body            GIF_ATTACH_2P         eval:image_count('gif','2')

body            PNG_ATTACH_1          eval:image_count('png','1','1')
body            PNG_ATTACH_2P         eval:image_count('png','2')
"""


class TestImageInfo(tests.util.TestBase):
    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    def test_simple_image_name(self):
        """Check message for image name """
        cwd = os.path.join(os.getcwd(), "pad", "plugins", "image_info.py")
        self.setup_conf(CONFIG_NAMED,
                        pre_config="loadplugin ImageInfoPlugin {0}\n"
                        "report _SCORE_".format(cwd))
        msg = new_email(
            {1: new_image(1, 1, "gif", "image001.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '1.0')

    def test_simple_image_size(self):
        """Check message for image size """
        cwd = os.path.join(os.getcwd(), "pad", "plugins", "image_info.py")
        self.setup_conf(CONFIG_SIZED,
                        pre_config="loadplugin ImageInfoPlugin {0}\n"
                        "report _SCORE_".format(cwd))
        msg = new_email(
            {1: new_image(127, 264, "gif", "image001.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '1.0')

    def test_simple_image_count(self):
        """Check message for image size """
        cwd = os.path.join(os.getcwd(), "pad", "plugins", "image_info.py")
        self.setup_conf(CONFIG_SIZED,
                        pre_config="loadplugin ImageInfoPlugin {0}\n"
                        "report _SCORE_".format(cwd))
        msg = new_email(
            {1: new_image(127, 264, "gif", "image001.gif"),
             2: new_image(127, 264, "png", "image002.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '1.0')


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestImageInfo, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
