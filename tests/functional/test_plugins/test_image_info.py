"""Test the image_info plugin"""
import email
import os
import unittest
import tests.util
from tests.util.image_utils import new_email, new_image

TESTDATA_DIR = os.path.join(os.getcwd(), "tests", "data")

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

CONFIG_COVERAGE = r"""
body            GIF_AREA_40K         eval:pixel_coverage('gif','35000','45000')
"""

CONFIG_RANGE = r"""
body          DC_GIF_200_300         eval:image_size_range('gif', 200, 300, 250, 350)
"""

CONFIG_IMG_RATIO = r"""
body          DC_GIF_TEXT_RATIO       eval:image_to_text_ratio('gif',0.000, 0.008)
describe      DC_GIF_TEXT_RATIO       Low body to GIF pixel area ratio
"""


class TestImageInfo(tests.util.TestBase):
    def setUp(self):
        tests.util.TestBase.setUp(self)

    def tearDown(self):
        tests.util.TestBase.tearDown(self)

    def test_image_name(self):
        """Check message for image name"""
        self.setup_conf(CONFIG_NAMED,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(1, 1, "gif", "image001.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '1.0')

    def test_image_size(self):
        """Check message for image size"""
        self.setup_conf(CONFIG_SIZED,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(127, 264, "gif", "image001.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '1.0')

    def test_image_count(self):
        """Check message for images count"""
        self.setup_conf(CONFIG_COUNT,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(127, 264, "gif", "image001.gif"),
             2: new_image(127, 264, "png", "image002.png")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '2.0')

    def test_image_pixel_coverage(self):
        """Check message for image pixel coverage"""
        self.setup_conf(CONFIG_COVERAGE,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(200, 200, "gif", "image001.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '1.0')

    def test_image_range(self):
        """Check message for image with size in range"""
        self.setup_conf(CONFIG_RANGE,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(320, 220, "gif", "image001.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '1.0')

    def test_image_text_ratio(self):
        """Check message for ration between text and images"""
        self.setup_conf(CONFIG_IMG_RATIO,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(127, 264, "gif", "image001.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '1.0')

    def test_image_count_fail(self):
        """Fail for images count"""
        self.setup_conf(CONFIG_COUNT,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(127, 264, "jpg", "image001.jpg"),
             2: new_image(127, 264, "jpg", "image002.jpg")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '0.0')

    def test_image_size_fail(self):
        """Fail for image size"""
        self.setup_conf(CONFIG_SIZED,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(127, 222, "gif", "image001.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '0.0')

    def test_pixel_coverage_fail(self):
        """Fail for image pixel coverage"""
        self.setup_conf(CONFIG_COVERAGE,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(2, 2, "gif", "image001.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '0.0')

    def test_image_name_fail(self):
        """Fail for image name"""
        self.setup_conf(CONFIG_NAMED,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(1, 1, "gif", "image0011.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '0.0')

    def test_many_rules_match(self):
        """Check message for image name, size and count"""
        self.setup_conf(CONFIG_NAMED + "\n" + CONFIG_SIZED +
                        "\n" + CONFIG_COUNT,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(127, 264, "gif", "image001.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '3.0')

    def test_one_of_many_match(self):
        """Check message for image name, size and coverage
        and only name is equal"""
        self.setup_conf(CONFIG_NAMED + "\n" + CONFIG_SIZED +
                        "\n" + CONFIG_COVERAGE,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(100, 100, "gif", "image001.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '1.0')

    def test_no_matches_of_many(self):
        """Check message for image name, size and coverage
        and no matches"""
        self.setup_conf(CONFIG_NAMED + "\n" + CONFIG_SIZED +
                        "\n" + CONFIG_COVERAGE,
                        pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                        "report _SCORE_")
        msg = new_email(
            {1: new_image(100, 100, "gif", "image002.gif")})
        result = self.check_pad(msg.as_string())
        self.assertEqual(result, '0.0')

    def test_real_msg_with_errors(self):
        """Check real multipart message"""
        self.setup_conf(CONFIG_NAMED + "\n" + CONFIG_SIZED +
                "\n" + CONFIG_COVERAGE,
                pre_config="loadplugin pad.plugins.image_info.ImageInfoPlugin\n"
                "report _SCORE_")
        with open(os.path.join(TESTDATA_DIR, "multipart.eml")) as m:
            msg = email.message_from_file(m)
            result = self.check_pad(msg.as_string())
        self.assertEqual(result, '0.0')


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestImageInfo, "test"))
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
