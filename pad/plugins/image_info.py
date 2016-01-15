"""Image Info plugin."""

from __future__ import absolute_import, print_function

import re
from io import BytesIO

import PIL.Image

import pad.regex
import pad.plugins.base


class ImageInfoPlugin(pad.plugins.base.BasePlugin):


    eval_rules = ("image_count",
                  "image_named",
                  "pixel_coverage",
                  "image_size_exact",
                  "image_size_range",
                  "image_to_text_ratio")
    options = {}

    def _image_info(self, content):
        imginfo = {}
        img_io = BytesIO(content)
        image = PIL.Image.open(img_io)

        imginfo['width'],imginfo['height'] = image.size
        imginfo['coverage'] = imginfo['width']*imginfo['height']
        img_io.close()
        return imginfo

    def extract_metadata(self, msg, payload, part):
        """Extend to extract image metadata"""

        if part.get_content_maintype() == "image":
            try:
                images = self.get_local(msg, "images")
            except KeyError:
                images = {}

            imginfo = self._image_info(part.get_payload(decode=True))
            imginfo['name'] = part.get_param("name")
            imginfo['subtype'] = part.get_content_subtype()
            images[part.get("Content-ID")] = imginfo
            self.set_local(msg, "images", images)

    def image_named(self, msg, name, target=None):
        """Match if the image matches a name."""
        try:
            images = self.get_local(msg, "images")
        except:
            images = {}
        for cid, image in images.items():
            if image['name'] == name:
                return True
        return False

    def image_name_regex(self, msg, regex, target=None):
        """Match if the name matches a regular expression."""
        pregex = pad.regex.perl2re(regex)
        name_re = re.compile(regex)
        try:
            images = self.get_local(msg, "images")
        except:
            images = {}
        for cid, image in images.items():
            if name_re.match(name):
                return True
        return False

    def image_size_exact(self, msg, img_type, height, width,
                         target=None):
        """Match by image size."""
        try:
            images = self.get_local(msg, "images")
        except:
            images = {}
        for cid, image in images.items():
            if img_type == "all" or img_type == image['subtype']:
                if image['width'] == width and image['height'] == height:
                    return True
        return False

    def image_count(self, msg, img_type, min_count, max_count=None, target=None):
        """Match number of images all or by type."""
        count = 0
        try:
            images = self.get_local(msg, "images")
        except:
            images = {}
        for cid, image in images.items():
            if img_type == "all" or img_type == image['subtype']:
                count+=1

        if max_count:
            return count >= min_count and count <= max_count
        else:
            return count >= min_count

    def pixel_coverage(self, msg, img_type, min_coverage, max_coverage=None,
                       target=None):
        """Determine the pixel coverage"""
        try:
            images = self.get_local(msg, "images")
        except:
            images = {}
        for cid, img in images.items():
            if img_type == "all" or img_type == img['subtype']:
                if max_coverage:
                    if img['coverage'] >= min_coverage and img['coverage'] <= max_coverage:
                        return True
                else:
                    if img['coverage'] >= min_coverage:
                        return True
        return False

    def image_size_range(self, msg, img_type, min_height, min_width,
                         max_height=None, max_width=None, target=None):
        """Minimum/ranged dimensions matches"""
        try:
            images = self.get_local(msg, "images")
        except:
            images = {}

        for cid, img in images.items():
            if img_type == "all" or img_type == img['subtype']:

                if img['width'] < min_width:
                    continue

                if img['height'] < min_height:
                    continue

                if max_width and img['width'] > max_width:
                    continue

                if max_height and img['height'] > max_height:
                    continue

                return True

        return False

    def image_to_text_ratio(self, msg, img_type, min_ratio, max_ratio=None,
                            target=None):
        """Image to text or html ratio"""
        try:
            images = self.get_local(msg, "images")
        except:
            images = {}
        for cid, img in images.items():
            if img_type == "all" or img_type == img['subtype']:
                try:
                    ratio = len(msg.text)/img['coverage']
                except ZeroDivisionError:
                    continue

                if max_ratio:
                    if ratio >= min_ratio and ratio <= max_ratio:
                        return True
                else:
                    if ratio >= max_ratio:
                        return True
        return False
