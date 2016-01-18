"""Image Info plugin."""

from __future__ import absolute_import

import re
from io import BytesIO
from hashlib import md5
from collections import defaultdict

import pad.errors

try:
    import PIL.Image
except ImportError:
    raise pad.errors.PluginLoadError(
        "ImageInfoPlugin not loaded, You must install Pillow to use this plugin")

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


    def _get_image_sizes(self, payload):
        imginfo = {}
        img_io = BytesIO(payload)
        image = PIL.Image.open(img_io)

        imginfo['width'],imginfo['height'] = image.size
        img_io.close()
        return imginfo

    def _get_local_images(self, msg):
        try:
            return self.get_local(msg, "images")
        except KeyError:
            return {}

    def _get_image_names(self, msg):

        try:
            return self.get_local(msg, "names")
        except KeyError:
            return []

    def _get_count(self, msg, subtype="all"):
        """Get count for a subtype or all"""
        try:
            counts = self.get_local(msg, "counts")
            return counts.get(subtype)
        except KeyError:
            return 0

    def _update_counts(self, msg, subtype, by):
        """Update the cumulative and subtype image counts."""

        try:
            counts = self.get_local(msg, "counts")
        except KeyError:
            counts = defaultdict(int)

        counts['all'] += by
        counts[subtype] += by
        self.set_local(msg, "counts", counts)

    def _add_name(self, msg, name):
        """Add a name to the names list."""
        try:
            names = self.get_local(msg, "names")
        except KeyError:
            names = set()
        names.add(name)
        self.set_local(msg, "names", names)

    def _add_id(self, msg, image_id):
        """Add an id to the id list to avoid unecessary work."""
        try:
            names = self.get_local(msg, "ids")
        except KeyError:
            ids = set()
        ids.add(image_id)
        self.set_local(msg, "ids", image_id)


    def _update_coverage(self, msg, subtype, by):
        """Updates the coverage for all and specific image types."""
        try:
            coverage = self.get_local(msg, "coverage")
        except KeyError:
            coverage = defaultdict(int)
        coverage["all"] += by
        coverage[subtype] += by
        self.set_local(msg, "coverage", coverage)

    def _get_coverage(self, msg, subtype):
        try:
            coverage = self.get_local(msg, "coverage")
        except KeyError:
            coverage = defaultdict(int)

        return coverage.get(subtype, 0)


    def _save_stats(self, msg, payload, subtype):
        """Extracts and saves image stats once per unique image."""

        image_id = md5(payload).hexdigest()

        try:
            sizes = self.get_local(msg, "sizes")
        except KeyError:
            sizes = defaultdict(dict)

        if image_id in sizes['all']:
            img = sizes['all'][image_id]
            area = img['width']*img['height']
            self._update_coverage(msg, subtype, area)

        else:
            img = self._get_image_sizes(payload)

            sizes['all'][image_id] = img
            sizes[subtype][image_id] = img

            self.set_local(msg, "sizes", sizes)
            area = img['width']*img['height']
            self._update_coverage(msg, subtype, area)

    def _get_sizes(self, msg, subtype):
        try:
            sizes = self.get_local(msg, "sizes")
        except KeyError:
            sizes = defaultdict(list)

        return sizes.get(subtype, {})

    def _get_pixel_coverage(self, msg, subtype):
        try:
            local_stats = self.get_local(msg, "pixel_coverage")
        except KeyError:
            local_stats = defaultdict(list)

        return local_stats.get(subtype, [])



    def _local_ids(self, msg):
        """Set of image ids to avoid loading the same image twice in PIL."""
        try:
            return self.get_local(msg, "ids")
        except KeyError:
            return set()


    def extract_metadata(self, msg, payload, part):
        """Extend to extract image metadata"""

        if part.get_content_maintype() == "image":

            name = part.get_param("name")
            subtype = part.get_content_subtype()

            self._add_name(msg, name)
            self._update_counts(msg, subtype, by=1)
            self._save_stats(msg, part.get_payload(decode=True), subtype)


    def image_named(self, msg, name, target=None):
        """Match if the image matches a name."""
        return name in self._get_image_names(msg)

    def image_name_regex(self, msg, regex, target=None):
        """Match if the name matches a regular expression."""
        name_re = pad.regex.perl2re(regex)
        names = self._get_image_names(msg)
        for name in names:
            if name_re.match(name):
                return True
        return False

    def image_size_exact(self, msg, img_type, height, width,
                         target=None):
        """Match by image size."""
        stats = self._get_sizes(msg, img_type)
        for img in stats.values():
            if (img['width'], img['height']) == (width, height):
                return True
        return False

    def image_count(self, msg, img_type, min_count, max_count=None, target=None):
        """Match number of images all or by type."""

        count = self._get_count(msg, img_type)
        if max_count:
            return min_count <= count <= max_count
        else:
            return min_count <= count

    def pixel_coverage(self, msg, img_type, min_coverage, max_coverage=None,
                       target=None):
        """Determine the pixel coverage"""
        coverage = self._get_coverage(msg, img_type)
        if max_coverage:
            return min_coverage <= coverage <= max_coverage
        return min_coverage <= coverage

    def image_size_range(self, msg, img_type, min_height, min_width,
                         max_height=None, max_width=None, target=None):
        """Minimum/ranged dimensions matches"""
        stats = self._get_sizes(msg, img_type)
        for img in stats.values():

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

        if target=="body":
            text_len = len(msg.text)
        else:
            text_len = len(msg.raw_text)
        coverage = float(self._get_coverage(msg, img_type))
        try:
            ratio = text_len/coverage
        except ZeroDivisionError:
            ratio = text_len
        if max_ratio:
            return min_ratio <= ratio <= max_ratio

        return min_ratio <= ratio
