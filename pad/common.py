"""Common methods used across the project."""

import logging
import platform


def can_compile():
    """Check if compiling is supported or not on this environment."""
    logger = logging.getLogger("pad-logger")
    if "pypy" in platform.python_implementation().lower():
        logger.warning("Compiler is not available on PyPy")
        return False
    major, minor, patch = platform.python_version_tuple()
    if int(major) >= 3 and int(minor) < 5:
        logger.warning("Compiler is not available on 3.4 or lower.")
        return False
    # There's not going to be a Python 2.8 so this is safe.
    if int(major) <= 2 and (int(minor) < 7 or int(patch) < 11):
        logger.warning("Compiler is not available on 2.7.10 or lower.")
        return False
    return True


