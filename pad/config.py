"""Load and set-up various configurations."""

import os
import logging

try:
    from raven.handlers.logging import SentryHandler
    _HAS_RAVEN = True
except ImportError:
    _HAS_RAVEN = False

import pad.rules.parser


def setup_logging(log_name, debug=False, filepath=None, sentry_dsn=None,
                  file_lvl="INFO", sentry_lvl="WARN"):
    """Setup logging according to the specified options. Return the Logger
    object.
    """
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

    stream_handler = logging.StreamHandler()

    if debug:
        stream_log_level = logging.DEBUG
        file_log_level = logging.DEBUG
    else:
        stream_log_level = logging.CRITICAL
        file_log_level = getattr(logging, file_lvl)

    logger = logging.getLogger(log_name)
    logger.setLevel(file_log_level)

    stream_handler.setLevel(stream_log_level)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    if filepath:
        file_handler = logging.FileHandler(filepath)
        file_handler.setLevel(file_log_level)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    if sentry_dsn and _HAS_RAVEN:
        sentry_level = getattr(logging, sentry_lvl)
        sentry_handler = SentryHandler(sentry_dsn)
        sentry_handler.setLevel(sentry_level)
        logger.addHandler(sentry_handler)

    return logger


def get_files_with_extension(path, extension):
    for p in os.listdir(path):
        if p.endswith(extension):
            yield os.path.join(path, p)


def get_config_files(config_path, siteconfig_path):
    """Return the .pre and .cf files in the correct order."""
    config_files = []
    config_files.extend(
        sorted(get_files_with_extension(siteconfig_path, ".pre")))
    config_files.extend(
        sorted(get_files_with_extension(config_path, ".pre")))
    config_files.extend(
        sorted(get_files_with_extension(config_path, ".cf")))
    config_files.extend(
        sorted(get_files_with_extension(siteconfig_path, ".cf")))

    return config_files




