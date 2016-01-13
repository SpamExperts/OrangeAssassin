"""Load and set-up various configurations."""

import os
import logging

try:
    from raven.handlers.logging import SentryHandler
    _HAS_RAVEN = True
except ImportError:
    _HAS_RAVEN = False

import pad.rules.parser


def load_ruleset(sitepath, configpath, paranoid=False):
    """Read the site configuration path and the user
    configuration and create and return a new RuleSet.

    Each RuleSet manages a separate GlobalContext.
    """
    site_files = [os.path.join(sitepath, fp) for fp in os.listdir(sitepath)
                  if os.path.isfile(os.path.join(sitepath, fp)) and
                  (fp.endswith(".cf") or fp.endswith(".pre"))]
    site_files.sort()
    config_files = [os.path.join(configpath, fp) for fp in os.listdir(configpath)
                  if os.path.isfile(os.path.join(configpath, fp)) and
                  (fp.endswith(".cf") or fp.endswith(".pre"))]
    config_files.sort()

    all_files = site_files + config_files
    return pad.rules.parser.parse_pad_rules(all_files, paranoid)


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


