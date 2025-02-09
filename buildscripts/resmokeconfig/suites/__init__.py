"""
Defines a mapping of shortened names for suite configuration files to
their full path.
"""

from __future__ import absolute_import

import os
import os.path


def _get_named_suites():
    """
    Explores this directory for any YAML configuration files.

    Returns a mapping of basenames without the file extension to their
    full path.
    """

    dirname = os.path.dirname(__file__)
    named_suites = {}

    try:
        (root, _dirs, files) = os.walk(dirname).next()
        for filename in files:
            (short_name, ext) = os.path.splitext(filename)
            if ext in (".yml", ".yaml"):
                pathname = os.path.join(root, filename)
                named_suites[short_name] = os.path.relpath(pathname)
    except StopIteration:
        # 'dirname' does not exist, which should be impossible because it contains __file__.
        raise IOError("Directory '%s' does not exist" % (dirname))

    return named_suites

NAMED_SUITES = _get_named_suites()
