"""Jinja filters module"""

import re


def list_as_meta(value, s):
    """Convert a list of values into a dict of YARA metadata.

    Transform an input list of values into a dictionary of YARA metadata
    lines. Each line is given a unique metadata key name using a base
    string s appended with an incrementing zero-padded number, ensuring
    that the metadata key name is unique for each value.

    Arguments
    ---------
    value : list
        Values to convert into metadata
    s : str
        Base string to use as the metadata key name
    """
    return {f"{s}{i+1:02}": value[i] for i in range(len(value))}


def regexpalt(value, boundaries=False):
    """Convert a list of strings into an alternation regular expression.

    Arguments
    ---------
    value : list
        Values to convert into alternation string
    boundaries : bool
        Whether to use word boundary zero-width assertions around regex
    """
    s = "|".join([re.escape(v) for v in value])
    s = f"({s})"
    if boundaries:
        s = f"\\b{s}\\b"
    return s
