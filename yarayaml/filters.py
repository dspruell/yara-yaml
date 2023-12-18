"""Jinja filters module."""

import re


def list_as_meta(value, s):
    """Convert a list of values into a dict of YARA metadata.

    Transform an input list of values into a dictionary of YARA metadata
    lines. Each line is given a unique metadata key name using a base
    string s appended with an incrementing zero-padded number, ensuring
    that the metadata key name is unique for each value. Keys and values are
    stripped of any errant leading or trailing whitespace.

    Arguments
    ---------
    value : list
        Values to convert into metadata
    s : str
        Base string to use as the metadata key name
    """
    s = s.strip()
    return {f"{s}{i+1:02}": value[i].strip() for i in range(len(value))}


def regexpalt(value, boundaries=True, strip=True):
    """Convert a list of strings into an alternation regular expression.

    Lists containing a single value are output as a bare string with no
    surrounding grouping parentheses. This sounds odd, but content authors may
    use macros that at first hold a single value but are expected to later
    contain multiple values. This ensures readability and no memory capture
    overhead where it makes sense.

    By default, using word boundary assertions is enabled since it is the
    recommended approach in most cases. Cases where this is not the desired
    behavior may explicitly omit it.

    List values are by default stripped of any leading and trailing
    whitespace. If this is not the desired behavior, it may be disabled.

    Arguments
    ---------
    value : list
        Values to convert into alternation string
    boundaries : bool
        Use word boundary zero-width assertions around regex
    strip : bool
        Strip leading and trailing whitespace from list values
    """
    if strip:
        value = [v.strip() for v in value]
    s = "|".join([re.escape(v) for v in value])
    if len(value) > 1:
        s = f"({s})"
        if boundaries:
            s = f"\\b{s}\\b"
    return s
