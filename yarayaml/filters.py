"""Jinja template filters."""

import re
from pathlib import Path

from yaml import load as yaml_load

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader

import logging

from . import VARS_DIR
from .exceptions import TooManyMacroValuesError

logger = logging.getLogger(__name__)

# Load variables in main variable file as a configuration dictionary
config_file = Path(VARS_DIR / "main.yml")
with open(config_file, "r") as f:
    config = yaml_load(f, Loader=SafeLoader)


def list_as_meta(values, s):
    """Convert a list of values into unique YARA metadata.

    YARA does not allow metadata to be composed as multi-value lists, but
    rather metadata identifiers must be unique. This filter transforms an
    input list of values into a dictionary of YARA metadata lines. Each
    line is given a unique metadata identifier using a base string, s, appended
    with an incrementing zero-padded number, ensuring that the metadata
    identifier name is unique for each value. Identifiers and values are
    stripped of leading and trailing whitespace.

    Arguments
    ---------
    values : list
        Values to convert into metadata
    s : str
        Base string to use in the metadata identifier
    """
    s = s.strip()
    return {f"{s}{i+1:02}": values[i].strip() for i in range(len(values))}


def regexpalt(values, strname="", modifiers=[], boundaries=True, strip=True):
    """Convert a list of strings into an alternation regular expression.

    This filter formats a list of values into a YARA regular expression
    alternation string, applying escape characters where needed using the
    Python re module.

    ```
    In [1]: x = ["foo.com", "bar.net", "baz.org.uk"]
    In [2]: print(regexpalt(x))
    \b(foo\.com|bar\.net|baz\.org\.uk)\b  # noqa: W605
    ```

    Lists containing a single value are output as a bare string with no
    surrounding grouping parentheses. This accommodates content authors who
    use macros that may at first hold a single value but are expected to
    later expand to multiple values. This ensures better readability and no
    memory capture overhead where it makes sense.

    ```
    In [1]: x = ["foo.com"]
    In [2]: print(regexpalt(x))
    foo\.com
    ```

    By default, word boundary assertions are placed around the alternation
    expression to ensure more precise matching. This may be disabled if it is
    not the desired behavior.

    List values are by default stripped of any leading and trailing whitespace.
    This too may be disabled.

    The filter also supports another mode of operation, which is required in
    cases that large macros containing many values are used in rules. In these
    cases, a resulting alternation regular expression string may trigger an
    internal resource limit in YARA which results in an error with expensive
    regular expressions. In these cases, it is possible to use the `strname`
    and `modifiers` keyword arguments to specify a base string identifier name
    and optional string modifiers to use when rendering a complete block of
    alternation regular expression strings, each containing a portion of the
    macro that matches without triggering YARA's resource limit.

    Arguments
    ---------
    values : list
        Values to convert into an alternation regular expression
    strname : str
        Output a block of complete YARA regular expression named using
        the base string in `strname`. If the number of values exceeds
        `macros_split_limit`, values are split into multiple strings given
        unique names using this argument value as a prefix.
    modifiers : list
        Append the given list of pattern modifiers (such as *nocase*,
        *ascii*, and *wide*) to the end of each string in a block composed with
        the use of `strname`.
    boundaries : bool
        Use word boundary zero-width assertions around regex
    strip : bool
        Strip leading and trailing whitespace from list values
    """

    def _get_regex_str(values):
        """
        Format and return a regular expression alternation string from a
        list of input values.
        """
        if strip:
            values = [v.strip() for v in values]
        s = "|".join([re.escape(v) for v in values])
        if len(values) > 1:
            s = f"({s})"
            if boundaries:
                s = f"\\b{s}\\b"
        return s

    split_limit = config["macros_split_limit"]
    num_vals = len(values)
    val_buckets = []
    modifiers_str = " ".join(modifiers)
    logging.debug(
        "modifiers: (kwarg): %s, (str): %s", modifiers, modifiers_str
    )

    # XXX I think I have something wrong here
    # val_buckets = [
    #     values[i : i + split_limit] for i in range(0, num_vals, split_limit)
    # ]
    for i in range(0, num_vals, split_limit):
        # val_buckets.append(values[i:i+split_limit])
        max_val = i + split_limit
        val_buckets.append(values[i:max_val])
    num_buckets = len(val_buckets)
    logging.debug(
        "resulting value buckets list of length %d: %s",
        num_buckets,
        val_buckets,
    )

    # Following is the error case: we have a macro with too many values and
    # the filter is not set up to output multiple strings.
    # XXX This may require a way to determine the rule and macro where this
    # XXX situation is occurring in the filter.
    if num_buckets > 1 and not strname:
        logger.error(
            "macro has too many values (%d) and no base string is specified",
            num_vals,
        )
        raise TooManyMacroValuesError(
            "The number of values in a the macro exceeds the amount "
            "that may result in a rule that won't function due to YARA "
            "regular expression complexity limits. It is recommended "
            "to set the filter to use the `strname` argument to place "
            "values into multiple strings and then adjust the rule "
            "conditions to work with this, if required."
        )

    # If strname is set, the caller has explicitly invoked the filter with
    # the argument, so output a string consisting of a block of formatted YARA
    # string names and values.
    if strname:
        strname = strname.strip()
        str_dict = {}
        i = 0
        for vb in val_buckets:
            i += 1
            str_dict.update({f"{strname}_{i:02}": _get_regex_str(vb)})
        logger.debug(
            "about to render the strname string dictionary: %s", str_dict
        )
        return "\n".join(
            [f"${k} = /{v}/ {modifiers_str}" for k, v in str_dict.items()]
        )

    # By this point, strname is not set, and we should be down to a
    # single list of values that will work successfully in a YARA regular
    # expression string.
    logging.debug(
        "value buckets - expected single bucket case: %s", val_buckets
    )
    return _get_regex_str(values)
