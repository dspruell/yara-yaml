"""Program exceptions."""


class TooManyMacroValuesError(Exception):
    """Error indicating too many values in a macro.

    Exception raised when the number of values in a macro list exceed
    the count that is expected to result in too complex a Python regular
    expression string and, thus, a broken ruleset. In this case, the caller
    should refactor the rule logic and allow the filter to fill multiple
    strings with the values.
    """
    pass
