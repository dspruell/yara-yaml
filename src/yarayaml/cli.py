"""yara-yaml CLI"""

import logging
from argparse import ArgumentParser
from importlib.metadata import version

from .builder import YamlRuleBuilder

__application_name__ = "yara-yaml"
__version__ = version(__application_name__)

DEFAULT_RULES_PATH = "rules"
LOG_LEVELS = ["critical", "error", "warning", "info", "debug"]
DEFAULT_LOG_LEVEL = "warning"

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(module)s:%(lineno)s %(message)s",
    level=DEFAULT_LOG_LEVEL.upper(),
)

logger = logging.getLogger(__name__)
# XXX
print("logger in cli:", logger)


def main():
    "Main CLI function"

    parser = ArgumentParser()
    parser.add_argument(
        "rules_path",
        nargs="?",
        default=DEFAULT_RULES_PATH,
        help="path to YAML rules directory or file (default: %(default)s)",
    )
    parser.add_argument(
        "--log-level",
        "-l",
        choices=LOG_LEVELS,
        default=DEFAULT_LOG_LEVEL,
        help="set logging level",
    )
    parser.add_argument(
        "--version",
        "-V",
        version=__version__,
        action="version",
        help="show program version",
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(args.log_level.upper())
    # XXX
    print("logger in cli:", logger)

    builder = YamlRuleBuilder(args.rules_path)
    # ruleset = builder.get_yara_rules()
    # ruleset = builder.load_yaml_rules()
    for rule in builder.load_yaml_rules():
        print(rule)
    # print(ruleset)
