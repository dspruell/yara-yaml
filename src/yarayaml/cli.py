"""yara-yaml CLI"""

import logging
from argparse import ArgumentParser
from importlib.metadata import version

from tabulate import tabulate

from .builder import YamlRuleBuilder

__application_name__ = "yara-yaml"
__version__ = version(__application_name__)

DEFAULT_RULES_PATH = "rules"
LOG_LEVELS = ["critical", "error", "warning", "info", "debug"]
DEFAULT_LOG_LEVEL = "warning"
DEFAULT_RULE_TEMPLATE = "default"

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(module)s:%(lineno)s - %(message)s",
    level=DEFAULT_LOG_LEVEL.upper(),
)

logger = logging.getLogger(__name__)


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
        "--list-templates",
        "-L",
        action="store_true",
        help="list available rule templates",
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

    builder = YamlRuleBuilder(args.rules_path)

    # If templates list was requested, print it out and exit
    if args.list_templates:
        templates = builder.list_rule_templates()
        print(tabulate(templates))
        parser.exit()

    # Build rules and emit as output
    # for rule in builder.load_yaml_rules():
    #     print(rule)
    for rule in builder.get_yara_rules():
        print(rule)
