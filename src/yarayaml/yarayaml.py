"""Main code module"""

import logging

from yaml import load

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader


logger = logging.getLogger(__name__)

LOREM = "rule test { condition: true }"


class YamlRuleBuilder:
    "XXX Conceptual class to house YARA ruleset builder logic"

    def __init__(self, rules_path):
        self.rules_path = rules_path

    def apply_templating(self):
        pass

    def load_yaml_rules(self):
        "XXX conceptual method to load rules dict from YAML file"

        with open(self.rules_path, "rb") as f:
            ruleset = load(f, Loader=SafeLoader)
        return ruleset

    def get_yara_rules(self):
        "XXX conceptual method to templatize and return ruleset"

        logger.info("preparing to build ruleset from %s", self.rules_path)
        # XXX return dummy rule for now
        return LOREM
