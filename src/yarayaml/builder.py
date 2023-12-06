"""Main code module"""

import logging

from jinja2 import Environment, FileSystemLoader
from yaml import load

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader


logger = logging.getLogger(__name__)

LOREM = "rule test { condition: true }"
RULE_TEMPLATE_DIR = "templates"
RULE_TEMPLATE_SUFFIX = "yar.j2"

# XXX
print("logger in builder:", logger)


class YamlRuleBuilder:
    "XXX Conceptual class to house YARA ruleset builder logic"

    def __init__(self, rules_path, template="default"):
        """Invoke new YARA rule builder.

        Arguments
        ---------
        rules_path : str
            Filesystem path to rules directory root or a rules file containing
            YAML formatted rule content
        template : str, optional
            Name of rule template to use for building rules from rules file
            content. The specified name is appended with the rule template
            suffix to form the file name to use.
        """
        self.rules_path = rules_path
        template_file = f"{template}.{RULE_TEMPLATE_SUFFIX}"
        env = Environment(loader=FileSystemLoader(RULE_TEMPLATE_DIR))
        self.template = env.get_template(template_file)

    def apply_templating(self, context):
        return self.template.render(context)

    def load_yaml_rules(self):
        "XXX conceptual method to load rules dict from YAML file"

        with open(self.rules_path, "rb") as f:
            self.ruleset = load(f, Loader=SafeLoader)

    def get_yara_rules(self):
        "XXX conceptual method to templatize and return ruleset"

        logger.info("preparing to build ruleset from %s", self.rules_path)
        # XXX return dummy rule for now
        # return LOREM
        for r in self.ruleset:
            yield self.apply_templating(r)
