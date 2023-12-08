"""Main code module"""

import logging
import os
from os.path import join
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from yaml import load

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader


logger = logging.getLogger(__name__)

LOREM = "rule test { condition: true }"
RULE_TEMPLATE_DIR = "templates"
RULE_TEMPLATE_SUFFIX = "yar.tmpl"
RULE_YAML_SUFFIX = "yml"


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

    def list_rule_templates(self):
        "List all templates in the configured templates directory"
        p = Path(RULE_TEMPLATE_DIR)
        contents = list(p.iterdir())
        logger.info("listing a total of %d templates", len(contents))
        return [[str(_) for _ in contents]]

    def apply_templating(self, context):
        return self.template.render(context)

    def load_yaml_rules(self):
        """Load rules dict from YAML files.

        Load rules from YAML files in the configured rules path. If a single
        file is given, load the file. If a directory path is given, walk the
        directory tree to find and load them.

        TODO: Support Path.walk() interface, available in Python 3.12.
        """
        rules_files = []
        p = Path(self.rules_path)
        logger.debug("configured rules_path: %s", self.rules_path)
        if p.is_file():
            # Add YAML file to the load list
            if p.suffix.lstrip(".") == RULE_YAML_SUFFIX:
                rules_files.append(p)
        elif p.is_dir():
            # Walk the directory tree and add files to process
            for root, dirs, files in os.walk(p):
                logging.debug("root: %s", root)
                logging.debug("dirs: %s", dirs)
                logging.debug("files: %s", files)
                for name in files:
                    logging.debug("suffix of %s: %s", name, Path(name).suffix)
                    if Path(name).suffix.lstrip(".") == RULE_YAML_SUFFIX:
                        rules_files.append(join(root, name))

        logger.info("found %d YAML rule file(s) to process", len(rules_files))
        logger.debug("rules_files: %s", rules_files)
        with open(self.rules_path, "rb") as f:
            self.ruleset = load(f, Loader=SafeLoader)
        logger.debug("self.ruleset: %s", self.ruleset)

    def get_yara_rules(self):
        "XXX conceptual method to templatize and return ruleset"
        logger.info("preparing to build ruleset from %s", self.rules_path)
        # XXX return dummy rule for now
        # return LOREM
        self.load_yaml_rules()
        for r in self.ruleset:
            yield self.apply_templating(r)
