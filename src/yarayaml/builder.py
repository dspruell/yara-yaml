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

from .filters import list_as_meta, regexpalt

# List all imported filter functions (these are later registered)
jinja_filters = [list_as_meta, regexpalt]

logger = logging.getLogger(__name__)

LOREM = "rule test { condition: true }"
RULE_TEMPLATE_DIR = "templates"
VARS_DIR = "vars"
RULE_TEMPLATE_SUFFIX = "yar.tmpl"
RULE_YAML_SUFFIX = "yml"


class YamlRuleBuilder:
    """YARA rule builder.

    Arguments
    ---------
    rules_path : str
        Filesystem path to rules directory root or a rules file containing
        YAML formatted rule content
    template : str
        Name of rule template to use for building rules from rules file
        content. The specified name is appended with the rule template
        suffix to form the file name to use.
    """

    def __init__(self, rules_path, template):
        self.rules_path = rules_path

        # Load the variable files from VARS_DIR and pass them as context
        # into the environment object
        global_vars = {}
        p = Path(VARS_DIR)
        for varfile in p.iterdir():
            logger.debug("varfile: %s", varfile)
            with open(varfile, "rb") as f:
                global_vars.update(load(f, Loader=SafeLoader))
        logger.debug("global_vars: %s", global_vars)

        template_file = f"{template}.{RULE_TEMPLATE_SUFFIX}"
        env = Environment(
            loader=FileSystemLoader(RULE_TEMPLATE_DIR),
        )
        # Register imported filter functions
        for f in jinja_filters:
            env.filters[f.__name__] = f
        logging.debug("env.filters: %s", env.filters)
        self.template = env.get_template(template_file, globals=global_vars)

    def list_rule_templates(self):
        "List all templates in the configured templates directory"

        p = Path(RULE_TEMPLATE_DIR)
        contents = list(p.iterdir())
        logger.info("listing a total of %d templates", len(contents))
        return [[str(_)] for _ in contents]

    def apply_templating(self, context):
        "Render the template"

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
        "Templatize and return ruleset"

        logger.info("preparing to build ruleset from %s", self.rules_path)
        # XXX return dummy rule for now
        # return LOREM
        self.load_yaml_rules()
        for r in self.ruleset:
            yield self.apply_templating(r)
