"""Main code module."""

import logging
import os
from os.path import join
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, FunctionLoader
from yaml import load as yaml_load

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader

from .filters import list_as_meta, regexpalt

# List all imported filter functions to later be registered
jinja_filters_local = [list_as_meta, regexpalt]

logger = logging.getLogger(__name__)

RULE_TEMPLATE_DIR = "templates"
VARS_DIR = "vars"
RULE_MACRO_DIR = "vars/macros"
RULE_TEMPLATE_SUFFIX = "yar.tmpl"
YAML_SUFFIX = "yml"


class YamlRuleBuilder:
    """YARA YAML rule builder.

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
        """Create a new YAML YARA rule builder."""
        self.rules_path = rules_path
        self.template_name = template

        # Load macros from files from RULE_MACRO_DIR and build a context
        self.macros_context = {}
        mp = Path(RULE_MACRO_DIR)
        for macrofile in mp.iterdir():
            # Include only macros files
            if (
                macrofile.is_file()
                and macrofile.suffix.lstrip(".") == YAML_SUFFIX
            ):
                logger.debug("loading macros from file: %s", macrofile)
                with open(macrofile, "rb") as f:
                    self.macros_context.update(yaml_load(f, Loader=SafeLoader))
        logger.debug("macros context: %s", self.macros_context)

        # Load the variable files from VARS_DIR and pass them as context
        # into the environment object. This requires ensuring that only regular
        # files are loaded.
        self.global_context = {}
        vp = Path(VARS_DIR)
        for varfile in vp.iterdir():
            # Include only vars files
            if varfile.is_file() and varfile.suffix.lstrip(".") == YAML_SUFFIX:
                logger.debug("loading variables from file: %s", varfile)
                with open(varfile, "rb") as f:
                    self.global_context.update(yaml_load(f, Loader=SafeLoader))
        logger.debug("global context: %s", self.global_context)

        template_file = f"{self.template_name}.{RULE_TEMPLATE_SUFFIX}"
        self.rule_env = Environment(
            loader=FileSystemLoader(RULE_TEMPLATE_DIR),
        )
        # Register the imported filter functions
        for f in jinja_filters_local:
            self.rule_env.filters[f.__name__] = f
        logging.debug("rule environment filters: %s", self.rule_env.filters)
        self.rule_template = self.rule_env.get_template(
            template_file, globals=self.global_context
        )

    def list_rule_templates(self):
        """List all templates in the configured templates directory.

        Return a list of dictionaries for the caller to render. Dictionary keys
        are the name of the template (the name the caller may specify) and the
        filename of the template.
        """
        templates = []
        suf = RULE_TEMPLATE_SUFFIX.split(".")[-1]
        for t in self.rule_env.list_templates(extensions=[suf]):
            templates.append({"name": t.split(".")[0], "template file": t})
        return templates

    def apply_templating(self, template, context):
        """Render specified template using the given context."""

        def load_rule_field(name):
            """Load rule context section for templatization.

            Load specified section of rule context as template for applying
            macro transformation.
            """
            if name == "strings":
                return rule_strings
            elif name == "condition":
                return rule_condition
            else:
                raise ValueError(f"Unsupported name specified: {name}")

        # Run loaded rule context strings and condition sections through
        # templating to apply macros.
        rule_strings = context.get("rule_strings")
        rule_condition = context.get("rule_condition")
        macro_env = Environment(
            loader=FunctionLoader(load_rule_field),
        )
        # Register the imported filter functions
        for f in jinja_filters_local:
            macro_env.filters[f.__name__] = f
        logging.debug("macro environment filters: %s", macro_env.filters)
        if rule_strings:
            rule_strings_template = macro_env.get_template(
                "strings", globals=self.global_context
            )
            context["rule_strings"] = rule_strings_template.render(
                self.macros_context
            )
        if rule_condition:
            rule_condition_template = macro_env.get_template(
                "condition", globals=self.global_context
            )
            context["rule_condition"] = rule_condition_template.render(
                self.macros_context
            )
        # Finally, run the updated complete rule context through
        # rule templating to build the rule.
        return template.render(context)

    def load_yaml_rules(self):
        """Load rules dict from YAML files.

        Load rules from YAML files in the configured rules path. If a single
        file is given, load the file. If a directory path is given, walk the
        directory tree to find and load them.

        TODO: Support Path.walk() interface, available in Python 3.12.
        """
        rules_files = []
        self.ruleset = []
        rp = Path(self.rules_path)
        logger.debug("configured rules path: %s", self.rules_path)
        if rp.is_file():
            # Add YAML file to the load list
            if rp.suffix.lstrip(".") == YAML_SUFFIX:
                rules_files.append(rp)
        elif rp.is_dir():
            # Walk the directory tree and add files to process
            logging.debug("walking rules directory tree: %s", rp)
            for root, dirs, files in os.walk(rp):
                logging.debug("current root: %s", root)
                logging.debug("child dirs: %s", dirs)
                logging.debug("child files: %s", files)
                for name in files:
                    logging.debug(
                        "suffix of identified file %s: %s",
                        name,
                        Path(name).suffix,
                    )
                    if Path(name).suffix.lstrip(".") == YAML_SUFFIX:
                        rules_files.append(join(root, name))

        logger.info("found %d YAML rule file(s) to process", len(rules_files))
        logger.debug("identified rules files: %s", rules_files)
        for rf in rules_files:
            with open(rf, "rb") as f:
                self.ruleset.extend(yaml_load(f, Loader=SafeLoader))
        logger.debug("loaded ruleset: %s", self.ruleset)

    def get_yara_rules(self):
        """Apply templating to loaded rules and emit ruleset.

        If auto import modules is configured, emit the specified modules
        prior to the rules. It's not clear if the multiple `yield`
        statements in this method is non-pythonic, but it seems to work.
        """
        logger.info("preparing to build ruleset from path %s", self.rules_path)
        self.load_yaml_rules()
        logger.debug("will build %d rule(s)", len(self.ruleset))
        if self.ruleset:
            if self.global_context.get("import_all_modules_auto"):
                for module in self.global_context["import_modules_list"]:
                    if (
                        self.template_name
                        in self.global_context["rule_full_templates"]
                    ):
                        yield f'import "{module}"'
                yield ""
        for r in self.ruleset:
            yield self.apply_templating(self.rule_template, r)
