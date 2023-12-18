"""yara-yaml rule builder package."""

from pathlib import Path

RULE_TEMPLATE_DIR = Path.cwd() / "templates"
VARS_DIR = Path.cwd() / "vars"
RULE_MACRO_DIR = VARS_DIR / "macros"
