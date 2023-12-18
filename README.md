# yara-yaml
Generate YARA rules from YAML source and Jinja templates.

This is a PoC to explore how to add some convenience through a sort of
detection-as-code approach to YARA rules.

Attributes related to rules are expressed as fields in YAML objects, making
them able to be read and manipulated in a machine-readable manner while
preserving much of the human readable elements of text-based rules. Jinja
templating supplies some convenience elements such as abstraction and injection
into the rules for features like macros.

## Setup
This prototype is designed to be operated from the checkout. From the top level
directory:

1. Create a Python virtual environment.

    `python3 -m venv env`

2. Install the yara-yaml package and dependencies in the virtualenv.

    `./env/bin/pip install .`

3. Use the command line tool to interface with the system.

    `./env/bin/yara-yaml --help`

## Usage
Pretty basic at this time. Sample content is present to demonstrate:

- Rule content lives in `rules/`.
- Rule templates live in `templates/`.
- Vars (setting variables and macros) live in `vars/`.

The most basic usage:

```
./env/bin/yara-yaml rules/network/malicious-traffic-distribution.yml
```

This should emit a YARA rule with all metadata and conditions taken directly
from the YAML rule source. The condition uses a macro to supply content matched
against an extrnal variable, and because the macro currently has a single
value, no transformation is applied to format it into a more complex regular
expression.

A more complex case, consisting of a strings section and a much more complex
macro application:

```
./env/bin/yara-yaml rules/file-characteristics.yml
```
