# yara-yaml
YARA rules from YAML and Jinja templates.

This is a PoC to explore how to add some convenience through a sort of
detection-as-code approach to YARA rules.

Attributes related to rules are expressed as fields in YAML objects, making
them able to be read and manipulated in a machine-readable manner while
preserving much of the human readable elements of text-based rules. Jinja
templating supplies some convenience elements such as abstraction and injection
into the rules for features like macros.
