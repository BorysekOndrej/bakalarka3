# this requires graphviz, which is not python module
pydeps app -o tmp/dependencies.svg
# pydeps app --include-missing -o tmp/dependencies_including_missing.svg
# pydeps app --show-cycles -o tmp/circle_dependencies.svg # this somewhat misbehaves
