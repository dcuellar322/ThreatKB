"""API reference generated from Flask's route registry."""

from flask import render_template_string
from inspect import getdoc


class Autodoc:
    def __init__(self, app):
        self.app = app

    def doc(self, **kwargs):
        return lambda view: view

    def html(self, **kwargs):
        routes = [
            {
                "path": rule.rule,
                "methods": ", ".join(sorted(rule.methods - {"HEAD", "OPTIONS"})),
                "description": getdoc(self.app.view_functions[rule.endpoint]) or "",
            }
            for rule in self.app.url_map.iter_rules()
            if rule.rule.startswith("/ThreatKB/")
        ]
        return render_template_string(
            "<!doctype html><html lang=en><title>ThreatKB API</title><h1>ThreatKB API</h1>"
            "{% for route in routes %}<h2>{{ route.methods }} {{ route.path }}</h2>"
            "<pre>{{ route.description }}</pre>{% endfor %}</html>",
            routes=routes,
        )
