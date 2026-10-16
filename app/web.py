"""WSGI entrypoint: serve immediately while the shared catalog cache warms."""

from app import generate_app

app = generate_app()
