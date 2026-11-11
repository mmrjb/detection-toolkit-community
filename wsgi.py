"""WSGI entry point for an optional WSGI server: ``wsgi:app``.

The README uses ``python -m detection_toolkit serve`` instead. Importing this
module builds the app but never creates or changes the database.
"""
from detection_toolkit import create_app

app = create_app()
