"""Forensia package."""

from forensia.core.verdicts import set_taxonomy_path
from forensia.knowledge.resources import schema_dir

__all__ = ["__version__"]

__version__ = "0.1.0"

# Package composition root: platform consumers validate against the packaged
# YAML authority without duplicating its values or requiring entry-point-specific setup.
set_taxonomy_path(schema_dir() / "verdict_taxonomy.yaml")
