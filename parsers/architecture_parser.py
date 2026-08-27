import json
from pathlib import Path
from typing import Any

import yaml

from threat_engine.models import Architecture


def parse_architecture(document: Architecture | dict[str, Any] | str) -> Architecture:
    """Parse a model, mapping, JSON document, YAML document, or file path."""
    if isinstance(document, Architecture):
        return document
    if isinstance(document, dict):
        return Architecture.model_validate(document)
    if not isinstance(document, str):
        raise ValueError("Architecture must be an object, JSON, YAML, or file path")

    raw = document
    if "\n" not in document and "\r" not in document:
        source = Path(document)
        try:
            if source.exists():
                raw = source.read_text()
        except OSError as error:
            raise ValueError(f"Unable to read architecture: {error}") from error
    try:
        parsed = json.loads(raw) if raw.lstrip().startswith(("{", "[")) else yaml.safe_load(raw)
        return Architecture.model_validate(parsed)
    except (json.JSONDecodeError, yaml.YAMLError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid architecture document: {error}") from error
