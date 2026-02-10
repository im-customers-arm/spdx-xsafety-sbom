"""
SHACL validation for xSafety extension.

Uses pyshacl to validate SPDX documents against
the xSafety extension SHACL shapes.

Requires: pyshacl, rdflib
Install with: uv add pyshacl rdflib
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from spdx_xsafety_sbom.paths import get_shacl_shapes_path
from spdx_xsafety_sbom.validation.spdx_validator import ValidationResult

logger = logging.getLogger(__name__)

# Path to SHACL shapes file (supports both frozen and development environments)
SHAPES_PATH = get_shacl_shapes_path()


def validate_shacl(
    document: dict[str, Any],
    shapes_path: Path | str | None = None,
) -> ValidationResult:
    """
    Validate document against xSafety SHACL shapes.

    Args:
        document: Parsed SPDX JSON-LD document.
        shapes_path: Optional path to SHACL shapes file.

    Returns:
        ValidationResult with SHACL validation results.
    """
    result = ValidationResult()

    try:
        import json

        from pyshacl import validate
        from rdflib import Graph
    except ImportError as e:
        result.warnings.append(f"SHACL validation requires pyshacl: {e}")
        result.warnings.append("Install with: uv add pyshacl rdflib")
        return result

    # Determine shapes path
    shapes_file = Path(shapes_path) if shapes_path else SHAPES_PATH

    if not shapes_file.exists():
        result.warnings.append(f"SHACL shapes file not found: {shapes_file}")
        return result

    try:
        # Load data graph from JSON-LD
        data_graph = Graph()
        json_ld_str = json.dumps(document)
        data_graph.parse(data=json_ld_str, format="json-ld")

        logger.debug("Loaded %d triples from document", len(data_graph))

        # Load shapes graph
        shapes_graph = Graph()
        shapes_graph.parse(shapes_file, format="turtle")

        logger.debug("Loaded %d triples from shapes", len(shapes_graph))

        # Run SHACL validation
        conforms, results_graph, results_text = validate(
            data_graph,
            shacl_graph=shapes_graph,
            inference="none",
            abort_on_first=False,
        )

        if conforms:
            logger.info("SHACL validation passed")
            result.info["shacl_conforms"] = True
        else:
            logger.warning("SHACL validation failed")
            result.info["shacl_conforms"] = False

            # Parse validation results
            _parse_shacl_results(results_graph, result)

    except Exception as e:
        result.errors.append(f"SHACL validation error: {e}")
        logger.exception("SHACL validation failed with exception")

    return result


def _parse_shacl_results(results_graph: Any, result: ValidationResult) -> None:
    """
    Parse SHACL validation results graph.

    Args:
        results_graph: RDFLib graph with SHACL results.
        result: ValidationResult to update.
    """
    # Query for validation results
    query = """
    PREFIX sh: <http://www.w3.org/ns/shacl#>
    SELECT ?focusNode ?resultMessage ?severity ?sourceShape
    WHERE {
        ?result a sh:ValidationResult ;
                sh:focusNode ?focusNode ;
                sh:resultMessage ?resultMessage .
        OPTIONAL { ?result sh:resultSeverity ?severity }
        OPTIONAL { ?result sh:sourceShape ?sourceShape }
    }
    """

    try:
        for row in results_graph.query(query):
            focus_node = str(row.focusNode) if row.focusNode else "unknown"
            message = str(row.resultMessage) if row.resultMessage else "No message"
            severity = str(row.severity) if row.severity else "Violation"

            full_message = f"[{focus_node}] {message}"

            if "Violation" in severity:
                result.errors.append(full_message)
            elif "Warning" in severity:
                result.warnings.append(full_message)
            else:
                result.warnings.append(full_message)

    except Exception as e:
        logger.warning("Could not parse SHACL results: %s", e)
        result.warnings.append("Could not parse detailed SHACL results")


def validate_file_shacl(
    sbom_path: Path | str,
    shapes_path: Path | str | None = None,
) -> ValidationResult:
    """
    Validate an SBOM file against SHACL shapes.

    Args:
        sbom_path: Path to SBOM JSON file.
        shapes_path: Optional path to SHACL shapes.

    Returns:
        ValidationResult with SHACL validation.
    """
    import json

    path = Path(sbom_path)
    result = ValidationResult()

    if not path.exists():
        result.valid = False
        result.errors.append(f"File not found: {path}")
        return result

    try:
        with open(path, encoding="utf-8") as f:
            document = json.load(f)
    except json.JSONDecodeError as e:
        result.valid = False
        result.errors.append(f"Invalid JSON: {e}")
        return result

    return validate_shacl(document, shapes_path)
