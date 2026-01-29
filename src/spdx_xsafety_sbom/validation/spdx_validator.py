"""
SPDX 3.0.1 JSON-LD structure validator.

Validates:
- JSON-LD document structure
- Required SPDX 3.0.1 fields
- Element and relationship integrity
- xSafety extension structure
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of SBOM validation."""

    valid: bool = True
    """Whether the document is valid."""

    errors: list[str] = field(default_factory=list)
    """List of validation errors."""

    warnings: list[str] = field(default_factory=list)
    """List of validation warnings."""

    info: dict[str, Any] = field(default_factory=dict)
    """Additional validation information."""


def validate_sbom(
    sbom_path: Path | str,
    run_shacl: bool = False,
) -> ValidationResult:
    """
    Validate an SPDX SBOM file.

    Args:
        sbom_path: Path to the SBOM JSON file.
        run_shacl: Whether to run SHACL validation.

    Returns:
        ValidationResult with validation status.
    """
    result = ValidationResult()
    path = Path(sbom_path)

    # Check file exists
    if not path.exists():
        result.valid = False
        result.errors.append(f"File not found: {path}")
        return result

    # Load JSON
    try:
        with open(path, encoding="utf-8") as f:
            document = json.load(f)
    except json.JSONDecodeError as e:
        result.valid = False
        result.errors.append(f"Invalid JSON: {e}")
        return result

    # Validate structure
    structure_result = validate_structure(document)
    result.errors.extend(structure_result.errors)
    result.warnings.extend(structure_result.warnings)
    result.info.update(structure_result.info)

    if structure_result.errors:
        result.valid = False

    # Run SHACL validation if requested
    if run_shacl and result.valid:
        try:
            from spdx_xsafety_sbom.validation.shacl_validator import validate_shacl

            shacl_result = validate_shacl(document)
            result.errors.extend(shacl_result.errors)
            result.warnings.extend(shacl_result.warnings)

            if shacl_result.errors:
                result.valid = False

        except ImportError:
            result.warnings.append("SHACL validation skipped: pyshacl not installed")

    return result


def validate_structure(document: dict[str, Any]) -> ValidationResult:
    """
    Validate JSON-LD document structure.

    Args:
        document: Parsed JSON document.

    Returns:
        ValidationResult with structure validation.
    """
    result = ValidationResult()

    # Check @context
    if "@context" not in document:
        result.errors.append("Missing @context")
    else:
        context = document["@context"]
        if not isinstance(context, list):
            result.warnings.append("@context should be an array for extensions")

        # Check for SPDX context
        has_spdx_context = False
        if isinstance(context, list):
            for ctx in context:
                if isinstance(ctx, str) and "spdx.org" in ctx:
                    has_spdx_context = True
                    break
        elif isinstance(context, str) and "spdx.org" in context:
            has_spdx_context = True

        if not has_spdx_context:
            result.warnings.append("SPDX context not found in @context")

    # Check @graph
    if "@graph" not in document:
        result.errors.append("Missing @graph")
        return result

    graph = document["@graph"]
    if not isinstance(graph, list):
        result.errors.append("@graph must be an array")
        return result

    if not graph:
        result.errors.append("@graph is empty")
        return result

    # Collect elements and validate
    spdx_documents = []
    elements = []
    relationships = []
    element_ids = set()

    for item in graph:
        if not isinstance(item, dict):
            result.errors.append("Graph item is not an object")
            continue

        item_type = item.get("@type") or item.get("type")
        spdx_id = item.get("spdxId")

        if spdx_id:
            if spdx_id in element_ids:
                result.errors.append(f"Duplicate spdxId: {spdx_id}")
            element_ids.add(spdx_id)

        if item_type == "SpdxDocument":
            spdx_documents.append(item)
        elif item_type == "Relationship":
            relationships.append(item)
        else:
            elements.append(item)

    # Validate SpdxDocument
    if not spdx_documents:
        result.errors.append("No SpdxDocument element found")
    elif len(spdx_documents) > 1:
        result.warnings.append("Multiple SpdxDocument elements found")
    else:
        doc = spdx_documents[0]
        _validate_spdx_document(doc, result)

    # Validate relationships
    for rel in relationships:
        _validate_relationship(rel, element_ids, result)

    # Validate elements with extensions
    for elem in elements:
        _validate_element(elem, result)

    # Add info
    result.info["element_count"] = len(elements)
    result.info["relationship_count"] = len(relationships)
    result.info["spdx_documents"] = len(spdx_documents)

    return result


def _validate_spdx_document(doc: dict[str, Any], result: ValidationResult) -> None:
    """Validate SpdxDocument element."""
    required_fields = ["spdxId", "name", "specVersion", "creationInfo"]

    for field_name in required_fields:
        if field_name not in doc:
            result.errors.append(f"SpdxDocument missing required field: {field_name}")

    # Check specVersion
    spec_version = doc.get("specVersion")
    if spec_version and not spec_version.startswith("3."):
        result.warnings.append(f"Unexpected specVersion: {spec_version} (expected 3.x)")

    # Check creationInfo
    creation_info = doc.get("creationInfo")
    if creation_info:
        if "created" not in creation_info:
            result.warnings.append("creationInfo missing 'created' timestamp")
        if "createdBy" not in creation_info:
            result.warnings.append("creationInfo missing 'createdBy'")


def _validate_relationship(
    rel: dict[str, Any],
    element_ids: set[str],
    result: ValidationResult,
) -> None:
    """Validate a Relationship element."""
    required_fields = ["spdxId", "relationshipType", "from", "to"]

    for field_name in required_fields:
        if field_name not in rel:
            result.errors.append(
                f"Relationship {rel.get('spdxId', 'unknown')} missing: {field_name}"
            )

    # Check 'from' reference
    from_id = rel.get("from")
    if from_id and from_id not in element_ids:
        result.warnings.append(
            f"Relationship 'from' references unknown element: {from_id}"
        )

    # Check 'to' references
    to_ids = rel.get("to", [])
    if isinstance(to_ids, list):
        for to_id in to_ids:
            if to_id not in element_ids:
                result.warnings.append(
                    f"Relationship 'to' references unknown element: {to_id}"
                )


def _validate_element(elem: dict[str, Any], result: ValidationResult) -> None:
    """Validate a generic SPDX element."""
    # Must have spdxId
    if "spdxId" not in elem:
        result.errors.append(
            f"Element missing spdxId: {elem.get('@type', 'unknown type')}"
        )

    # Must have @type or type
    if "@type" not in elem and "type" not in elem:
        result.errors.append(f"Element missing @type: {elem.get('spdxId', 'unknown')}")

    # Validate extensions if present
    extensions = elem.get("extension", [])
    if extensions:
        for ext in extensions:
            _validate_extension(ext, elem.get("spdxId", "unknown"), result)


def _validate_extension(
    ext: dict[str, Any],
    parent_id: str,
    result: ValidationResult,
) -> None:
    """Validate an xSafety extension."""
    ext_type = ext.get("type")

    if not ext_type:
        result.errors.append(f"Extension on {parent_id} missing type")
        return

    # Check for xSafety namespace prefix
    if not ext_type.startswith("xSafety:"):
        result.warnings.append(
            f"Extension type {ext_type} does not use xSafety namespace"
        )

    # Validate known extension types
    valid_types = {
        "xSafety:HazardExtension",
        "xSafety:SafetyGoalExtension",
        "xSafety:SafetyExtension",
        "xSafety:SafetyRequirementExtension",
        "xSafety:SafetyEvidenceExtension",
        "xSafety:SafetyTestExtension",
    }

    if ext_type not in valid_types:
        result.warnings.append(f"Unknown extension type: {ext_type}")

    # Validate required fields for specific extension types
    if ext_type == "xSafety:SafetyRequirementExtension":
        if "xSafety:requirementType" not in ext:
            result.errors.append(
                f"SafetyRequirementExtension on {parent_id} missing requirementType"
            )

    elif ext_type == "xSafety:SafetyGoalExtension":
        if "xSafety:safetyIntegrityLevel" not in ext:
            result.errors.append(
                f"SafetyGoalExtension on {parent_id} missing safetyIntegrityLevel"
            )

    elif ext_type == "xSafety:SafetyEvidenceExtension":
        if "xSafety:evidenceType" not in ext:
            result.errors.append(
                f"SafetyEvidenceExtension on {parent_id} missing evidenceType"
            )

    elif ext_type == "xSafety:SafetyTestExtension" and "xSafety:testType" not in ext:
        result.errors.append(f"SafetyTestExtension on {parent_id} missing testType")
