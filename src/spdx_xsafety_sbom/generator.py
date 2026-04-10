"""
Main generator orchestration module.

This module provides the high-level API for generating SPDX 3.0.1
Design SBOMs with xSafety extensions from StrictDoc requirements.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from spdx_xsafety_sbom import __version__
from spdx_xsafety_sbom.models import GenerationResult, GeneratorConfig
from spdx_xsafety_sbom.relationships import RelationshipBuilder
from spdx_xsafety_sbom.source_scanner import SourceScanner
from spdx_xsafety_sbom.spdx_builder import SPDX3Builder
from spdx_xsafety_sbom.strictdoc_parser import StrictDocParser

if TYPE_CHECKING:
    from spdx_xsafety_sbom.models import RangeLink

logger = logging.getLogger(__name__)


def generate_design_sbom(
    input_path: Path | str,
    output_path: Path | str,
    source_root: Path | str | None = None,
    spdx_id_prefix: str = "urn:spdx:example:",
    document_name: str = "design-sbom",
    tool_name: str = "spdx-xsafety-sbom",
    organization: str | None = None,
    scan_source_markers: bool = True,
    validate_output: bool = True,
    input_format: str = "auto",
) -> GenerationResult:
    """
    Generate an SPDX 3.0.1 Design SBOM with xSafety extensions.

    This is the main entry point for SBOM generation. It:
    1. Parses StrictDoc or Sphinx-Needs sources for requirements
    2. Optionally scans source files for requirement markers (@sdoc, @need)
    3. Builds SPDX 3.0.1 elements with xSafety extensions
    4. Builds relationships (descendantOf, hasTestCase, testedOn, etc.)
    5. Writes JSON-LD output

    Args:
        input_path: Path to the requirements source.  Accepts three forms:
            a StrictDoc directory (containing ``.sdoc`` files), a single
            ``.sdoc`` file, or a Sphinx-Needs ``needs.json`` export file.
            Use ``input_format`` to control which parser is selected
            (default: ``"auto"`` detects from the path).
        output_path: Path for output SBOM file.
        source_root: Optional root path for source code scanning.
        spdx_id_prefix: Prefix for SPDX element IDs.
        document_name: Name for the SPDX document.
        tool_name: Name of the generating tool.
        organization: Optional organization name.
        scan_source_markers: Whether to scan for requirement markers.
        validate_output: Whether to validate generated SBOM.
        input_format: Input format -- "auto" (detect), "strictdoc", or "sphinx-needs".

    Returns:
        GenerationResult with success status and details.
    """
    start_time = time.time()
    result = GenerationResult(success=False)

    try:
        # Convert paths
        export_path = Path(input_path)
        out_path = Path(output_path)
        src_root = Path(source_root) if source_root else None

        logger.info("Starting SBOM generation")
        logger.info("  Input path: %s", export_path)
        logger.info("  Output: %s", out_path)
        if src_root:
            logger.info("  Source root: %s", src_root)

        # =================================================================
        # Step 1: Parse requirements source content
        # =================================================================
        # Normalise so Python callers are case-insensitive (click does this
        # automatically for CLI users via case_sensitive=False).
        fmt = (
            _detect_input_format(export_path)
            if input_format.lower() == "auto"
            else input_format.lower()
        )
        logger.info("Parsing requirements (format: %s)...", fmt)
        if fmt == "sphinx-needs":
            from spdx_xsafety_sbom.sphinxneeds_parser import SphinxNeedsParser

            nodes = SphinxNeedsParser(export_path).parse()
        else:
            nodes = StrictDocParser(export_path).parse()

        if not nodes:
            result.errors.append("No requirements found in sources")
            return result

        logger.info("Found %d requirements", len(nodes))

        # =================================================================
        # Step 2: Scan source files for requirement markers
        # =================================================================
        source_links: dict[str, list[RangeLink]] = {}

        if scan_source_markers and src_root and src_root.exists():
            logger.info("Scanning source files for requirement markers...")
            scanner = SourceScanner(src_root)
            source_links = scanner.scan()
            logger.info("Found markers for %d UIDs", len(source_links))

        # =================================================================
        # Step 3: Build SPDX elements
        # =================================================================
        logger.info("Building SPDX elements...")
        builder = SPDX3Builder(
            spdx_id_prefix=spdx_id_prefix,
            document_name=document_name,
        )

        # Build creation info
        builder.build_creation_info(
            tool_name=tool_name,
            tool_version=__version__,
            organization=organization,
        )

        # Build elements for each node
        root_elements: list[str] = []
        for _uid, node in nodes.items():
            element = builder.build_node_element(node)
            # Top-level elements (no parents) are root elements
            if not node.parent_uids:
                root_elements.append(element["spdxId"])

        logger.info("Built %d elements", len(builder.elements))

        # =================================================================
        # Step 4: Build relationships
        # =================================================================
        logger.info("Building relationships...")
        rel_builder = RelationshipBuilder(builder)
        relationships = rel_builder.build_all_relationships(
            nodes=nodes,
            source_links=source_links if source_links else None,
            source_root=str(src_root) if src_root else None,
        )

        # Add relationships to builder
        for rel in relationships:
            builder._add_element(rel)

        logger.info("Built %d relationships", len(relationships))

        # =================================================================
        # Step 5: Build document and write output
        # =================================================================
        logger.info("Building SPDX document...")
        document = builder.build_document(root_elements=root_elements)

        # Ensure output directory exists
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # Write JSON-LD output
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(document, f, indent=2, ensure_ascii=False)

        logger.info("Wrote SBOM to %s", out_path)

        # =================================================================
        # Step 6: Validate output (optional)
        # =================================================================
        if validate_output:
            validation_warnings = _validate_document(document)
            result.warnings.extend(validation_warnings)

        # =================================================================
        # Build result
        # =================================================================
        result.success = True
        result.output_path = out_path
        result.document = document
        result.element_count = len(builder.elements)
        result.relationship_count = len(relationships)
        result.generation_time = time.time() - start_time

        logger.info(
            "Generation complete: %d elements, %d relationships in %.2fs",
            result.element_count,
            result.relationship_count,
            result.generation_time,
        )

    except FileNotFoundError as e:
        result.errors.append(f"File not found: {e}")
        logger.error("Generation failed: %s", e)

    except (ValueError, RuntimeError) as e:
        # Expected failures: bad input format, parser errors, empty sources.
        result.errors.append(f"Generation failed: {e}")
        logger.error("Generation failed: %s", e)

    except Exception:
        # Unexpected programming error (e.g. AttributeError from a refactoring
        # mistake).  Log it and re-raise so it surfaces as a traceback rather
        # than a silent "Generation failed" message that hides the real cause.
        logger.exception("Unexpected error during SBOM generation")
        raise

    return result


def _validate_document(document: dict[str, Any]) -> list[str]:
    """
    Basic validation of generated SPDX document.

    Args:
        document: Generated SPDX document.

    Returns:
        List of validation warnings.
    """
    warnings: list[str] = []

    # Check required fields
    if "@context" not in document:
        warnings.append("Missing @context in document")

    if "@graph" not in document:
        warnings.append("Missing @graph in document")
        return warnings

    graph = document["@graph"]
    if not graph:
        warnings.append("Empty @graph in document")
        return warnings

    # Find SpdxDocument
    spdx_docs = [e for e in graph if e.get("@type") == "SpdxDocument"]
    if not spdx_docs:
        warnings.append("No SpdxDocument element found")
    elif len(spdx_docs) > 1:
        warnings.append("Multiple SpdxDocument elements found")

    # Check for orphan elements (no relationships)
    element_ids = {e.get("spdxId") for e in graph if e.get("spdxId")}
    relationship_refs = set()

    for e in graph:
        if e.get("@type") == "Relationship":
            relationship_refs.add(e.get("from"))
            for to_id in e.get("to", []):
                relationship_refs.add(to_id)

    # Elements that are neither in relationships nor root elements
    spdx_doc = spdx_docs[0] if spdx_docs else {}
    root_elements = set(spdx_doc.get("rootElement", []))

    orphans = element_ids - relationship_refs - root_elements
    # Filter using @type: structural/metadata elements are never requirements.
    # Using @type is more robust than string-matching on the spdxId prefix.
    _structural_types = {"Tool", "SpdxDocument", "Relationship", "CreationInfo"}
    spdx_id_to_type = {e.get("spdxId"): e.get("@type") or e.get("type") for e in graph}
    orphans = {oid for oid in orphans if spdx_id_to_type.get(oid) not in _structural_types}

    if orphans:
        warnings.append(f"Found {len(orphans)} potentially orphan elements")

    return warnings


def _detect_input_format(path: Path) -> str:
    """
    Auto-detect the input format from the given path.

    Returns "sphinx-needs" if the path is (or contains) a needs.json file,
    "strictdoc" if the directory contains .sdoc files, and defaults to
    "strictdoc" with a warning otherwise.
    """
    if path.is_file() and path.name == "needs.json":
        return "sphinx-needs"
    if path.is_dir() and (path / "needs.json").exists():
        if any(path.rglob("*.sdoc")):
            logger.warning(
                "Directory %s contains both needs.json and .sdoc files; "
                "auto-detecting as sphinx-needs. Use --input-format to override.",
                path,
            )
        return "sphinx-needs"
    if path.is_dir() and any(path.rglob("*.sdoc")):
        return "strictdoc"
    logger.warning("Could not detect input format for %s; defaulting to strictdoc", path)
    return "strictdoc"


def generate_from_config(config: GeneratorConfig) -> GenerationResult:
    """
    Generate SBOM from a GeneratorConfig object.

    Args:
        config: GeneratorConfig with all settings.

    Returns:
        GenerationResult with success status and details.
    """
    return generate_design_sbom(
        input_path=config.input_path,
        output_path=config.output_path,
        source_root=config.source_root,
        spdx_id_prefix=config.spdx_id_prefix,
        document_name=config.document_name,
        tool_name=config.creator_name,
        organization=config.creator_org,
        scan_source_markers=config.scan_source_markers,
        validate_output=config.validate_output,
        input_format=config.input_format,
    )
