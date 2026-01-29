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

from spdx_xsafety_sbom.models import GenerationResult, GeneratorConfig
from spdx_xsafety_sbom.relationships import RelationshipBuilder
from spdx_xsafety_sbom.source_scanner import SourceScanner
from spdx_xsafety_sbom.spdx_builder import SPDX3Builder
from spdx_xsafety_sbom.strictdoc_adapter import StrictDocAdapter
from spdx_xsafety_sbom.strictdoc_parser import StrictDocParser

if TYPE_CHECKING:
    from spdx_xsafety_sbom.models import RangeLink

logger = logging.getLogger(__name__)


def generate_design_sbom(
    strictdoc_export_path: Path | str,
    output_path: Path | str,
    source_root: Path | str | None = None,
    spdx_id_prefix: str = "urn:spdx:example:",
    document_name: str = "design-sbom",
    tool_name: str = "spdx-xsafety-sbom",
    organization: str | None = None,
    scan_source_markers: bool = True,
    validate_output: bool = True,
) -> GenerationResult:
    """
    Generate an SPDX 3.0.1 Design SBOM with xSafety extensions.

    This is the main entry point for SBOM generation. It:
    1. Parses StrictDoc JSON export for requirements
    2. Optionally scans source files for @sdoc markers
    3. Builds SPDX 3.0.1 elements with xSafety extensions
    4. Builds relationships (descendantOf, hasTestCase, testedOn, etc.)
    5. Writes JSON-LD output

    Args:
        strictdoc_export_path: Path to StrictDoc JSON export directory.
        output_path: Path for output SBOM file.
        source_root: Optional root path for source code scanning.
        spdx_id_prefix: Prefix for SPDX element IDs.
        document_name: Name for the SPDX document.
        tool_name: Name of the generating tool.
        organization: Optional organization name.
        scan_source_markers: Whether to scan for @sdoc markers.
        validate_output: Whether to validate generated SBOM.

    Returns:
        GenerationResult with success status and details.
    """
    start_time = time.time()
    result = GenerationResult(success=False)

    try:
        # Convert paths
        export_path = Path(strictdoc_export_path)
        out_path = Path(output_path)
        src_root = Path(source_root) if source_root else None

        logger.info("Starting SBOM generation")
        logger.info("  StrictDoc export: %s", export_path)
        logger.info("  Output: %s", out_path)
        if src_root:
            logger.info("  Source root: %s", src_root)

        # =================================================================
        # Step 1: Parse StrictDoc export
        # =================================================================
        logger.info("Parsing StrictDoc export...")
        parser = StrictDocParser(export_path)
        nodes = parser.parse()

        if not nodes:
            result.errors.append("No requirements found in StrictDoc export")
            return result

        logger.info("Found %d requirements", len(nodes))

        # =================================================================
        # Step 2: Scan source files for @sdoc markers
        # =================================================================
        source_links: dict[str, list[RangeLink]] = {}

        if scan_source_markers and src_root and src_root.exists():
            logger.info("Scanning source files for @sdoc markers...")
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
            tool_version="0.1.0",
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

    except Exception as e:
        result.errors.append(f"Generation failed: {e}")
        logger.exception("Generation failed with exception")

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
    # Filter out creator/tool elements
    orphans = {
        oid for oid in orphans
        if not any(x in oid for x in ["tool-", "org-", "document-"])
    }

    if orphans:
        warnings.append(f"Found {len(orphans)} potentially orphan elements")

    return warnings


def generate_from_config(config: GeneratorConfig) -> GenerationResult:
    """
    Generate SBOM from a GeneratorConfig object.

    Args:
        config: GeneratorConfig with all settings.

    Returns:
        GenerationResult with success status and details.
    """
    return generate_design_sbom(
        strictdoc_export_path=config.strictdoc_export_path,
        output_path=config.output_path,
        source_root=config.source_root,
        spdx_id_prefix=config.spdx_id_prefix,
        document_name=config.document_name,
        tool_name=config.creator_name,
        organization=config.creator_org,
        scan_source_markers=config.scan_source_markers,
        validate_output=config.validate_output,
    )


def generate_design_sbom_from_project(
    project_path: Path | str,
    output_path: Path | str,
    spdx_id_prefix: str = "urn:spdx:example:",
    document_name: str = "design-sbom",
    tool_name: str = "spdx-xsafety-sbom",
    organization: str | None = None,
    validate_output: bool = True,
) -> GenerationResult:
    """
    Generate an SPDX 3.0.1 Design SBOM directly from a StrictDoc project.

    This is the new simplified entry point that uses StrictDoc's native
    library API to parse .sdoc files directly, eliminating the need for
    a separate JSON export step.

    Args:
        project_path: Path to StrictDoc project (containing .sdoc files).
        output_path: Path for output SBOM file.
        spdx_id_prefix: Prefix for SPDX element IDs.
        document_name: Name for the SPDX document.
        tool_name: Name of the generating tool.
        organization: Optional organization name.
        validate_output: Whether to validate generated SBOM.

    Returns:
        GenerationResult with success status and details.

    Example:
        result = generate_design_sbom_from_project(
            project_path="./my-safety-project",
            output_path="./design-sbom.json",
        )
        if result.success:
            print(f"Generated {result.element_count} elements")
    """
    start_time = time.time()
    result = GenerationResult(success=False)

    try:
        proj_path = Path(project_path).resolve()
        out_path = Path(output_path)

        logger.info("Starting SBOM generation (native StrictDoc mode)")
        logger.info("  Project path: %s", proj_path)
        logger.info("  Output: %s", out_path)

        # =================================================================
        # Step 1: Parse StrictDoc project using native adapter
        # =================================================================
        logger.info("Parsing StrictDoc project...")
        adapter = StrictDocAdapter(proj_path)
        nodes = adapter.parse()

        if not nodes:
            result.errors.append("No requirements found in StrictDoc project")
            return result

        logger.info("Found %d requirements", len(nodes))

        # =================================================================
        # Step 2: Get source file links (from StrictDoc traceability)
        # =================================================================
        logger.info("Extracting source file traceability...")
        source_links = adapter.get_source_links()
        logger.info("Found source links for %d UIDs", len(source_links))

        # =================================================================
        # Step 3: Build SPDX elements
        # =================================================================
        logger.info("Building SPDX elements...")
        builder = SPDX3Builder(
            spdx_id_prefix=spdx_id_prefix,
            document_name=document_name,
        )

        builder.build_creation_info(
            tool_name=tool_name,
            tool_version="0.2.0",
            organization=organization,
        )

        root_elements: list[str] = []
        for _uid, node in nodes.items():
            element = builder.build_node_element(node)
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
            source_root=str(proj_path),
        )

        for rel in relationships:
            builder._add_element(rel)

        logger.info("Built %d relationships", len(relationships))

        # =================================================================
        # Step 5: Build document and write output
        # =================================================================
        logger.info("Building SPDX document...")
        document = builder.build_document(root_elements=root_elements)

        out_path.parent.mkdir(parents=True, exist_ok=True)

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(document, f, indent=2, ensure_ascii=False)

        logger.info("Wrote SBOM to %s", out_path)

        # =================================================================
        # Step 6: Validate output
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
        result.errors.append(f"Project not found: {e}")
        logger.error("Generation failed: %s", e)

    except Exception as e:
        result.errors.append(f"Generation failed: {e}")
        logger.exception("Generation failed with exception")

    return result
