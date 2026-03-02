"""
Data models for SPDX xSafety SBOM generation.

This module defines Pydantic models for:
- StrictDoc parsed nodes
- Source code range links
- SPDX elements and extensions
- Generation configuration
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    pass


# =============================================================================
# StrictDoc Node Models
# =============================================================================


@dataclass
class StrictDocNode:
    """Represents a parsed StrictDoc requirement/section node."""

    uid: str
    """Unique identifier (e.g., SSR-001, HAZ-002)."""

    title: str | None = None
    """Node title/name."""

    statement: str | None = None
    """Requirement statement text."""

    rationale: str | None = None
    """Rationale for the requirement."""

    comment: str | None = None
    """Additional comments."""

    node_type: str = "REQUIREMENT"
    """StrictDoc node type (REQUIREMENT, SECTION, etc.)."""

    # Safety-specific fields
    asil: str | None = None
    """ASIL level (A, B, C, D, QM)."""

    severity: str | None = None
    """ISO 26262 severity rating (S0-S3)."""

    exposure: str | None = None
    """ISO 26262 exposure rating (E0-E4)."""

    controllability: str | None = None
    """ISO 26262 controllability rating (C0-C3)."""

    # Evidence-specific fields
    evidence_artifact_id: str | None = None
    """Path or URI to the evidence artifact (from ARTIFACT_ID)."""

    evidence_timestamp_utc: str | None = None
    """Evidence timestamp in UTC (from TIMESTAMP_UTC)."""

    evidence_hash: str | None = None
    """Evidence hash string (from HASH)."""

    # Links and relationships
    parent_uids: list[str] = field(default_factory=list)
    """UIDs of parent requirements (via RELATIONS)."""

    child_uids: list[str] = field(default_factory=list)
    """UIDs of child requirements (computed)."""

    file_refs: list[str] = field(default_factory=list)
    """File references from @sdoc markers."""

    # Metadata
    document_path: Path | None = None
    """Path to the source .sdoc document."""

    def get_requirement_type(self) -> str:
        """Infer requirement type from UID prefix."""
        if self.uid.startswith("HAZ"):
            return "HAZ"
        if self.uid.startswith("SG"):
            return "SG"
        if self.uid.startswith("TSR"):
            return "TSR"
        if self.uid.startswith("SSR"):
            return "SSR"
        if self.uid.startswith("HSR"):
            return "HSR"
        if self.uid.startswith("SWA"):
            return "SWA"
        if self.uid.startswith("TC"):
            return "TC"  # Test Case
        if self.uid.startswith("EVID"):
            return "EVID"  # Evidence
        return "REQ"  # Generic requirement


@dataclass
class RangeLink:
    """Represents a source code location linking to a requirement."""

    file_path: Path
    """Absolute path to the source file."""

    line_start: int
    """Starting line number (1-indexed)."""

    line_end: int
    """Ending line number (1-indexed)."""

    uid: str
    """Requirement UID from @sdoc marker."""

    snippet: str | None = None
    """Optional code snippet context."""

    def to_spdx_range(self) -> dict[str, Any]:
        """Convert to SPDX 3.0.1 PositionalRange format."""
        return {
            "type": "PositionalRange",
            "beginPointer": {
                "type": "LineCharPointer",
                "lineNumber": self.line_start,
            },
            "endPointer": {
                "type": "LineCharPointer",
                "lineNumber": self.line_end,
            },
        }


# =============================================================================
# Configuration Models
# =============================================================================


class GeneratorConfig(BaseModel):
    """Configuration for SBOM generation."""

    # Input paths
    strictdoc_export_path: Path = Field(
        ..., description="Path to StrictDoc directory or .sdoc file"
    )
    source_root: Path | None = Field(
        None, description="Root path for source code scanning"
    )

    # Output configuration
    output_path: Path = Field(..., description="Output file path for SBOM")
    output_format: Literal["json-ld", "json"] = Field(
        "json-ld", description="Output format"
    )

    # SPDX configuration
    spdx_id_prefix: str = Field(
        "urn:spdx:example:", description="Prefix for SPDX element IDs"
    )
    document_name: str = Field("design-sbom", description="Name of the SPDX document")
    document_namespace: str | None = Field(
        None, description="Namespace URI for the document"
    )

    # Creator information
    creator_name: str = Field("spdx-xsafety-sbom", description="Tool name")
    creator_org: str | None = Field(None, description="Organization name")

    # Feature flags
    include_source_links: bool = Field(
        True, description="Include source code range links"
    )
    scan_source_markers: bool = Field(
        True, description="Scan source files for @sdoc markers"
    )
    validate_output: bool = Field(True, description="Validate generated SBOM")

    # Scanning configuration
    scannable_extensions: tuple[str, ...] = Field(
        (".c", ".h", ".cpp", ".hpp", ".py", ".rs"),
        description="File extensions to scan",
    )
    excluded_dirs: list[str] = Field(
        [".git", "__pycache__", "build", "venv"],
        description="Directories to exclude from scanning",
    )

    model_config = ConfigDict(arbitrary_types_allowed=True)


# =============================================================================
# SPDX Element Models (for type hints)
# =============================================================================


class SPDXElement(BaseModel):
    """Base SPDX 3.0.1 Element."""

    type: str = Field(..., alias="@type")
    spdxId: str
    name: str | None = None
    description: str | None = None
    comment: str | None = None
    primaryPurpose: str | None = None
    extension: list[dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class SPDXRelationship(BaseModel):
    """SPDX 3.0.1 Relationship."""

    type: str = Field("Relationship", alias="@type")
    spdxId: str
    relationshipType: str
    from_: str = Field(..., alias="from")
    to: list[str]
    comment: str | None = None

    model_config = ConfigDict(populate_by_name=True)


class SPDXDocument(BaseModel):
    """SPDX 3.0.1 SpdxDocument (root element)."""

    type: str = Field("SpdxDocument", alias="@type")
    spdxId: str
    name: str
    specVersion: str = "3.0.1"
    creationInfo: dict[str, Any]
    namespaceMap: list[dict[str, str]] = Field(default_factory=list)
    rootElement: list[str] = Field(default_factory=list)
    element: list[str] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


# =============================================================================
# Extension Models
# =============================================================================


class XSafetyHazardExtension(BaseModel):
    """xSafety:HazardExtension data."""

    type: str = "xSafety:HazardExtension"
    severity: str | None = Field(None, alias="xSafety:severity")
    exposure: str | None = Field(None, alias="xSafety:exposure")
    controllability: str | None = Field(None, alias="xSafety:controllability")
    safetyIntegrityLevel: str | None = Field(None, alias="xSafety:safetyIntegrityLevel")

    model_config = ConfigDict(populate_by_name=True)


class XSafetyRequirementExtension(BaseModel):
    """xSafety:SafetyRequirementExtension data."""

    type: str = "xSafety:SafetyRequirementExtension"
    requirementType: str = Field(..., alias="xSafety:requirementType")
    safetyIntegrityLevel: str | None = Field(None, alias="xSafety:safetyIntegrityLevel")

    model_config = ConfigDict(populate_by_name=True)


# =============================================================================
# Generation Result Models
# =============================================================================


@dataclass
class GenerationResult:
    """Result of SBOM generation."""

    success: bool
    """Whether generation succeeded."""

    output_path: Path | None = None
    """Path to generated SBOM file."""

    document: dict[str, Any] | None = None
    """Generated SPDX document (JSON structure)."""

    element_count: int = 0
    """Number of SPDX elements generated."""

    relationship_count: int = 0
    """Number of relationships generated."""

    warnings: list[str] = field(default_factory=list)
    """Non-fatal warnings during generation."""

    errors: list[str] = field(default_factory=list)
    """Errors encountered during generation."""

    generation_time: float = 0.0
    """Time taken for generation (seconds)."""

    timestamp: datetime = field(default_factory=datetime.now)
    """Generation timestamp."""
