"""
Constants for SPDX 3.0.1 Design SBOM generation with xSafety extension.

This module defines:
- SPDX 3.0.1 namespaces and contexts
- xSafety extension namespace (v2.1.0)
- ISO 26262 HARA vocabulary mappings
- Safety requirement type mappings
"""

from __future__ import annotations

from typing import Final

# =============================================================================
# SPDX 3.0.1 Namespaces and Contexts
# =============================================================================

SPDX_VERSION: Final[str] = "3.0.1"
SPDX_CONTEXT: Final[str] = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
SPDX_NS: Final[str] = "https://spdx.org/rdf/3.0.1/terms/"

# =============================================================================
# xSafety Extension Configuration
# =============================================================================

XSAFETY_VERSION: Final[str] = "2.1.0"
XSAFETY_NS: Final[str] = "https://example.org/spdx-extensions/xSafety/"

# Extension class names (to be combined with XSAFETY_NS)
EXTENSION_CLASSES: Final[dict[str, str]] = {
    "hazard": "HazardExtension",
    "safety_goal": "SafetyGoalExtension",
    "safety": "SafetyExtension",
    "requirement": "SafetyRequirementExtension",
    "evidence": "SafetyEvidenceExtension",
    "test": "SafetyTestExtension",
}

# =============================================================================
# ISO 26262 ASIL Levels
# =============================================================================

ASIL_LEVELS: Final[dict[str, str]] = {
    "ASIL_A": "asilA",
    "ASIL_B": "asilB",
    "ASIL_C": "asilC",
    "ASIL_D": "asilD",
    "QM": "qm",
    "ASIL A": "asilA",
    "ASIL B": "asilB",
    "ASIL C": "asilC",
    "ASIL D": "asilD",
    "A": "asilA",
    "B": "asilB",
    "C": "asilC",
    "D": "asilD",
}

# IEC 61508 SIL Levels
SIL_LEVELS: Final[dict[str, str]] = {
    "SIL_1": "sil1",
    "SIL_2": "sil2",
    "SIL_3": "sil3",
    "SIL_4": "sil4",
    "SIL 1": "sil1",
    "SIL 2": "sil2",
    "SIL 3": "sil3",
    "SIL 4": "sil4",
    "1": "sil1",
    "2": "sil2",
    "3": "sil3",
    "4": "sil4",
}

# DO-178C DAL Levels
DAL_LEVELS: Final[dict[str, str]] = {
    "DAL_A": "dalA",
    "DAL_B": "dalB",
    "DAL_C": "dalC",
    "DAL_D": "dalD",
    "DAL A": "dalA",
    "DAL B": "dalB",
    "DAL C": "dalC",
    "DAL D": "dalD",
}

# =============================================================================
# ISO 26262 HARA Severity Ratings
# =============================================================================

SEVERITY_LEVELS: Final[dict[str, str]] = {
    "S0": "s0",
    "S1": "s1",
    "S2": "s2",
    "S3": "s3",
    "0": "s0",
    "1": "s1",
    "2": "s2",
    "3": "s3",
}

SEVERITY_DESCRIPTIONS: Final[dict[str, str]] = {
    "s0": "No injuries",
    "s1": "Light and moderate injuries",
    "s2": "Severe and life-threatening injuries (survival probable)",
    "s3": "Life-threatening injuries (survival uncertain), fatal injuries",
}

# =============================================================================
# ISO 26262 HARA Exposure Ratings
# =============================================================================

EXPOSURE_LEVELS: Final[dict[str, str]] = {
    "E0": "e0",
    "E1": "e1",
    "E2": "e2",
    "E3": "e3",
    "E4": "e4",
    "0": "e0",
    "1": "e1",
    "2": "e2",
    "3": "e3",
    "4": "e4",
}

EXPOSURE_DESCRIPTIONS: Final[dict[str, str]] = {
    "e0": "Incredible",
    "e1": "Very low probability",
    "e2": "Low probability",
    "e3": "Medium probability",
    "e4": "High probability",
}

# =============================================================================
# ISO 26262 HARA Controllability Ratings
# =============================================================================

CONTROLLABILITY_LEVELS: Final[dict[str, str]] = {
    "C0": "c0",
    "C1": "c1",
    "C2": "c2",
    "C3": "c3",
    "0": "c0",
    "1": "c1",
    "2": "c2",
    "3": "c3",
}

CONTROLLABILITY_DESCRIPTIONS: Final[dict[str, str]] = {
    "c0": "Controllable in general",
    "c1": "Simply controllable",
    "c2": "Normally controllable",
    "c3": "Difficult to control or uncontrollable",
}

# =============================================================================
# Safety Requirement Types
# =============================================================================

REQUIREMENT_TYPES: Final[dict[str, str]] = {
    "TSR": "technicalSafetyRequirement",
    "SSR": "softwareSafetyRequirement",
    "HSR": "hardwareSafetyRequirement",
    "FSR": "functional",  # Functional Safety Requirement
    "SWA": "functional",  # Software Architecture (functional type)
    "HAZ": "hazard",  # Special case - handled by HazardExtension
    "SG": "safetyGoal",  # Special case - handled by SafetyGoalExtension
}

# StrictDoc document type to requirement type mapping
DOCUMENT_TYPE_MAPPING: Final[dict[str, str]] = {
    "hazard-analysis": "HAZ",
    "safety-goal": "SG",
    "technical-safety-requirement": "TSR",
    "software-safety-requirement": "SSR",
    "hardware-safety-requirement": "HSR",
    "software-architecture": "SWA",
    "functional-requirement": "FSR",
}

# =============================================================================
# Test Types
# =============================================================================

TEST_TYPES: Final[dict[str, str]] = {
    "UNIT": "unitTest",
    "INTEGRATION": "integrationTest",
    "SYSTEM": "systemTest",
    "VALIDATION": "validationTest",
    "REGRESSION": "regressionTest",
    "FAULT_INJECTION": "faultInjectionTest",
    "HIL": "hardwareInLoopTest",
    "SIL": "softwareInLoopTest",
    "MIL": "modelInLoopTest",
}

# =============================================================================
# Evidence Types
# =============================================================================

EVIDENCE_TYPES: Final[dict[str, str]] = {
    "TEST_REPORT": "testReport",
    "TEST_RESULT": "testResult",
    "REVIEW_REPORT": "reviewReport",
    "ANALYSIS_REPORT": "analysisReport",
    "CERTIFICATION_REPORT": "certificationReport",
    "AUDIT_REPORT": "auditReport",
    "TRACEABILITY_MATRIX": "traceabilityMatrix",
    "COMPLIANCE_STATEMENT": "complianceStatement",
}

# =============================================================================
# Compliance Status Values
# =============================================================================

COMPLIANCE_STATUS: Final[dict[str, str]] = {
    "COMPLIANT": "compliant",
    "PARTIAL": "partiallyCompliant",
    "NON_COMPLIANT": "nonCompliant",
    "UNDER_REVIEW": "underReview",
    "NOT_APPLICABLE": "notApplicable",
    "NO_ASSERTION": "noAssertion",
}

# =============================================================================
# SPDX 3.0.1 Relationship Types
# =============================================================================

RELATIONSHIP_TYPES: Final[dict[str, str]] = {
    # Hierarchy relationships
    "descendantOf": "descendantOf",
    "ancestorOf": "ancestorOf",
    "contains": "contains",
    "containedBy": "containedBy",
    # Specification relationships
    "hasSpecification": "hasSpecification",
    "specificationFor": "specificationFor",
    # Test relationships
    "hasTestCase": "hasTestCase",
    "testCaseFor": "testCaseFor",
    "testedOn": "testedOn",
    # Evidence relationships
    "hasEvidence": "hasEvidence",
    "evidenceFor": "evidenceFor",
    # Dependency relationships
    "dependsOn": "dependsOn",
    "dependencyOf": "dependencyOf",
    # Documentation relationships
    "hasDocumentation": "hasDocumentation",
    "documentationOf": "documentationOf",
    # General relationships
    "other": "other",
}

# StrictDoc link role to SPDX relationship mapping
LINK_ROLE_MAPPING: Final[dict[str, str]] = {
    "refines": "descendantOf",  # Child refines parent
    "parent": "ancestorOf",  # Link to parent
    "derives": "descendantOf",  # Derived from
    "implements": "hasSpecification",  # Implementation link
    "tests": "hasTestCase",  # Test link
    "verifies": "hasEvidence",  # Verification link
    "allocates": "contains",  # Allocation link
    "traces": "other",  # Generic trace
}

# =============================================================================
# SPDX 3.0.1 Purpose Values (for primaryPurpose)
# =============================================================================

PURPOSE_VALUES: Final[dict[str, str]] = {
    "requirement": "requirement",
    "test": "test",
    "evidence": "evidence",
    "application": "application",
    "library": "library",
    "source": "source",
    "documentation": "documentation",
    "architecture": "architecture",
}

# =============================================================================
# Source Code Marker Patterns
# =============================================================================

# Regex patterns for @sdoc markers in source code
SDOC_MARKER_PATTERN: Final[str] = r"@sdoc\[(?P<uid>[A-Z]+-\d+(?:\.\d+)*)\]"
SDOC_MULTILINE_PATTERN: Final[str] = (
    r"@sdoc\[(?P<uid>[A-Z]+-\d+(?:\.\d+)*(?:,\s*[A-Z]+-\d+(?:\.\d+)*)*)\]"
)

# File extensions to scan for @sdoc markers
SCANNABLE_EXTENSIONS: Final[tuple[str, ...]] = (
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".cc",
    ".hh",
    ".py",
    ".rs",
    ".go",
    ".java",
    ".kt",
    ".swift",
    ".ts",
    ".js",
)

# =============================================================================
# Default Configuration
# =============================================================================

DEFAULT_CONFIG: Final[dict[str, str | bool | list[str]]] = {
    "spdx_id_prefix": "urn:spdx:example:",
    "include_source_links": True,
    "scan_source_markers": True,
    "validate_output": True,
    "output_format": "json-ld",
    "excluded_dirs": [".git", "__pycache__", "node_modules", "venv", ".venv", "build"],
}
