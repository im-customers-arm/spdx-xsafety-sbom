"""
SPDX validation module.

Provides validation for:
- JSON-LD structure
- SPDX 3.0.1 schema compliance
- xSafety extension validation
- Optional SHACL shape validation
"""

from spdx_xsafety_sbom.validation.spdx_validator import (
    ValidationResult,
    validate_sbom,
    validate_structure,
)

__all__ = ["ValidationResult", "validate_sbom", "validate_structure"]
