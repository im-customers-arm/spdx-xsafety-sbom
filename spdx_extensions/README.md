# SPDX 3.0.1 Custom Extensions for Safety-Critical Systems

## Overview

This folder contains the xSafety extension specification for SPDX 3.0.1, providing domain-specific metadata for safety-critical systems compliant with ISO 26262, DO-178C, IEC 61508, and similar standards.

## Directory Structure

```
spdx_extensions/
├── README.md                    # This file
├── specs/                       # Markdown specifications
│   └── safety-profile.md        # xSafety extension spec
├── contexts/                    # JSON-LD context files
│   └── safety-context.jsonld    # xSafety extension context
└── shacl/                       # SHACL validation shapes
    └── safety-shapes.ttl        # xSafety validation shapes
```

## xSafety Extension

**Namespace**: `https://example.org/spdx-extensions/xSafety/`
**Prefix**: `xSafety`
**Version**: 2.1.0

### Extension Classes

| Class | Description |
|-------|-------------|
| `xSafety:HazardExtension` | ISO 26262 HARA: severity, exposure, controllability |
| `xSafety:SafetyGoalExtension` | Safety goals derived from hazard analysis |
| `xSafety:SafetyExtension` | Safety classification (ASIL level, compliance status) |
| `xSafety:SafetyRequirementExtension` | Safety requirement documentation |
| `xSafety:SafetyEvidenceExtension` | Compliance evidence (test reports, reviews) |
| `xSafety:SafetyTestExtension` | Test classification and results |

### Usage in SPDX Documents

Reference extension contexts in your SPDX JSON-LD documents:

```json
{
  "@context": [
    "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    "./spdx_extensions/contexts/safety-context.jsonld"
  ],
  "@graph": [...]
}
```

Or inline the namespace:

```json
{
  "@context": [
    "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    { "xSafety": "https://example.org/spdx-extensions/xSafety/" }
  ],
  "@graph": [...]
}
```

## Compliance Notes

These extensions follow SPDX 3.0.1 extension guidelines:

1. **Extension mechanism** - All extension classes subclass `Extension`, not `Element`
2. **Attachment** - Extensions attach via the `extension` property on Elements
3. **Standard carriers** - Use `Bundle`, `software_Package`, `software_File` as carrier Elements
4. **Namespace prefixes** - All extension properties use their namespace prefix (`xSafety:`)
5. **JSON-LD contexts** - Proper context definitions for namespace resolution

## Validation

### SHACL Validation

```bash
# Install pyshacl
uv add pyshacl

# Validate a document against safety shapes
uv run pyshacl -s spdx_extensions/shacl/safety-shapes.ttl \
    -df json-ld design-sbom.json
```

## Source

This extension specification is derived from the `spdx_diff` project:
https://github.com/im-customers-arm/spdx_diff/tree/main/spdx_extensions
