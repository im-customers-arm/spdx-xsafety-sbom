# Sphinx-Needs Integration Plan

This document captures the implementation status and forward plan for Sphinx-Needs support in this repository.

## Objective

Enable SPDX 3.0.1 xSafety Design SBOM generation from Sphinx-Needs `needs.json` exports with behavior that is semantically aligned with the existing StrictDoc pipeline.

## Current Status

Sphinx-Needs integration is implemented and covered by tests.

Implemented capabilities:

- Dedicated parser for Sphinx-Needs exports in `src/spdx_xsafety_sbom/sphinxneeds_parser.py`
- Generator support for explicit and auto-detected input formats in `src/spdx_xsafety_sbom/generator.py`
- CLI support for `--input-format auto|strictdoc|sphinx-needs` in `src/spdx_xsafety_sbom/cli.py`
- Source scanning support for both `@sdoc[...]` and `@need[...]` markers in `src/spdx_xsafety_sbom/source_scanner.py`
- Relationship mapping into existing SPDX relationship builder (`descendantOf`, `hasTestCase`, `hasEvidence`, `testedOn`)
- Fixtures and tests for parser, generator, CLI, and marker scanning paths

Validation snapshot:

- Test suite currently passes: 74/74 tests
- Includes Sphinx-Needs focused tests plus StrictDoc/Sphinx-Needs parity checks on shared semantics

## Implemented Mapping Rules

### Input Structure

- Supports standard Sphinx-Needs top-level structure with `versions`
- Accepts empty version key (`""`) and falls back to first available version if `current_version` is missing
- Rejects invalid exports without top-level `versions`

### Field Mapping

Mapped from need fields into `StrictDocNode`:

- `id` -> `uid`
- `title` -> `title`
- `content` or `description` -> `statement`
- `rationale` -> `rationale`
- `type` -> `node_type`
- `docname` -> `document_path`
- `file_links` -> `file_refs`
- `artifact_id` -> `evidence_artifact_id`
- `timestamp_utc` -> `evidence_timestamp_utc`
- `hash_value` -> `evidence_hash`
- `asil`, `severity`, `exposure`, `controllability` -> safety metadata fields

### Type Mapping

Supported explicit type normalization includes:

- Generic: `req`, `spec`, `impl`, `test`, `need`
- Safety-specific: `hazard`, `safety_goal`, `fsc`, `tsc`, `tsr`, `ssr`, `swa`, `test_case`, `evidence`

Fallback behavior:

1. Explicit map lookup
2. UID prefix inference (for example `EVID-001` -> `EVID`)
3. Uppercase raw type fallback
4. Default `REQUIREMENT` when type is missing

### Relationship Extraction

Parent links are collected and deduplicated from schema-declared link fields:

- `derived_from`, `links`, `parent_needs`, `tests`, `validates`, `realises`

Backlink fields (schema `field_type: backlinks`) are excluded from parent extraction.

Child links are computed as reverse edges after all nodes are parsed.

## Alignment with Real Project Patterns

The integration has been verified against a representative Sphinx-Needs safety model pattern that includes:

- Hazard and goal chain: HAZ -> SG
- Functional/technical safety concept chain: SG -> FSC -> TSR
- Software requirements and architecture links: TSR -> SSR and SWA `realises` SSR
- Verification and evidence links: TC and EVID relationships

## Delivery Milestones

### M1 - Parser and Format Integration (completed)

- Add parser and wire generator format routing
- Add auto-format detection for `needs.json`
- Keep common downstream SPDX pipeline unchanged

### M2 - Source Marker Compatibility (completed)

- Extend marker scanning to include `@need[...]`
- Preserve `@sdoc[...]` behavior

### M3 - Safety Type/Field Coverage (completed)

- Extend type map for safety taxonomy (`fsc`, `tsc`, etc.)
- Extract safety metadata from flattened extra options
- Add tests for type inference and relationship extraction

### M4 - Cross-Format Semantics Validation (completed)

- Add parity tests for shared StrictDoc/Sphinx-Needs subset
- Ensure relationship semantics remain stable on common nodes

## Open Improvements

1. Add fixture variants for custom `needs_extra_links` names beyond the current defaults.
2. Add CLI integration tests for failure modes specific to malformed `needs.json` files.
3. Add documentation examples for end-to-end Sphinx build and export to `needs.json` in this repository.
4. Add optional strict mode to fail when expected safety extra fields are missing from `needs_schema`.

## Recommended Usage

```bash
# Auto-detect format (works with needs.json)
uv run spdx-xsafety-sbom generate ./_build/needs/needs.json -o design-sbom.json

# Explicit Sphinx-Needs input format
uv run spdx-xsafety-sbom generate ./_build/needs/needs.json --input-format sphinx-needs -o design-sbom.json

# With source traceability scanning for @need/@sdoc markers
uv run spdx-xsafety-sbom generate ./_build/needs/needs.json -s ./ -o design-sbom.json
```

## Definition of Done

Sphinx-Needs integration is considered production-ready when:

- Parser, generator, CLI, and scanning paths stay green in CI
- Shared semantic parity with StrictDoc remains covered by regression tests
- Documentation stays aligned with implemented behavior and supported type/link mapping
