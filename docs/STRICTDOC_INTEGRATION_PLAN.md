# StrictDoc Library Integration Status

This document replaces the previous refactor plan and reflects the current implementation state.

## Status

Integration with the StrictDoc Python library is implemented.

- Native `.sdoc` parsing is active via `strictdoc.backend.sdoc.reader.SDReader`
- `spdx-xsafety-sbom generate` accepts StrictDoc project directories directly
- Custom grammar projects are supported through automatic export fallback (`strictdoc export --formats json`) when `.sgra` files are detected
- Source traceability scanning is handled in-project via `source_scanner.py`

## Current Architecture

### Parser

File: `src/spdx_xsafety_sbom/strictdoc_parser.py`

- Primary path: parse `.sdoc` files using StrictDoc library APIs
- Fallback path: invoke StrictDoc CLI export and parse generated `index.json`
- Produces `StrictDocNode` instances used by the SBOM pipeline

### Generator

File: `src/spdx_xsafety_sbom/generator.py`

- Orchestrates parse -> scan -> build elements -> build relationships -> write -> validate
- Supports optional source scanning and output validation toggles

### Source Scanner

File: `src/spdx_xsafety_sbom/source_scanner.py`

- Scans code for `@sdoc[...]` markers using regex
- Emits `RangeLink` data used for `testedOn` relationships

## What Changed From the Original Plan

Completed items:

- CLI now works from native StrictDoc project paths (`.sdoc` inputs)
- JSON-export-only workflow is no longer required for normal operation
- StrictDoc is a core dependency in `pyproject.toml`
- Tests are centered on `.sdoc` fixtures (`tests/fixtures/sdoc`)

Deferred/non-goals:

- `strictdoc_parser.py` and `source_scanner.py` were retained because they contain repository-specific transformation logic and fallback behavior

## Operational Notes

- Validation extras are optional: `uv sync --extra validation`
- SHACL shapes are loaded from `spdx_extensions/shacl/safety-shapes.ttl`
- Source root is optional and auto-detected from git root in the CLI when possible

## Future Improvements

1. Reduce parser complexity by extracting native and export fallback paths into separate internal adapters.
2. Replace heuristic source range detection with language-aware parsing where needed.
3. Add dedicated CLI tests for option-level behavior and error messages.
