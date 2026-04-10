"""
Sphinx-Needs parser module.

Reads a Sphinx-Needs ``needs.json`` export and produces the same
``dict[str, StrictDocNode]`` intermediate representation that the
StrictDoc parser returns.

Key design points
-----------------
* ``needs.json`` is flat-structured JSON — no AST parsing, no grammar
  files, no subprocess export fallback.
* The top-level format is::

    {
      "created": "...",
      "current_version": "<ver>",
      "project": "...",
      "versions": {
        "<ver>": {
          "needs": { "<ID>": { ... }, ... },
          "needs_schema": { ... }
        }
      }
    }

* A version key of ``""`` (empty string) is valid and used by the
  ``docs/needs.json`` fixture in this repository.

Field mapping (Sphinx-Needs → StrictDocNode)
--------------------------------------------
=========================  =======================
Sphinx-Needs field         StrictDocNode field
=========================  =======================
``id``                     ``uid``
``title``                  ``title``
``content`` / ``description``  ``statement``
``rationale``              ``rationale``
``type``                   ``node_type``
``asil``                   ``asil``
``severity``               ``severity``
``exposure``               ``exposure``
``controllability``        ``controllability``
``artifact_id``            ``evidence_artifact_id``
``timestamp_utc``          ``evidence_timestamp_utc``
``hash_value``             ``evidence_hash``
``derived_from``           ``parent_uids``  (outgoing parent links)
``docname``                ``document_path``
=========================  =======================

Relationship links (``links``, ``tests``, ``validates``,
``realises``, ``derived_from``) are all collected and deduplicated
into ``parent_uids``.  Child back-links are computed after all needs
are loaded.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from spdx_xsafety_sbom.models import StrictDocNode

logger = logging.getLogger(__name__)

# Fallback set of forward link field names used when the needs.json
# contains no ``needs_schema`` (older Sphinx-Needs exports).
# When a schema IS present the parser reads ALL ``field_type: "links"``
# fields dynamically, so custom link types are captured automatically.
_PARENT_LINK_FIELDS: tuple[str, ...] = (
    "derived_from",  # HAZ → SG, SG → TSR, etc.
    "links",  # generic forward links
    "parent_needs",  # Sphinx-Needs built-in parent link
    "tests",  # TC tests SSR
    "validates",  # EVID validates TC
    "realises",  # SWA realises SSR
)

# Sphinx-Needs directive ``type`` → canonical node-type abbreviation.
# Resolution order in _infer_node_type():
#   1. Direct lookup here (e.g. ``test_case`` → ``TC``).
#   2. UID-prefix inference (e.g. ``EVID-001`` → ``EVID``).
#   3. ``raw_type.upper()`` as a final fallback.
_TYPE_MAP: dict[str, str] = {
    # Generic Sphinx-Needs built-in types
    "req": "REQUIREMENT",
    "spec": "SPEC",
    "impl": "IMPL",
    "test": "TC",
    "need": "NEED",
    # Safety-specific types used in this project
    "evidence": "EVID",
    "test_case": "TC",
    "hazard": "HAZ",
    "safety_goal": "SG",
    "fsc": "FSC",  # Functional Safety Concept per ISO 26262
    "tsc": "TSC",  # Technical Safety Concept per ISO 26262
    "ssr": "SSR",
    "swa": "SWA",
    "tsr": "TSR",
}

_DEFAULT_NODE_TYPE = "REQUIREMENT"

# Safety metadata fields declared via ``needs_extra_options`` in conf.py.
# Sphinx-Needs flattens extra options into the top-level need dict and marks
# them as ``"field_type": "extra"`` in the needs_schema.
_SAFETY_EXTRA_FIELDS: tuple[str, ...] = (
    "asil",
    "severity",
    "exposure",
    "controllability",
)


class SphinxNeedsParser:
    """
    Parser for Sphinx-Needs ``needs.json`` exports.

    Parses the flat JSON structure directly — no subprocess, no
    grammar files, no StrictDoc library dependency.

    Usage::

        parser = SphinxNeedsParser(Path("docs/needs.json"))
        nodes: dict[str, StrictDocNode] = parser.parse()
    """

    def __init__(self, path: Path) -> None:
        """
        Initialise the parser.

        Args:
            path: Path to a ``needs.json`` file produced by Sphinx-Needs.
        """
        self.path = Path(path)
        self._nodes: dict[str, StrictDocNode] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self) -> dict[str, StrictDocNode]:
        """
        Parse the ``needs.json`` file.

        Returns:
            ``dict[str, StrictDocNode]`` mapping UID to node, with
            ``child_uids`` populated as the reverse of ``parent_uids``.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the JSON structure is not a valid needs.json.
        """
        nodes: dict[str, StrictDocNode] = {}

        try:
            with open(self.path, encoding="utf-8") as fh:
                data: dict[str, Any] = json.load(fh)
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"needs.json not found: {self.path}") from exc
        except (json.JSONDecodeError, OSError) as exc:
            if isinstance(exc, json.JSONDecodeError):
                raise ValueError(
                    f"Invalid JSON in needs.json — {exc.msg} "
                    f"(line {exc.lineno}, col {exc.colno}): {self.path}"
                ) from exc
            else:
                raise ValueError(f"Cannot read needs.json: {exc}") from exc

        if "versions" not in data:
            raise ValueError(f"Invalid needs.json — missing top-level 'versions' key: {self.path}")

        # Resolve the version to parse: prefer current_version, fall
        # back to the first (or only) version key present.
        current_version: str = data.get("current_version", "")
        versions: dict[str, Any] = data["versions"]

        if current_version in versions:
            version_data = versions[current_version]
        elif versions:
            first_key = next(iter(versions))
            logger.warning(
                "needs.json current_version %r not found in versions keys %s; "
                "falling back to first available version %r — "
                "the file may be from a different Sphinx-Needs export.",
                current_version,
                sorted(versions.keys()),
                first_key,
            )
            version_data = versions[first_key]
        else:
            logger.warning("needs.json contains no version data: %s", self.path)
            return {}

        raw_needs: dict[str, Any] = version_data.get("needs", {})
        if not raw_needs:
            logger.warning("No needs found in %s", self.path)
            return {}

        # Index the schema: used for back-link detection and safety-field
        # verification.  _SAFETY_EXTRA_FIELDS live in the 'extra' bucket.
        fields_by_type = self._schema_fields_by_type(version_data)
        backlink_fields = fields_by_type.get("backlinks", frozenset())
        # Use all schema-declared forward link fields when available so that
        # custom link types (needs_extra_links in conf.py) are captured too.
        # Fall back to the hardcoded constant for older exports with no schema.
        schema_link_fields: frozenset[str] = fields_by_type.get("links", frozenset())
        link_fields: frozenset[str] = schema_link_fields or frozenset(_PARENT_LINK_FIELDS)
        self._verify_safety_extra_fields(fields_by_type)

        for need_id, need_data in raw_needs.items():
            self._parse_need(need_id, need_data, backlink_fields, link_fields, nodes)

        self._build_child_relationships(nodes)

        logger.info(
            "SphinxNeedsParser: parsed %d nodes from %s",
            len(nodes),
            self.path,
        )
        self._nodes = nodes  # cache for callers that inspect _nodes directly
        return nodes  # return the local var; avoids aliasing via self._nodes

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _schema_fields_by_type(
        version_data: dict[str, Any],
    ) -> dict[str, frozenset[str]]:
        """
        Index all needs_schema field names by their ``field_type``.

        Returns a mapping like::

            {
                "core":      frozenset({"id", "title", "type", ...}),
                "extra":     frozenset({"asil", "severity", ...}),
                "links":     frozenset({"derived_from", "links", ...}),
                "backlinks": frozenset({"derived_from_back", ...}),
            }

        If the version has no ``needs_schema`` the result is an empty dict.
        """
        schema_props: dict[str, Any] = version_data.get("needs_schema", {}).get("properties", {})
        index: dict[str, set[str]] = {}
        for name, meta in schema_props.items():
            if isinstance(meta, dict):
                ft = meta.get("field_type", "")
                index.setdefault(ft, set()).add(name)
        return {ft: frozenset(names) for ft, names in index.items()}

    @staticmethod
    def _verify_safety_extra_fields(
        fields_by_type: dict[str, frozenset[str]],
    ) -> None:
        """
        Warn when expected safety metadata fields are absent from the schema.

        Sphinx-Needs projects define ``asil``, ``severity``, ``exposure``,
        and ``controllability`` via ``needs_extra_options`` in ``conf.py``.
        They appear as ``field_type: "extra"`` in the exported schema.  If a
        needs.json was generated without those options the fields will be
        absent from the need dicts and extraction will silently yield ``None``;
        this log message surfaces that situation.

        ``fields_by_type`` is empty when the export contains no ``needs_schema``
        (older Sphinx-Needs or minimal exports); in that case all safety fields
        will be absent from every need dict.
        """
        if not fields_by_type:
            logger.debug(
                "needs_schema not present in export — this may be from an older "
                "Sphinx-Needs version or a minimal export. Safety fields (%s) "
                "will be None for all nodes.",
                list(_SAFETY_EXTRA_FIELDS),
            )
            return

        registered_extras: frozenset[str] = fields_by_type.get("extra", frozenset())
        missing = [f for f in _SAFETY_EXTRA_FIELDS if f not in registered_extras]
        if missing:
            logger.warning(
                "Safety extra fields not found in needs_schema "
                "(not declared via needs_extra_options?): %s — "
                "these fields will be None for all nodes.",
                missing,
            )
        else:
            logger.debug(
                "Safety extra fields confirmed in schema: %s",
                list(_SAFETY_EXTRA_FIELDS),
            )

    def _parse_need(
        self,
        need_id: str,
        need: dict[str, Any],
        backlink_fields: frozenset[str],
        link_fields: frozenset[str],
        nodes: dict[str, StrictDocNode],
    ) -> None:
        """Parse a single need dict into a :class:`StrictDocNode`."""

        uid: str = need.get("id") or need_id
        if not uid:
            logger.warning(
                "Skipping need with no id (dict key %r has no 'id' field)",
                need_id,
            )
            return

        if uid != need_id:
            logger.debug(
                "Need dict key %r differs from embedded id %r — using embedded id as UID",
                need_id,
                uid,
            )

        if uid in nodes:
            logger.warning(
                "Duplicate need id %r — skipping second occurrence (dict key %r)",
                uid,
                need_id,
            )
            return

        # --- Core narrative fields ---
        title: str | None = need.get("title") or None

        # Prefer 'content' (the requirement body) as the statement;
        # fall back to 'description' (used in some custom types).
        raw_content: str = need.get("content", "")
        raw_description: str = need.get("description", "")
        statement: str | None = (raw_content or raw_description) or None

        rationale: str | None = need.get("rationale") or None

        # node_type: resolve via type-map → UID-prefix fallback → upper-case.
        raw_type: str = need.get("type", "req")
        node_type: str = self._infer_node_type(raw_type, uid)

        # --- Safety-specific extra fields (needs_extra_options) ---
        # Sphinx-Needs flattens all extra options into the top-level need dict.
        # Each field_type="extra" key is accessed the same way as any core key.
        # Values are JSON null (→ Python None) when undeclared for a need type.
        asil: str | None = need.get("asil") or None
        severity: str | None = need.get("severity") or None
        exposure: str | None = need.get("exposure") or None
        controllability: str | None = need.get("controllability") or None

        # --- Evidence fields ---
        evidence_artifact_id: str | None = need.get("artifact_id") or None
        evidence_timestamp_utc: str | None = need.get("timestamp_utc") or None
        # hash_value is the Sphinx-Needs extra field name; it maps to
        # evidence_hash on StrictDocNode.
        evidence_hash: str | None = need.get("hash_value") or None

        # --- Document source location ---
        docname: str | None = need.get("docname") or None
        document_path = Path(docname) if docname else None

        # --- Source file references (field_type="extra", maps to file_refs) ---
        # Sphinx-Needs stores file references in ``file_links`` (a list of
        # relative paths).  StrictDoc captures the same information via
        # ``@sdoc`` markers and stores them in StrictDocNode.file_refs.
        raw_file_links = need.get("file_links") or []
        file_refs: list[str] = (
            [str(f) for f in raw_file_links if f] if isinstance(raw_file_links, list) else []
        )

        # --- Parent UIDs (outgoing traceability links) ---
        parent_uids = self._extract_parent_uids(need, backlink_fields, link_fields)

        node = StrictDocNode(
            uid=uid,
            title=title,
            statement=statement,
            rationale=rationale,
            node_type=node_type,
            asil=asil,
            severity=severity,
            exposure=exposure,
            controllability=controllability,
            evidence_artifact_id=evidence_artifact_id,
            evidence_timestamp_utc=evidence_timestamp_utc,
            evidence_hash=evidence_hash,
            parent_uids=parent_uids,
            file_refs=file_refs,
            document_path=document_path,
        )

        nodes[uid] = node
        logger.debug(
            "Parsed need: %s (type=%s, parents=%s)",
            uid,
            node_type,
            parent_uids,
        )

    @staticmethod
    def _extract_parent_uids(
        need: dict[str, Any],
        backlink_fields: frozenset[str],
        link_fields: frozenset[str],
    ) -> list[str]:
        """
        Collect parent UIDs from all forward-link fields.

        Iterates every field in ``link_fields`` (schema-derived, so all typed
        link types including custom ones are covered) and skips any field that
        the schema marks as a back-link to avoid duplicate reverse edges.
        """
        seen: set[str] = set()
        parent_uids: list[str] = []

        for field_name in link_fields:
            if field_name in backlink_fields:
                continue
            raw_value = need.get(field_name)
            if not raw_value:
                continue
            # Values may be a list[str] or a comma-separated string.
            if isinstance(raw_value, list):
                items = raw_value
            else:
                items = [v.strip() for v in str(raw_value).split(",") if v.strip()]

            for item_uid in items:
                item_uid = item_uid.strip()
                if item_uid and item_uid not in seen:
                    seen.add(item_uid)
                    parent_uids.append(item_uid)

        return parent_uids

    @staticmethod
    def _infer_node_type(raw_type: str, uid: str) -> str:
        """
        Resolve a Sphinx-Needs ``type`` string to a canonical node-type label.

        Resolution order:

          1. If ``raw_type`` is empty, return :data:`_DEFAULT_NODE_TYPE`.
          2. Direct lookup in :data:`_TYPE_MAP`
           (e.g. ``test_case`` → ``TC``, ``evidence`` → ``EVID``).
          3. UID-prefix inference — the part before the first ``-``
           (e.g. ``EVID-001`` → ``EVID``, ``SSR-003`` → ``SSR``).
          4. ``raw_type.upper()`` as a final, lossless fallback.
        """
        if not raw_type:
            return _DEFAULT_NODE_TYPE

        mapped = _TYPE_MAP.get(raw_type.lower())
        if mapped:
            return mapped

        # Infer from UID prefix (e.g. "TC-001" → "TC")
        if "-" in uid:
            prefix = uid.split("-", 1)[0].strip()
            if prefix:
                return prefix.upper()

        return raw_type.upper()

    def _build_child_relationships(self, nodes: dict[str, StrictDocNode]) -> None:
        """
        Populate ``child_uids`` as the reverse of ``parent_uids``.

        Mirrors the behaviour of ``StrictDocParser._build_child_relationships``.
        Uses a set-based accumulator to avoid O(n) lookup on list membership.
        """
        # Accumulate children using sets for O(1) membership check
        child_uid_sets: dict[str, set[str]] = {}
        for uid, node in nodes.items():
            for parent_uid in node.parent_uids:
                if parent_uid in nodes:
                    child_uid_sets.setdefault(parent_uid, set()).add(uid)

        # Convert sets to lists and assign to nodes
        for parent_uid, child_set in child_uid_sets.items():
            nodes[parent_uid].child_uids.extend(child_set)
