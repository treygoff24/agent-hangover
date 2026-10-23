"""Native complexity anchors without pretending line numbers name functions."""
from __future__ import annotations

from collections import Counter, defaultdict
from hashlib import sha256
from pathlib import Path
import re
from typing import Any


def duplication_spans(finding: dict[str, Any]) -> frozenset[tuple[str, int, int]]:
    """Exact instance locations, including evidence-only pre-upgrade cards."""
    identity = finding.get("duplication_identity")
    if isinstance(identity, dict):
        records = identity.get("spans", [])
    else:
        records = []
        for line in finding.get("evidence", []):
            match = re.fullmatch(r"Instance: (.+):(\d+)-(\d+)", line) if isinstance(line, str) else None
            if match:
                records.append(dict(file=match[1], start_line=int(match[2]), end_line=int(match[3])))
            elif isinstance(line, str) and line.startswith("Instance:"):
                return frozenset()
    spans = set()
    for item in records:
        if not isinstance(item, dict):
            return frozenset()
        start, end = _position(item.get("start_line"), 1), _position(item.get("end_line"), 1)
        if not isinstance(item.get("file"), str) or not item["file"] or start is None or end is None or end < start:
            return frozenset()
        spans.add((item["file"], start, end))
    return frozenset(spans)


def _position(value: Any, minimum: int) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= minimum else None


def _source_spans(
    repo: Path | None, locations: list[dict[str, Any]],
) -> tuple[dict[int, str], dict[str, str]]:
    anchors: dict[int, str] = {}
    contexts: dict[str, str] = {}
    if repo is None:
        return anchors, contexts
    repo = repo.resolve()
    grouped: dict[str, list[int]] = defaultdict(list)
    for index, location in enumerate(locations):
        grouped[location["family"][0]].append(index)
    from .repository import open_repo_file  # Local import: repository imports model, which imports this.

    for name, indices in grouped.items():
        try:
            # The containment rule: a path the analyzer reports outside the repository, or through a
            # link, is refused (RepositoryRefusal, a RuntimeError) and stays ambiguous work.
            handle = open_repo_file(repo, name, purpose=f"finding file {name!r}")
            if handle is None:
                continue
            spans = {}
            for index in indices:
                start = locations[index]["line"]
                count = locations[index]["line_count"]
                if start is not None and count is not None:
                    spans[index] = (start, start + count - 1, sha256())
            context = sha256()
            line = 1
            last_line = 0
            with handle:
                # readline(size) also bounds a single huge/minified line.
                while chunk := handle.readline(64 * 1024):
                    context.update(chunk)
                    last_line = line
                    for start, end, digest in spans.values():
                        if start <= line <= end:
                            digest.update(chunk)
                    line += chunk.endswith(b"\n")
            contexts[name] = context.hexdigest()
            anchors.update({index: digest.hexdigest() for index, (_, end, digest) in spans.items()
                            if last_line >= end})
        except (OSError, ValueError, RuntimeError):
            # Unreadable/outside/symlinked spans remain explicit ambiguous work.
            continue
    return anchors, contexts


def _unique_positions(function_inventory: Any) -> dict[tuple[str, str], list[tuple[Any, Any]]] | None:
    if not isinstance(function_inventory, dict) or function_inventory.get("complete") is not True:
        return None
    found: dict[tuple[str, str], list[tuple[Any, Any]]] = {}
    for item in function_inventory.get("functions") or []:
        if isinstance(item, dict) and isinstance(item.get("positions"), list):
            found.setdefault((item.get("path"), item.get("name")), []).extend(
                tuple(position) for position in item["positions"] if isinstance(position, (list, tuple)))
    return found


def assign_complexity_identities(
    findings: list[dict[str, Any]], repo: Path | None, function_inventory: Any = None,
) -> None:
    """Key a complexity card by file and name when Fallow's full function listing shows one such function.

    Fallow reports only functions above a threshold, so one reported finding
    does not make the name unique: a same-name sibling below its threshold can
    cross later and would inherit the card. `function_inventory` is Fallow's
    complete, syntax-aware listing of the functions (zero thresholds). The name
    key is used only when it lists exactly one function of that name in the
    file and that function is the reported one; without complete evidence
    the span-anchored, explicitly ambiguous identities apply and are never
    silently renumbered.
    """
    locations = [finding["complexity_identity"] for finding in findings]
    for location in locations:
        for field, minimum in (("line", 1), ("col", 0), ("line_count", 1)):
            location[field] = _position(location.get(field), minimum)
    families = Counter(tuple(location["family"]) for location in locations)
    anchors, contexts = _source_spans(repo, locations)
    listed = _unique_positions(function_inventory)
    named = {index for index, location in enumerate(locations)
             if listed is not None and families[tuple(location["family"])] == 1
             and listed.get(tuple(location["family"])) == [(location["line"], location["col"])]}
    spans = Counter((tuple(location["family"]), anchors.get(index)) for index, location in enumerate(locations))
    occurrences: Counter[tuple[Any, ...]] = Counter()
    for index, (finding, location) in enumerate(zip(findings, locations)):
        path, name = location["family"]
        anchor = anchors.get(index)
        if index in named:
            finding["fingerprint"] = ["fallow", "complexity", path, name, "fn-v3"]
            location.update(version=3, span_sha256=anchor, context_sha256=None, ambiguous=False, stable=True)
            continue
        ambiguous = anchor is None or spans[(tuple(location["family"]), anchor)] > 1
        context = contexts.get(path) if ambiguous else None
        point = (path, name, anchor, location["line"], location["col"])
        occurrence = occurrences[point]
        occurrences[point] += 1
        finding["fingerprint"] = ["fallow", "complexity", path, name, "span-v2", anchor]
        if ambiguous:
            # Full file context prevents ordinal/position reuse after a change
            # swaps identical bodies or removes an earlier same-named function.
            finding["fingerprint"] = ["fallow", "complexity", path, name, "ambiguous-v2",
                                      anchor, context, location["line"], location["col"], occurrence]
            finding["evidence"].append(
                "Function identity is ambiguous: the source span is unavailable or not unique. "
                "Inspect the reported location; prior per-location dispositions are not proof of resolution."
            )
        location.update(version=2, span_sha256=anchor, context_sha256=context,
                        ambiguous=ambiguous, stable=anchor is not None and (not ambiguous or context is not None))
        if families[tuple(location["family"])] > 1:
            finding["title"] += f":{location['line']}:{location['col']}"
