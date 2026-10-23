"""Evidence caveats shared by ingestion, ledger transitions, and verification."""
import json
from pathlib import Path
from typing import Any

# Kinds that predate Fallow's own `degrades_analysis` marker (3.27). Fallow asks
# consumers to read the marker instead of an allowlist so later degrading kinds
# reach an unchanged consumer; the list keeps older kinds covered either way.
UNREAD_KINDS = frozenset({
    'source-parse-degraded', 'source-read-failure', 'skipped-large-file',
    'skipped-minified-file', 'skipped-source-dotdir',
})
# The run analyzed nothing, so absent findings prove nothing.
EMPTY_ANALYSIS_KIND = 'no-source-files-analyzed'


def _diagnostics(result: dict[str, Any]):
    for command in result.get('commands', {}).values():
        data = command.get('data') or {}
        for item in data.get('workspace_diagnostics') or []:
            if isinstance(item, dict) and isinstance(item.get('kind'), str) and isinstance(item.get('path'), str):
                yield item


def degrading_diagnostics(result: dict[str, Any]) -> list[dict[str, str]]:
    records = {}
    for item in _diagnostics(result):
        if item['kind'] in UNREAD_KINDS or item.get('degrades_analysis') is True:
            records[(item['path'], item['kind'])] = {'path': item['path'], 'kind': item['kind']}
    return [records[key] for key in sorted(records)]


def empty_analysis(result: dict[str, Any]) -> bool:
    return any(item['kind'] == EMPTY_ANALYSIS_KIND for item in _diagnostics(result))


def degrading_index(result: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    """Index degrading diagnostics once for repeated per-finding lookups."""
    index: dict[str, list[dict[str, str]]] = {}
    for item in degrading_diagnostics(result):
        index.setdefault(item['path'].rstrip('/'), []).append(item)
    return index


def caveat_reasons(result: dict[str, Any], files,
                   index: dict[str, list[dict[str, str]]] | None = None) -> list[str]:
    # Only a skipped finding file can hide that finding from this run.
    if index is None:
        index = degrading_index(result)
    covering: dict[tuple[str, str], dict[str, str]] = {}
    for file in files:
        keys = [file]
        position = file.find('/')
        while position != -1:
            keys.append(file[:position])
            position = file.find('/', position + 1)
        for key in keys:
            for item in index.get(key, ()):
                # Preserve exact-path semantics for diagnostics with a trailing slash.
                if _covers(item['path'], (file,)):
                    covering[(item['path'], item['kind'])] = item
    return [f"{item['kind']}: {item['path']} was not fully analyzed"
            for _, item in sorted(covering.items())]


def _covers(path: str, files) -> bool:
    # A folder diagnostic (an undeclared workspace, a broken tsconfig directory)
    # covers every file beneath it. A root-level `.` diagnostic matches no file:
    # it is summarized in the scan warnings, since holding every card would
    # freeze the campaign.
    return any(file == path or file.startswith(path.rstrip('/') + '/') for file in files)


def type_aware_degradation(result: dict[str, Any]) -> str | None:
    command = result.get('commands', {}).get('dead_code', {})
    if command.get('fallback') == 'type_aware_failed':
        return command.get('fallback_reason') or 'type-aware sidecar failed'
    meta = (command.get('data') or {}).get('_meta', {}).get('type_aware', {})
    warnings = meta.get('warnings') or []
    completeness = (meta.get('identity') or {}).get('completeness')
    if (completeness == 'partial' and not warnings and not meta.get('warning_count', 0)
            and _partial_only_retains(meta) and _api_surface_settled(result, meta)):
        return None
    if warnings or meta.get('warning_count', 0) or completeness in {'partial', 'incomplete', 'degraded'}:
        return '; '.join(str(w) for w in warnings) or f'type-aware evidence incomplete ({completeness or "warning_count"})'
    return None


RETAINED_DECISIONS = frozenset({'retained-abstained', 'retained-unresolved'})
KNOWN_CAPABILITIES = frozenset({'symbol-use', 'api-surface'})


def _partial_only_retains(meta: dict[str, Any]) -> bool:
    """A partial type-aware pass hides nothing when every incomplete query kept its candidate.

    The semantic pass removes a syntactic candidate only on positive evidence
    of use; an abstention keeps the finding (with its own caveat), so absent
    findings stay trustworthy. Any other incomplete query, or a payload
    without per-candidate decisions, stays degraded.
    """
    decisions = meta.get('candidate_decisions')
    queries = meta.get('queries')
    if not isinstance(decisions, list) or not isinstance(queries, list) or not queries:
        return False
    retained = set()
    for item in decisions:
        if not isinstance(item, dict):
            return False
        if item.get('status') != 'complete':
            if item.get('decision') not in RETAINED_DECISIONS:
                return False
            retained.add(item.get('query_id'))
    return all(isinstance(query, dict) and (query.get('status') == 'complete' or query.get('query_id') in retained)
               for query in queries)


def _api_surface_settled(result: dict[str, Any], meta: dict[str, Any]) -> bool:
    """`partial` covers every requested capability, not only symbol use.

    api-surface evidence produces cross-file private type leak findings, so a
    partial run is acceptable only when that capability finished completely or
    the repository has the private-type-leaks rule off (hangover then consumes
    none of its findings).
    """
    capabilities = (meta.get('identity') or {}).get('capabilities') or []
    if not set(capabilities) <= KNOWN_CAPABILITIES:
        return False  # a later capability may produce findings hangover consumes
    if 'api-surface' not in capabilities:
        return True
    surface = meta.get('api_surface')
    if isinstance(surface, dict) and surface.get('status') == 'complete':
        return True
    return _config_rules(result).get('private-type-leaks') == 'off'


def _config_rules(result: dict[str, Any]) -> dict[str, Any]:
    """Resolved rules, read like the scan reads them: parsed data, else the raw file."""
    command = result.get('commands', {}).get('config', {})
    config = command.get('data')
    if not isinstance(config, dict) and isinstance(command.get('raw'), str):
        try:
            config = json.loads(Path(command['raw']).read_text())
        except (OSError, ValueError):
            config = None
    rules = config.get('rules') if isinstance(config, dict) else None
    return rules if isinstance(rules, dict) else {}


def semantic_caveat(item: dict[str, Any]) -> list[str]:
    semantic = item.get('semantic')
    if not isinstance(semantic, dict) or semantic.get('status') in (None, 'complete'):
        return []
    detail = semantic.get('explanation') or semantic.get('decision') or 'no reason given'
    return [f"Type-aware analysis could not confirm this is unused ({semantic.get('reason_code', 'unknown')}): {detail}"]


def fallow_clock(result: dict[str, Any]) -> dict[str, Any]:
    health = result.get('commands', {}).get('health', {}).get('data') or {}
    clock = (health.get('hotspot_summary') or {}).get('clock') or {}
    epoch = clock.get('epoch_secs')
    if type(epoch) is not int or epoch < 0:
        return {}
    return {key: clock.get(key) for key in ('epoch_secs', 'source', 'reproducible')}
