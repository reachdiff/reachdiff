"""Report dict and renderers. Reports name principals and objects: treat them as sensitive metadata."""

from __future__ import annotations

import json
from dataclasses import asdict

from reachdiff.diff import AccessDiff, Change
from reachdiff.resolve import Route
from reachdiff.scope import has_access_changes
from reachdiff.state import BUILTIN_GROUPS, State, kind_of
from reachdiff.tfplan import Plan

STANDING_LIMITATIONS = (
    'metastore and workspace admin powers',
    'ABAC policies, row filters and column masks',
    'workspace-level ACLs',
    'account and identity-provider membership completeness',
    'runtime behavior',
)


def route_text(route: Route) -> str:
    main = f'{route.main.privilege} on {route.main.securable}'
    if route.main.chain:
        main += f' (via {" → ".join(route.main.chain)})'
    parts, shown = [main], {(route.main.privilege, route.main.securable)}
    for hop in route.prerequisites:  # ownership can meet several requirements; show each hop once
        if (hop.privilege, hop.securable) not in shown:
            shown.add((hop.privilege, hop.securable))
            parts.append(f'{hop.privilege} on {hop.securable}')
    return ' + '.join(parts)


def _row(change: Change) -> dict:
    members = None
    if change.members is not None:
        members = {**asdict(change.members), 'names': list(change.members.names)}
    return {
        'direction': change.direction,
        'principal': change.principal,
        'kind': change.kind,
        'level': change.level,
        'securable': change.securable,
        'via': [route_text(r) for r in change.routes],
        'members': members,
    }


def build_report(plan: Plan, before: State, after: State, diff: AccessDiff, findings: tuple, status: str) -> dict:
    gaps = sorted(set(plan.gaps) | set(before.gaps) | set(after.gaps) | set(diff.gaps))
    return {
        'schema_version': 1,
        'tool': 'reachdiff',
        'status': status,
        'mode': before.source,
        'synthetic': plan.synthetic,
        'access_changes': has_access_changes(plan) or bool(plan.not_evaluated),
        'summary': {
            'gained': sum(r.direction == '+' for r in diff.rows),
            'lost': sum(r.direction == '-' for r in diff.rows),
            'findings': len(findings),
        },
        'changes': [_row(r) for r in diff.rows],
        'findings': [asdict(f) for f in findings],
        'not_evaluated': list(plan.not_evaluated),
        'gaps': [asdict(g) for g in gaps],
        'route_changes': [
            {
                'principal': k[0],
                'level': k[1],
                'securable': k[2],
                'before': [route_text(r) for r in old],
                'after': [route_text(r) for r in new],
            }
            for k, old, new in diff.route_changes
        ],
        'notes': sorted(set(before.notes) | set(after.notes)),
        'standing_limitations': list(STANDING_LIMITATIONS),
    }


def _who(row: dict) -> str:
    name, members = row['principal'], row['members']
    if name in BUILTIN_GROUPS:
        return f'{name} ({BUILTIN_GROUPS[name]})'
    if members is None:
        return name
    if members.get('unread'):
        return f'{name} (members not read)'
    if not members['expanded']:
        return f'{name} (members not expanded)'
    total = f'{members["total"]} member' + ('' if members['total'] == 1 else 's')
    if row['direction'] == '+':
        return f'{name} ({total}, {members["changed"]} new, {members["unchanged"]} already had it)'
    return f'{name} ({total}, {members["changed"]} lose it, {members["unchanged"]} keep it another way)'


def _where(securable: str) -> str:
    return securable + {'catalog': ' (all schemas)', 'schema': ' (all tables)', 'table': ''}[kind_of(securable)]


INLINE = (('\\', '\\\\'), ('\r', ' '), ('\n', ' '), ('<', '&lt;'), ('>', '&gt;'), ('[', '\\['), (']', '\\]'))


def _escape(text: str, pairs) -> str:
    for old, new in pairs:
        text = text.replace(old, new)
    return text


def _inline(text: str) -> str:
    """Untrusted text on one Markdown line: no line breaks, HTML tags, code spans or links."""
    return _escape(text, INLINE + (('`', "'"),))


def _cell(text: str) -> str:
    return _escape(text, INLINE + (('|', '\\|'),))


def _no_changes(report: dict) -> str:
    return 'No evaluated access changes; see findings.' if report['access_changes'] else 'No access changes.'


def _details(report: dict) -> list[str]:
    lines = [
        '- ' + _inline(f'{r["principal"]} {r["level"]} {r["securable"]}: {", ".join(r["members"]["names"])}')
        for r in report['changes']
        if r['members'] and r['members']['names']
    ]
    lines += [
        '- route changed: ' + _inline(f'{c["principal"]} {c["level"]} {c["securable"]}')
        for c in report['route_changes']
    ]
    lines += [f'- gap `{_inline(g["category"])}`: {_inline(g["detail"])}' for g in report['gaps']]
    lines += [f'- note: {_inline(n)}' for n in report['notes']]
    return lines or ['- nothing further']


def render_markdown(report: dict) -> str:
    label = 'SYNTHETIC FIXTURE · ' if report['synthetic'] else ''
    summary = report['summary']
    lines = [
        f'## reachdiff: {report["status"]}',
        '',
        f'_{label}{report["mode"]} mode_',
        '',
        f'**{summary["gained"]} gained · {summary["lost"]} lost · {summary["findings"]} findings**',
        '',
    ]
    if report['changes']:
        lines += ['| | Principal | Access | On | Via |', '|---|---|---|---|---|']
        lines += [
            f'| {r["direction"]} | {_cell(_who(r))} | {r["level"]} | {_cell(_where(r["securable"]))} | '
            f'{_cell("; ".join(r["via"]))} |'
            for r in report['changes']
        ]
    else:
        lines.append(_no_changes(report))
    if report['findings']:
        lines += ['', '### Findings', '']
        lines += [
            f'- **{f["severity"]}** `{_inline(f["rule"])}` {_inline(f["subject"])}: {_inline(f["message"])}'
            for f in report['findings']
        ]
    if report['not_evaluated']:
        lines += ['', f'### Not evaluated ({len(report["not_evaluated"])})', '']
        lines += [f'- {_inline(item)}' for item in report['not_evaluated']]
    lines += ['', '<details><summary>Details</summary>', ''] + _details(report)
    lines += [
        '',
        '</details>',
        '',
        f'<sub>Not evaluated in any run: {"; ".join(report["standing_limitations"])}.</sub>',
    ]
    return '\n'.join(lines) + '\n'


def render_text(report: dict) -> str:
    label = ', SYNTHETIC FIXTURE' if report['synthetic'] else ''
    summary = report['summary']
    lines = [
        f'reachdiff: {report["status"]} ({report["mode"]} mode{label})',
        f'{summary["gained"]} gained, {summary["lost"]} lost, {summary["findings"]} findings',
        '',
    ]
    for r in report['changes']:
        lines.append(f'{r["direction"]} {_who(r)}  {r["level"]}  {_where(r["securable"])}')
        lines += [f'    via {v}' for v in r['via']]
    if not report['changes']:
        lines.append(_no_changes(report))
    if report['findings']:
        lines += ['', 'Findings:'] + [
            f'  {f["severity"]} {f["rule"]} {f["subject"]}: {f["message"]}' for f in report['findings']
        ]
    if report['not_evaluated']:
        lines += ['', 'Not evaluated:'] + [f'  {item}' for item in report['not_evaluated']]
    if report['gaps']:
        lines += ['', 'Gaps:'] + [f'  {g["category"]}: {g["detail"]}' for g in report['gaps']]
    if report['route_changes']:
        lines += ['', 'Route changes:'] + [
            f'  {c["principal"]} {c["level"]} {c["securable"]}' for c in report['route_changes']
        ]
    if report['notes']:
        lines += ['', 'Notes:'] + [f'  {n}' for n in report['notes']]
    lines += ['', 'Not evaluated in any run: ' + '; '.join(report['standing_limitations']) + '.']
    # Every entry is one line: a line break inside a name must not forge report lines.
    return '\n'.join(line.replace('\r', ' ').replace('\n', ' ') for line in lines) + '\n'


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + '\n'


RENDERERS = {'text': render_text, 'json': render_json, 'md': render_markdown}
