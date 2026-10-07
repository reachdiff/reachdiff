"""Built-in and configured rules. Every finding names the row or gap that raised it."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from fnmatch import fnmatchcase

from reachdiff.config import Config
from reachdiff.diff import AccessDiff, Change
from reachdiff.scope import changed_objects, has_access_changes
from reachdiff.state import BUILTIN_GROUPS, Gap, State, ancestors, kind_of
from reachdiff.tfplan import Plan

BROAD = frozenset({'ALL_PRIVILEGES', 'MANAGE'})
# A change whose values could not be read may still change access, so it can never PASS.
UNREADABLE_PLAN_VALUES = frozenset({'unknown_after_apply', 'sensitive_value'})


@dataclass(frozen=True, order=True)
class Finding:
    severity: str  # 'BLOCK' sorts before 'WARN'
    rule: str
    subject: str
    message: str


def sensitive(state: State, securable: str, globs: tuple[str, ...]) -> bool:
    """A matching tag on the object, a parent, or a child present in the state."""
    names = set(ancestors(securable)) | {n for n in state.securables if n.startswith(securable + '.')}
    return any(
        fnmatchcase(tag, glob)
        for name in names
        if name in state.securables
        for tag in state.securables[name].tags
        for glob in globs
    )


def _column_tags_unread(state: State, securable: str, changed: set[str]) -> bool:
    """Column tags are read only for tables the plan changes; any other table here was not checked."""
    names = {securable} | {n for n in state.securables if n.startswith(securable + '.')}
    return any(kind_of(n) == 'table' and n not in changed for n in names)


def _subject(row: Change) -> str:
    return f'{row.principal} {row.level} {row.securable}'


def _exempt(row: Change, unless_via: frozenset[str]) -> bool:
    return bool(unless_via) and all(({row.principal} | set(r.main.chain)) & unless_via for r in row.routes)


def _glob_tokens(pattern: str) -> list[str]:
    """Split a glob as fnmatch reads it: `*`, `?`, each `[...]` class and each literal character.

    An unclosed `[` is a literal; it is re-escaped as `[[]` so that a prefix of the tokens stays a valid glob.
    """
    tokens, i, n = [], 0, len(pattern)
    while i < n:
        if pattern[i] == '[':
            j = i + 1
            if j < n and pattern[j] == '!':
                j += 1
            if j < n and pattern[j] == ']':
                j += 1
            while j < n and pattern[j] != ']':
                j += 1
            if j < n:
                tokens.append(pattern[i : j + 1])
                i = j + 1
                continue
            tokens.append('[[]')
        else:
            tokens.append(pattern[i])
        i += 1
    return tokens


def _object_matches(securable: str, pattern: str) -> bool:
    """The pattern matches the row's object, or some object below it, even when `*` spans a dot.

    A child's name is `securable + '.' + rest`, where rest is not empty and adds at most one more part under a
    catalog and none under a schema. Some child can match when a prefix of the pattern's tokens matches
    `securable + '.'` exactly, and the remaining tokens can match a nonempty rest with no more literal dots
    than rest may contain. (A `*` ending the prefix can also run on into rest.) Matching ignores case, as Unity
    Catalog does.
    """
    pattern = pattern.lower()  # Unity Catalog names are case-insensitive and stored in lowercase
    if fnmatchcase(securable, pattern):
        return True
    budget = 1 - securable.count('.')  # catalog 1, schema 0; a table has no children
    if budget < 0:
        return False
    tokens, head = _glob_tokens(pattern), securable + '.'
    return any(
        (k < len(tokens) or tokens[k - 1] == '*')
        and tokens[k:].count('.') <= budget
        and fnmatchcase(head, ''.join(tokens[:k]))
        for k in range(1, len(tokens) + 1)
    )


def _matches(rule, row: Change, before: State, after: State, globs) -> bool:
    """Matching fails closed: a parent row and a principal of unknown kind can both hide a match."""
    if rule.when != 'any' and row.direction != ('+' if rule.when == 'gain' else '-'):
        return False
    if rule.levels and row.level not in rule.levels:
        return False
    if rule.objects and not any(_object_matches(row.securable, p) for p in rule.objects):
        return False
    if rule.principal_kinds and row.kind not in rule.principal_kinds and row.kind != 'unknown':
        return False
    state = after if row.direction == '+' else before
    if rule.sensitive is not None and sensitive(state, row.securable, globs) != rule.sensitive:
        return False
    return not _exempt(row, rule.unless_via)


def evaluate(
    diff: AccessDiff, plan: Plan, before: State, after: State, config: Config, *, deep: bool
) -> tuple[Finding, ...]:
    findings: list[Finding] = []

    def add(rule: str, subject: str, message: str, severity: str | None = None) -> None:
        severity = severity or config.builtin[rule]
        if severity != 'off':
            findings.append(Finding(severity, rule, subject, message))

    extra: list[Gap] = []
    changed = changed_objects(plan)
    for row in (r for r in diff.rows if r.direction == '+'):
        if row.principal in ('account users', 'users'):
            add(
                'broad_principal', _subject(row), f'{BUILTIN_GROUPS[row.principal]} gain {row.level} on {row.securable}'
            )
        if row.level in ('READ', 'WRITE') and config.builtin['sensitive_access'] != 'off':
            if sensitive(after, row.securable, config.sensitive_tags):
                add(
                    'sensitive_access',
                    _subject(row),
                    f'{row.principal} gains {row.level} on sensitive data in {row.securable}',
                )
            elif kind_of(row.securable) != 'table' and not deep:
                extra.append(
                    Gap(
                        'sensitivity_not_evaluated',
                        f'child table sensitivity not evaluated for {row.securable} (use --deep)',
                    )
                )
            elif deep and _column_tags_unread(after, row.securable, changed):
                what = row.securable if kind_of(row.securable) == 'table' else f'child tables under {row.securable}'
                extra.append(Gap('sensitivity_not_evaluated', f'column tags of {what} were not read'))
    for resource in plan.changed_grants():
        if kind_of(resource.securable) == 'table':
            continue
        for principal, privileges in sorted((resource.after or {}).items()):
            broad = sorted((privileges - (resource.before or {}).get(principal, frozenset())) & BROAD)
            if broad:
                add(
                    'broad_privilege',
                    f'{principal} {"+".join(broad)} {resource.securable}',
                    f'{", ".join(broad)} granted to {principal} on {kind_of(resource.securable)} {resource.securable}',
                )
    for resource in plan.changed_owners():
        if resource.after and after.kind(resource.after) == 'user':
            add(
                'individual_owner',
                f'{resource.after} OWNER {resource.securable}',
                f'ownership of {resource.securable} moves to the individual user {resource.after}',
            )
    if has_access_changes(plan):
        for gap in plan.gaps:
            if gap.category == 'conflicting_grant_resources':
                securable, _, detail = gap.detail.partition(': ')
                add('grant_resource_conflict', securable, f'{detail}, and grants can be lost without an error')
    for rule in config.rules:
        for row in diff.all_rows:
            if _matches(rule, row, before, after, config.sensitive_tags):
                add(rule.id, _subject(row), rule.message, rule.severity)
    unreadable = any(g.category in UNREADABLE_PLAN_VALUES for g in plan.gaps)
    if has_access_changes(plan) or plan.not_evaluated or unreadable:
        gaps = set(plan.gaps) | set(before.gaps) | set(after.gaps) | set(diff.gaps) | set(extra)
        if plan.not_evaluated:
            gaps.add(Gap('not_evaluated', f'{len(plan.not_evaluated)} change(s) are outside what v0.1 evaluates'))
        by_category: dict[str, list[str]] = defaultdict(list)
        for gap in sorted(gaps):
            by_category[gap.category].append(gap.detail)
        for category, details in sorted(by_category.items()):
            more = f' (+{len(details) - 1} more)' if len(details) > 1 else ''
            add('unverified', category, details[0] + more)
    return tuple(sorted(set(findings)))


def status_of(findings: tuple[Finding, ...]) -> str:
    severities = {f.severity for f in findings}
    return 'BLOCK' if 'BLOCK' in severities else 'WARN' if 'WARN' in severities else 'PASS'
