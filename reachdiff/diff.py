"""Compare access before and after a plan, and shape the rows a reviewer sees."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from reachdiff.resolve import Entry, Route, groups_of, resolve
from reachdiff.scope import changed_objects, with_ancestors
from reachdiff.state import BUILTIN_GROUPS, Gap, State, ancestors, kind_of
from reachdiff.tfplan import Plan

USAGE = frozenset({'USE_CATALOG', 'USE_SCHEMA', 'ALL_PRIVILEGES'})


@dataclass(frozen=True)
class MemberCount:
    expanded: bool
    total: int = 0
    changed: int = 0  # members who newly gain (+) or lose (-) the entry
    unchanged: int = 0  # members who already had it (+) or keep it another way (-)
    names: tuple[str, ...] = ()
    unread: bool = False  # membership could not be read


@dataclass(frozen=True)
class Change:
    direction: str  # '+' gained, '-' lost
    principal: str
    kind: str
    level: str
    securable: str
    routes: tuple[Route, ...]
    members: MemberCount | None = None


@dataclass(frozen=True)
class AccessDiff:
    rows: tuple[Change, ...]  # what a reviewer sees: child rows collapse into parent rows
    all_rows: tuple[Change, ...]  # the same rows before collapsing; configured rules match these
    gained: frozenset
    lost: frozenset
    route_changes: tuple
    gaps: tuple[Gap, ...]


Members = dict[str, frozenset[str]]  # group -> transitive members, computed once per state


def _direct(state: State) -> dict[str, list[str]]:
    children: dict[str, list[str]] = {}
    for link in state.memberships:
        children.setdefault(link.group, []).append(link.member)
    return children


def _walk(children: dict[str, list[str]], group: str) -> set[str]:
    found: set[str] = set()
    queue = deque([group])
    while queue:
        for member in children.get(queue.popleft(), ()):
            if member not in found and member != group:
                found.add(member)
                queue.append(member)
    return found


def members_of(state: State, group: str) -> set[str]:
    """Transitive members through explicit memberships (built-in groups have none listed)."""
    return _walk(_direct(state), group)


def _member_map(state: State) -> Members:
    children = _direct(state)
    return {group: frozenset(_walk(children, group)) for group in children}


def _touched(before: State, after: State, plan: Plan) -> tuple[set[str], set[str]]:
    ids = {p.scim_id: p.name for s in (before, after) for p in s.principals.values() if p.scim_id}
    ids.update({scim_id: p.name for scim_id, p in plan.identities.items()})
    touched: set[str] = set()
    member_groups: set[str] = set()
    for resource in plan.changed_grants():
        touched |= set(resource.before or {}) | set(resource.after or {})
    for resource in plan.changed_owners():
        touched |= {x for x in (resource.before, resource.after) if x}
    for edge in plan.changed_memberships():
        for scim_id, bucket in ((edge.group_id, member_groups), (edge.member_id, touched)):
            if scim_id in ids:
                bucket.add(ids[scim_id])
    return touched | member_groups, member_groups


def _count(
    state: State, members_map: Members, group: str, entry: Entry, entries: frozenset, expanded: set[str]
) -> MemberCount:
    if group in state.unread_groups:
        return MemberCount(False, unread=True)
    if group in BUILTIN_GROUPS or group not in expanded:
        return MemberCount(False)
    members = sorted(m for m in members_map.get(group, ()) if state.kind(m) != 'group')
    changed = tuple(m for m in members if (m,) + entry[1:] in entries)
    return MemberCount(True, len(members), len(changed), len(members) - len(changed), changed)


def _explained(routes: tuple[Route, ...], group_rows: dict, level: str, securable: str) -> bool:
    """Hidden only when every route passes through a group shown in its own row for the same level and object."""
    shown = {
        group for group, row_level, row_securable in group_rows if (row_level, row_securable) == (level, securable)
    }
    return all(shown & set(route.main.chain) for route in routes)


def _rows(
    direction: str, entries: frozenset, state: State, members_map: Members, routes: dict, expanded: set[str]
) -> list[Change]:
    group_rows = {}
    for entry in sorted(entries):
        principal, level, securable = entry
        if state.kind(principal) == 'group':
            group_rows[entry] = Change(
                direction,
                principal,
                'group',
                level,
                securable,
                routes[entry],
                _count(state, members_map, principal, entry, entries, expanded),
            )
    rows = list(group_rows.values())
    for entry in sorted(entries):
        principal, level, securable = entry
        if entry not in group_rows and not _explained(routes[entry], group_rows, level, securable):
            rows.append(Change(direction, principal, state.kind(principal), level, securable, routes[entry]))
    return rows


def _sorted(rows: list[Change]) -> tuple[Change, ...]:
    return tuple(sorted(rows, key=lambda r: (r.direction, r.principal, r.level, r.securable)))


def _collapse(rows: list[Change]) -> tuple[Change, ...]:
    keys = {(r.direction, r.principal, r.level, r.securable) for r in rows}
    return _sorted(
        [r for r in rows if not any((r.direction, r.principal, r.level, a) in keys for a in ancestors(r.securable)[1:])]
    )


def _usage(state: State, securable: str) -> dict[str, frozenset[str]]:
    held: dict[str, frozenset[str]] = {}
    for grant in state.grants:
        if grant.securable == securable:
            held[grant.principal] = held.get(grant.principal, frozenset()) | (grant.privileges & USAGE)
    return held


def _latent(before: State, after: State, plan: Plan) -> list[Gap]:
    """Usage privileges gained or lost on a catalog or schema can change grants below it that were not read.

    Compared on the states, like the rows: a resource's plan `before` misses grants it replaces, such as the live
    grants on an object a `databricks_grants` create takes over.
    """
    gaps = []
    for securable in sorted({r.securable for r in plan.changed_grants() if kind_of(r.securable) != 'table'}):
        old, new = _usage(before, securable), _usage(after, securable)
        for principal in sorted(set(old) | set(new)):
            had, has = old.get(principal, frozenset()), new.get(principal, frozenset())
            if gained := has - had:
                gaps.append(
                    Gap(
                        'latent_grants',
                        f'{principal} gains {", ".join(sorted(gained))} on '
                        f'{securable}; this may activate existing table-level grants '
                        'that were not enumerated (use --deep)',
                    )
                )
            if lost := had - has:
                gaps.append(
                    Gap(
                        'deactivated_grants',
                        f'{principal} loses {", ".join(sorted(lost))} on '
                        f'{securable}; grants below it that relied on this may stop working '
                        'and were not enumerated (use --deep)',
                    )
                )
    return gaps


def compute_diff(before: State, after: State, plan: Plan, *, members_limit: int, deep: bool) -> AccessDiff:
    gaps: list[Gap] = []
    touched, member_groups = _touched(before, after, plan)
    holders = {h for g in member_groups for s in (before, after) for h in groups_of(s, g)}
    objects = set(changed_objects(plan))
    for s in (before, after):
        objects |= {g.securable for g in s.grants if g.principal in holders}
        objects |= {x.name for x in s.securables.values() if x.owner in holders}
        if deep:
            objects |= set(s.securables)
    objects = with_ancestors(objects)
    if deep:
        # A usage change can activate or deactivate anyone's grants below it, so evaluate every holder in scope.
        for s in (before, after):
            touched |= {g.principal for g in s.grants if g.securable in objects}
            touched |= {x.owner for x in s.securables.values() if x.owner and x.name in objects}
    groups = {p for p in touched if 'group' in (before.kind(p), after.kind(p))}
    members_before, members_after = _member_map(before), _member_map(after)

    def members(group: str) -> frozenset[str]:
        return members_before.get(group, frozenset()) | members_after.get(group, frozenset())

    subjects = set(touched)
    # Decided once: member counts are shown only for groups whose members were all evaluated.
    expanded: set[str] = set()
    skipped: list[str] = []
    for group in sorted(groups - set(BUILTIN_GROUPS)):
        if len(subjects | members(group)) > members_limit:
            skipped.append(group)
            continue
        subjects |= members(group)
        expanded.add(group)
    # A group nested in an expanded group comes along when every one of its members was evaluated.
    nested = {m for g in expanded for m in members(g) if 'group' in (before.kind(m), after.kind(m))} - set(skipped)
    expanded |= {g for g in nested if members(g) <= subjects}
    if skipped:
        gaps.append(Gap('limit_reached', f'members of {", ".join(skipped)} were not expanded beyond {members_limit}'))
    old, new = resolve(before, subjects, objects), resolve(after, subjects, objects)
    gained, lost = frozenset(new.keys() - old.keys()), frozenset(old.keys() - new.keys())
    route_changes = tuple((k, old[k], new[k]) for k in sorted(old.keys() & new.keys()) if old[k] != new[k])
    rows = _rows('+', gained, after, members_after, new, expanded) + _rows(
        '-', lost, before, members_before, old, expanded
    )
    if not deep:
        gaps += _latent(before, after, plan)
    return AccessDiff(_collapse(rows), _sorted(rows), gained, lost, route_changes, tuple(sorted(set(gaps))))
