"""Effective access per principal and object, with evidence routes."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from reachdiff.state import Grant, State, ancestors

LEVELS = ('READ', 'WRITE', 'MANAGE')
Entry = tuple[str, str, str]  # (principal, level, securable)


@dataclass(frozen=True, order=True)
class Hop:
    chain: tuple[str, ...]  # groups from the subject to the holder; () when the subject holds it
    privilege: str
    securable: str
    evidence: str = field(compare=False)


@dataclass(frozen=True, order=True)
class Route:
    main: Hop
    prerequisites: tuple[Hop, ...] = ()


def groups_of(state: State, subject: str) -> dict[str, tuple[str, ...]]:
    """The subject, every group it belongs to (shortest chain), and implicit `account users`."""
    chains: dict[str, tuple[str, ...]] = {subject: ()}
    if subject != 'account users':
        chains['account users'] = ('account users',)
    links = sorted(state.memberships, key=lambda m: (m.member, m.group))
    queue = deque([subject])
    while queue:
        current = queue.popleft()
        for link in links:
            if link.member == current and link.group not in chains:
                chains[link.group] = chains[current] + (link.group,)
                queue.append(link.group)
    return chains


def _by_securable(state: State) -> dict[str, list[Grant]]:
    index: dict[str, list[Grant]] = {}
    for grant in state.grants:
        index.setdefault(grant.securable, []).append(grant)
    return index


def _hops(grants: dict[str, list[Grant]], chains: dict, scope: tuple[str, ...], privileges: set[str]) -> list[Hop]:
    found = []
    for securable in scope:
        for grant in grants.get(securable, ()):
            if grant.principal in chains:
                for privilege in sorted(grant.privileges & privileges):
                    found.append(Hop(chains[grant.principal], privilege, grant.securable, grant.evidence))
    return sorted(found)


def _ownership(state: State, chains: dict, scope: tuple[str, ...]) -> list[Hop]:
    found = []
    for name in scope:
        securable = state.securables.get(name)
        if securable and securable.owner in chains:
            found.append(Hop(chains[securable.owner], 'OWNER', name, f'owner of {name}'))
    return sorted(found)


def _levels(state: State, grants: dict[str, list[Grant]], chains: dict, obj: str) -> dict[str, list[Route]]:
    chain = ancestors(obj)
    catalog = chain[-1]
    schema_scope = chain[-2:]  # (schema, catalog) for tables and schemas; (catalog,) for catalogs
    # Owners hold all privileges on the owned object and its children (Databricks docs), and MANAGE.
    owned = _ownership(state, chains, chain)

    def held(scope: tuple[str, ...], privileges: set[str]) -> list[Hop]:
        return sorted(_hops(grants, chains, scope, privileges) + [h for h in owned if h.securable in scope])

    use_catalog = held((catalog,), {'USE_CATALOG', 'ALL_PRIVILEGES'})
    use_schema = held(schema_scope, {'USE_SCHEMA', 'ALL_PRIVILEGES'})
    select = held(chain, {'SELECT', 'ALL_PRIVILEGES'})
    modify = held(chain, {'MODIFY', 'ALL_PRIVILEGES'})
    manage = held(chain, {'MANAGE'})
    levels = {'READ': [], 'WRITE': [], 'MANAGE': [Route(h) for h in manage]}
    if use_catalog and use_schema:
        usage = (use_catalog[0], use_schema[0])
        levels['READ'] = [Route(h, usage) for h in select]
        if select:
            levels['WRITE'] = [Route(h, usage + (select[0],)) for h in modify]
    return levels


def resolve(state: State, subjects: Iterable[str], objects: Iterable[str]) -> dict[Entry, tuple[Route, ...]]:
    result: dict[Entry, tuple[Route, ...]] = {}
    grants = _by_securable(state)
    for subject in sorted(set(subjects)):
        chains = groups_of(state, subject)
        for obj in sorted(set(objects)):
            for level, routes in _levels(state, grants, chains, obj).items():
                if routes:
                    result[(subject, level, obj)] = tuple(sorted(set(routes)))
    return result
