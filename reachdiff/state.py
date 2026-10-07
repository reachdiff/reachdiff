"""Snapshot of Unity Catalog access facts. Pure data; no I/O."""

from __future__ import annotations

from dataclasses import dataclass, field

KINDS = ('catalog', 'schema', 'table')
BUILTIN_GROUPS = {'account users': 'all account users', 'users': 'all workspace users', 'admins': 'workspace admins'}


def normalize_privilege(value: str) -> str:
    return value.strip().upper().replace(' ', '_')


def kind_of(name: str) -> str:
    parts = name.split('.')
    if len(parts) > 3 or any(not part for part in parts):
        raise ValueError(f'unsupported securable name: {name!r}')
    return KINDS[len(parts) - 1]


def parent_of(name: str) -> str | None:
    return name.rsplit('.', 1)[0] if '.' in name else None


def ancestors(name: str) -> tuple[str, ...]:
    """The object itself first, then its schema and catalog."""
    chain = [name]
    while (parent := parent_of(chain[-1])) is not None:
        chain.append(parent)
    return tuple(chain)


@dataclass(frozen=True, order=True)
class Gap:
    category: str
    detail: str


@dataclass(frozen=True)
class Principal:
    name: str
    kind: str  # 'user' | 'service_principal' | 'group' | 'unknown'
    scim_id: str | None = None


@dataclass(frozen=True)
class Securable:
    name: str
    owner: str | None = None
    tags: frozenset[str] = frozenset()  # tag keys on the object and, for tables, its columns

    @property
    def kind(self) -> str:
        return kind_of(self.name)


@dataclass(frozen=True)
class Grant:
    principal: str
    securable: str
    privileges: frozenset[str]
    evidence: str = field(compare=False)


@dataclass(frozen=True)
class Membership:
    member: str
    group: str
    evidence: str = field(compare=False)


@dataclass(frozen=True)
class State:
    source: str  # 'live' | 'offline'
    principals: dict[str, Principal]  # keyed by UC grant name
    securables: dict[str, Securable]  # keyed by full name
    grants: tuple[Grant, ...]
    memberships: tuple[Membership, ...]
    gaps: tuple[Gap, ...] = ()
    notes: tuple[str, ...] = ()
    unread_groups: frozenset[str] = frozenset()  # groups whose members could not be read

    def kind(self, name: str) -> str:
        if name in self.principals:
            return self.principals[name].kind
        if name in BUILTIN_GROUPS or any(m.group == name for m in self.memberships):
            return 'group'
        return 'user' if '@' in name else 'unknown'
