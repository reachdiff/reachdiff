"""Read `terraform show -json` output. Extract only the resource types reachdiff needs.

Plan JSON can contain secrets in plain text. Only the attributes named here are read,
and error messages name resource addresses, never values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from reachdiff.state import Gap, Principal, kind_of, normalize_privilege

SUPPORTED_ATTRS = ('catalog', 'schema', 'table')
OTHER_ATTRS = (
    'volume',
    'function',
    'model',
    'external_location',
    'storage_credential',
    'metastore',
    'share',
    'foreign_connection',
    'credential',
)
MODELED = frozenset({'USE_CATALOG', 'USE_SCHEMA', 'SELECT', 'MODIFY', 'MANAGE', 'ALL_PRIVILEGES', 'BROWSE'})
GRANT_TYPES = ('databricks_grants', 'databricks_grant')
OWNER_TYPES = {
    'databricks_catalog': ('name',),
    'databricks_schema': ('catalog_name', 'name'),
    'databricks_sql_table': ('catalog_name', 'schema_name', 'name'),
}
IDENTITY_TYPES = {
    'databricks_group': ('group', 'display_name'),
    'databricks_user': ('user', 'user_name'),
    'databricks_service_principal': ('service_principal', 'application_id'),
}
RELEVANT = {
    'databricks_grants': SUPPORTED_ATTRS + OTHER_ATTRS + ('grant',),
    'databricks_grant': SUPPORTED_ATTRS + OTHER_ATTRS + ('principal', 'privileges'),
    'databricks_group_member': ('group_id', 'member_id'),
    **{t: keys + ('owner',) for t, keys in OWNER_TYPES.items()},
}
ACCOUNT_HOST = re.compile(r'^https://accounts\.')


@dataclass(frozen=True)
class GrantResource:
    address: str
    securable: str
    authoritative: bool
    before: dict[str, frozenset[str]] | None
    after: dict[str, frozenset[str]] | None


@dataclass(frozen=True)
class MembershipResource:
    address: str
    group_id: str
    member_id: str
    before: bool
    after: bool


@dataclass(frozen=True)
class OwnerResource:
    address: str
    securable: str
    before: str | None
    after: str | None


@dataclass(frozen=True)
class Plan:
    hosts: tuple[str, ...]
    grants: tuple[GrantResource, ...]
    memberships: tuple[MembershipResource, ...]
    owners: tuple[OwnerResource, ...]
    identities: dict[str, Principal]
    gaps: tuple[Gap, ...]
    not_evaluated: tuple[str, ...]
    synthetic: bool = False

    def changed_grants(self) -> tuple[GrantResource, ...]:
        return tuple(g for g in self.grants if g.before != g.after)

    def changed_memberships(self) -> tuple[MembershipResource, ...]:
        return tuple(m for m in self.memberships if m.before != m.after)

    def changed_owners(self) -> tuple[OwnerResource, ...]:
        return tuple(o for o in self.owners if o.before != o.after)


def _any_true(value: object) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_any_true(v) for v in value.values())
    if isinstance(value, list):
        return any(_any_true(v) for v in value)
    return False


def _flagged(marks: object, keys: tuple[str, ...]) -> bool:
    """True if a listed attribute is marked in a Terraform unknown/sensitive structure."""
    if marks is True:
        return True
    return isinstance(marks, dict) and any(_any_true(marks.get(k)) for k in keys)


def _privileges(value: object, address: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(p, str) and p.strip() for p in value):
        raise ValueError(f'{address}: privileges must be a list of names')
    return frozenset(normalize_privilege(p) for p in value)


def _securable(values: dict, address: str) -> tuple[str | None, str | None, object]:
    """(name, None, name) for an evaluated securable, or (None, attribute, value) for another type.

    The last element only tells the two sides of a change apart. It is never emitted.
    """
    for attr in SUPPORTED_ATTRS:
        name = values.get(attr)
        if name:
            if not isinstance(name, str):
                raise ValueError(f'{address}: {attr} is not a valid {attr} full name')
            try:
                if kind_of(name) != attr:
                    raise ValueError(f'{address}: {attr} is not a valid {attr} full name')
            except ValueError:
                raise ValueError(f'{address}: {attr} is not a valid {attr} full name') from None
            return name.lower(), None, name.lower()
    for attr in OTHER_ATTRS:
        if values.get(attr):
            return None, attr, values[attr]
    raise ValueError(f'{address}: grant resource has no securable attribute')


def _grant_map(values: dict, authoritative: bool, address: str) -> dict[str, frozenset[str]]:
    if not authoritative:
        principal = values.get('principal')
        if not isinstance(principal, str) or not principal:
            raise ValueError(f'{address}: principal must be a nonempty string')
        return {principal: _privileges(values.get('privileges'), address)}
    blocks = values.get('grant') or []
    if not isinstance(blocks, list):
        raise ValueError(f'{address}: grant must be a list')
    result: dict[str, frozenset[str]] = {}
    for block in blocks:
        principal = block.get('principal') if isinstance(block, dict) else None
        if not isinstance(principal, str) or not principal:
            raise ValueError(f'{address}: every grant block needs a principal')
        result[principal] = result.get(principal, frozenset()) | _privileges(block.get('privileges'), address)
    return result


def _edge(values: object, address: str) -> tuple[str, str] | None:
    if values is None:
        return None
    group, member = values.get('group_id'), values.get('member_id')
    if not isinstance(group, str) or not group or not isinstance(member, str) or not member:
        raise ValueError(f'{address}: group_id and member_id must be nonempty strings')
    return group, member


def _owned(values: object, rtype: str, address: str) -> tuple[str | None, str | None]:
    """(securable name, owner) for an owner-bearing resource, or (None, None)."""
    if values is None:
        return None, None
    parts = [values.get(k) for k in OWNER_TYPES[rtype]]
    if not all(isinstance(p, str) and p for p in parts):
        return None, None
    value = values.get('owner')
    if value is not None and not isinstance(value, str):
        raise ValueError(f'{address}: owner must be a string')
    return '.'.join(parts).lower(), value or None


def _add_identity(values: object, rtype: str, identities: dict[str, Principal], *marks: object) -> None:
    """marks: the sensitivity structures covering `values`. A name marked sensitive is never read."""
    kind, field = IDENTITY_TYPES[rtype]
    if any(_flagged(m, (field,)) for m in marks):
        return
    if isinstance(values, dict) and isinstance(values.get('id'), str) and isinstance(values.get(field), str):
        identities[values['id']] = Principal(values[field], kind, values['id'])


def _prior_resources(module: object):
    if not isinstance(module, dict):
        return
    yield from (r for r in module.get('resources') or [] if isinstance(r, dict))
    for child in module.get('child_modules') or []:
        yield from _prior_resources(child)


def _object(value: object, where: str) -> dict:
    """An optional JSON object: absent or null reads as empty, anything else must be an object."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f'{where} must be an object')
    return value


def _providers(raw: dict) -> tuple[tuple[str, ...], int]:
    configs = _object(
        _object(raw.get('configuration'), 'configuration').get('provider_config'), 'configuration.provider_config'
    )
    hosts, workspace = set(), 0
    for key, config in configs.items():
        if not isinstance(config, dict):
            raise ValueError(f'provider_config {key} must be an object')
        if config.get('name') != 'databricks':
            continue
        expressions = _object(config.get('expressions'), f'provider_config {key}: expressions')
        host = _object(expressions.get('host'), f'provider_config {key}: expressions.host').get('constant_value')
        if 'account_id' in expressions or (isinstance(host, str) and ACCOUNT_HOST.match(host)):
            continue
        workspace += 1
        if isinstance(host, str) and host:
            hosts.add(host.rstrip('/'))
    return tuple(sorted(hosts)), workspace


def _conflicts(grants: list[GrantResource]) -> list[str]:
    """Grants on one securable set by more than one resource, counted by address. Resources being destroyed count."""
    by_securable: dict[str, list[GrantResource]] = {}
    for resource in grants:
        by_securable.setdefault(resource.securable, []).append(resource)
    details = []
    for securable, resources in sorted(by_securable.items()):
        authoritative = sorted({r.address for r in resources if r.authoritative})
        holders: dict[str, set[str]] = {}
        for r in resources:
            if not r.authoritative:
                for principal in set(r.before or {}) | set(r.after or {}):
                    holders.setdefault(principal, set()).add(r.address)
        if authoritative and holders:
            details.append(f'{securable}: databricks_grants and databricks_grant both manage it')
        if len(authoritative) > 1:
            details.append(f'{securable}: {", ".join(authoritative)} each manage all of its grants')
        for principal, addresses in sorted(holders.items()):
            if len(addresses) > 1:
                details.append(f'{securable}: {", ".join(sorted(addresses))} each manage the grants of {principal}')
    return details


def read_plan(raw: object) -> Plan:
    if not isinstance(raw, dict):
        raise ValueError('plan must be a JSON object produced by terraform show -json')
    version = raw.get('format_version')
    if not isinstance(version, str) or version.split('.')[0] != '1':
        raise ValueError('unsupported plan format_version; expected 1.x from terraform show -json')
    changes = raw.get('resource_changes', [])
    if not isinstance(changes, list):
        raise ValueError('resource_changes must be a list')
    hosts, workspace_providers = _providers(raw)
    gaps: list[Gap] = []
    if workspace_providers > 1:
        gaps.append(
            Gap(
                'multiple_workspace_providers',
                f'the plan has {workspace_providers} workspace '
                'provider configurations; results assume they share one metastore',
            )
        )
    not_evaluated: list[str] = []
    grants, memberships, owners = [], [], []
    identities: dict[str, Principal] = {}
    for resource in _prior_resources(((raw.get('prior_state') or {}).get('values') or {}).get('root_module')):
        if resource.get('type') in IDENTITY_TYPES:
            _add_identity(resource.get('values'), resource['type'], identities, resource.get('sensitive_values'))
    for rc in changes:
        if not isinstance(rc, dict) or not isinstance(rc.get('change'), dict):
            raise ValueError('resource_changes entries must be objects with a change')
        rtype, address, change = rc.get('type'), str(rc.get('address', '?')), rc['change']
        if rtype not in IDENTITY_TYPES and (rc.get('mode') != 'managed' or rtype not in RELEVANT):
            continue
        before, after = change.get('before'), change.get('after')
        if not all(v is None or isinstance(v, dict) for v in (before, after)):
            raise ValueError(f'{address}: change.before and change.after must be objects or null')
        if rtype in IDENTITY_TYPES:
            for values in (before, after):
                _add_identity(values, rtype, identities, change.get('before_sensitive'), change.get('after_sensitive'))
            continue
        if 'forget' in (change.get('actions') or []):
            after = before
        keys = RELEVANT[rtype]
        if _flagged(change.get('before_sensitive'), keys) or _flagged(change.get('after_sensitive'), keys):
            gaps.append(Gap('sensitive_value', f'{address}: a relevant value is marked sensitive and was not read'))
            continue
        if after is not None and _flagged(change.get('after_unknown'), keys):
            gaps.append(Gap('unknown_after_apply', f'{address}: relevant values are known only after apply'))
            after = before
        if rtype in GRANT_TYPES:
            if before is None and after is None:
                continue
            authoritative = rtype == 'databricks_grants'
            old_target = None if before is None else _securable(before, address)
            new_target = None if after is None else _securable(after, address)
            old = None if before is None else _grant_map(before, authoritative, address)
            new = None if after is None else _grant_map(after, authoritative, address)
            if old_target and new_target and old_target[1:] != new_target[1:]:
                # The securable itself changes: the old one loses these grants, the new one gains them.
                sides = [(old_target, old, None), (new_target, None, new)]
            else:
                sides = [(new_target or old_target, old, new)]
            for (securable, other, _), side_old, side_new in sides:
                if other:
                    if side_old != side_new:
                        not_evaluated.append(f'{address}: grants on a {other.replace("_", " ")}')
                    continue
                grants.append(GrantResource(address, securable, authoritative, side_old, side_new))
                for principal in sorted(set(side_old or {}) | set(side_new or {})):
                    delta = (side_old or {}).get(principal, frozenset()) ^ (side_new or {}).get(principal, frozenset())
                    if delta - MODELED:
                        not_evaluated.append(
                            f'{address}: {", ".join(sorted(delta - MODELED))} for {principal} on {securable}'
                        )
        elif rtype == 'databricks_group_member':
            old, new = _edge(before, address), _edge(after, address)
            if old and new and old != new:
                memberships += [
                    MembershipResource(address, *old, True, False),
                    MembershipResource(address, *new, False, True),
                ]
            elif old or new:
                memberships.append(MembershipResource(address, *(old or new), old is not None, new is not None))
        else:
            (old_name, old_owner), (new_name, new_owner) = _owned(before, rtype, address), _owned(after, rtype, address)
            securable = new_name or old_name
            if securable:
                owners.append(
                    OwnerResource(
                        address,
                        securable,
                        old_owner if old_name == securable else None,
                        new_owner if new_name == securable else None,
                    )
                )
    for detail in _conflicts(grants):
        gaps.append(Gap('conflicting_grant_resources', f'{detail}; the applied result depends on apply order'))
    return Plan(
        hosts,
        tuple(grants),
        tuple(memberships),
        tuple(owners),
        identities,
        tuple(sorted(set(gaps))),
        tuple(sorted(set(not_evaluated))),
        raw.get('reachdiff_fixture') == 'synthetic',
    )
