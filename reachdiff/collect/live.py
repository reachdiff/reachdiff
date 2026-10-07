"""Read-only Databricks reads limited to what a plan touches. The only module that performs I/O.

Request shapes follow databricks-sdk 0.140.0 and were checked against an Azure workspace on 1 October 2026; the
visibility self-check (effective permissions, SCIM Me) is re-checked in milestone 1a.
Exception text is never kept: SDK errors can include request details.
"""

from __future__ import annotations

from urllib.parse import quote

from reachdiff.config import Config
from reachdiff.scope import changed_objects, with_ancestors
from reachdiff.state import (
    BUILTIN_GROUPS,
    Gap,
    Grant,
    Membership,
    Principal,
    Securable,
    State,
    ancestors,
    kind_of,
    normalize_privilege,
)
from reachdiff.tfplan import Plan

UC = '/api/2.1/unity-catalog'
SCIM = '/api/2.0/preview/scim/v2'
PLURAL = {'catalog': 'catalogs', 'schema': 'schemas', 'table': 'tables'}
LOOKUPS = {
    'group': ('Groups', 'displayName'),
    'service_principal': ('ServicePrincipals', 'applicationId'),
    'user': ('Users', 'userName'),
}
MEMBER_KINDS = {
    'user': 'user',
    'users': 'user',
    'group': 'group',
    'groups': 'group',
    'serviceprincipal': 'service_principal',
    'serviceprincipals': 'service_principal',
}
SEES_ALL = frozenset({'READ_METADATA', 'MANAGE'})  # with ownership and metastore admin: see every grant
NEEDS = 'needs READ METADATA, MANAGE or ownership'
HIDDEN = f"only the caller's own grants are visible; {NEEDS}"


# The SDK raises ValueError when it cannot get a token, for example when a federation policy refuses the exchange.
LOGIN_ERRORS = ('Unauthenticated', 'ValueError')
LOGIN_HINT = (
    "Check DATABRICKS_AUTH_TYPE or the profile, the client ID and, with token federation, the policy's "
    'issuer, subject and audience'
)


class _ReadError(Exception):
    """A failed or malformed read. Carries only an exception type name."""


class _Reader:
    def __init__(self, client) -> None:
        self.client = client
        self.attempted = self.succeeded = 0
        self.first_failure: str | None = None

    def get(self, path: str, query: dict | None = None) -> dict:
        self.attempted += 1
        try:
            result = self.client.api_client.do('GET', path, query=query or {})
        except Exception as exc:
            if type(exc).__name__ in LOGIN_ERRORS:
                raise RuntimeError(
                    f'Databricks login failed ({type(exc).__name__} on GET {path}). {LOGIN_HINT}'
                ) from None
            self.first_failure = self.first_failure or f'{type(exc).__name__} on GET {path}'
            raise _ReadError(type(exc).__name__) from None
        if not isinstance(result, dict):
            self.first_failure = self.first_failure or f'InvalidResponse on GET {path}'
            raise _ReadError('InvalidResponse')
        self.succeeded += 1
        return result

    def pages(self, path: str, key: str, query: dict | None = None, *, max_results: bool = True) -> list:
        """Follow next_page_token until it is absent; an empty page does not end the listing."""
        items: list = []
        token, seen = None, set()
        while True:
            params = dict(query or {})
            if max_results:
                params['max_results'] = 0
            if token:
                params['page_token'] = token
            page = self.get(path, params)
            batch = page.get(key, [])
            if not isinstance(batch, list):
                raise _ReadError('InvalidResponse')
            items.extend(batch)
            token = page.get('next_page_token')
            if not token:
                return items
            if not isinstance(token, str) or token in seen:
                raise _ReadError('RepeatedPageToken')
            seen.add(token)


def _read_grants(reader: _Reader, name: str, gaps: list[Gap]) -> list[Grant] | None:
    path = f'{UC}/permissions/{kind_of(name)}/{quote(name, safe="")}'
    grants = []
    try:
        for item in reader.pages(path, 'privilege_assignments'):
            principal = item.get('principal') if isinstance(item, dict) else None
            privileges = item.get('privileges') if isinstance(item, dict) else None
            if (
                not isinstance(principal, str)
                or not isinstance(privileges, list)
                or not all(isinstance(p, str) and p.strip() for p in privileges)
            ):
                raise _ReadError('InvalidAssignment')
            if privileges:
                grants.append(Grant(principal, name, frozenset(map(normalize_privilege, privileges)), f'GET {path}'))
    except _ReadError as exc:
        gaps.append(Gap('unreadable_object', f'grants on {name} ({exc}); partial data discarded'))
        return None
    return grants


def _tags(reader: _Reader, entity_type: str, name: str, gaps: list[Gap]) -> set[str]:
    path = f'{UC}/entity-tag-assignments/{entity_type}/{quote(name, safe="")}/tags'
    try:
        items = reader.pages(path, 'tag_assignments', max_results=False)
    except _ReadError as exc:
        gaps.append(Gap('tags_unavailable', f'{name} ({exc})'))
        return set()
    return {i['tag_key'] for i in items if isinstance(i, dict) and isinstance(i.get('tag_key'), str)}


def _read_securable(reader: _Reader, name: str, column_tags: bool, gaps: list[Gap]) -> Securable:
    kind = kind_of(name)
    owner, columns = None, []
    try:
        detail = reader.get(f'{UC}/{PLURAL[kind]}/{quote(name, safe="")}')
        owner = detail['owner'] if isinstance(detail.get('owner'), str) else None
        columns = [
            c['name'] for c in detail.get('columns') or [] if isinstance(c, dict) and isinstance(c.get('name'), str)
        ]
    except _ReadError as exc:
        gaps.append(Gap('unreadable_object', f'owner of {name} ({exc})'))
    tags = _tags(reader, PLURAL[kind], name, gaps)
    if column_tags:
        for column in columns:
            tags |= _tags(reader, 'columns', f'{name}.{column}', gaps)
    return Securable(name, owner, frozenset(tags))


def _children(reader: _Reader, changed: set[str], limit: int, gaps: list[Gap]) -> set[str]:
    schemas: set[str] = set()
    for name in sorted(changed):
        if kind_of(name) == 'schema':
            schemas.add(name)
        elif kind_of(name) == 'catalog':
            try:
                listed = reader.pages(f'{UC}/schemas', 'schemas', {'catalog_name': name})
            except _ReadError as exc:
                gaps.append(Gap('unreadable_object', f'schemas in {name} ({exc})'))
                continue
            schemas |= {
                s['full_name'].lower() for s in listed if isinstance(s, dict) and isinstance(s.get('full_name'), str)
            }
    found = set(schemas)
    for schema in sorted(schemas):
        catalog, schema_name = schema.split('.')
        try:
            listed = reader.pages(f'{UC}/tables', 'tables', {'catalog_name': catalog, 'schema_name': schema_name})
        except _ReadError as exc:
            gaps.append(Gap('unreadable_object', f'tables in {schema} ({exc})'))
            continue
        found |= {t['full_name'].lower() for t in listed if isinstance(t, dict) and isinstance(t.get('full_name'), str)}
    if len(found) > limit:
        gaps.append(Gap('limit_reached', f'{len(found)} child objects under --deep; only the first {limit} were read'))
        found = set(sorted(found)[:limit])
    return found


def _check_since_plan(plan: Plan, live: dict[str, dict[str, frozenset[str]]], gaps: list[Gap]) -> None:
    for resource in plan.grants:
        if resource.before is None or resource.securable not in live:
            continue
        current = live[resource.securable]
        observed = current if resource.authoritative else {p: current.get(p, frozenset()) for p in resource.before}
        if observed != resource.before:
            gaps.append(
                Gap(
                    'changed_since_plan',
                    f"grants on {resource.securable} differ from the plan's refreshed state ({resource.address})",
                )
            )


def _lookup_name(reader: _Reader, name: str, gaps: list[Gap]) -> Principal | None:
    if '"' in name or '\\' in name:
        gaps.append(Gap('unresolved_name', f'{name} cannot be looked up safely'))
        return None
    kinds = ('user', 'group', 'service_principal') if '@' in name else ('group', 'service_principal', 'user')
    for kind in kinds:
        resource, attribute = LOOKUPS[kind]
        try:
            page = reader.get(f'{SCIM}/{resource}', {'filter': f'{attribute} eq "{name}"', 'attributes': 'id'})
        except _ReadError as exc:
            gaps.append(Gap('unresolved_name', f'{name} ({exc})'))
            return None
        ids = [r['id'] for r in page.get('Resources') or [] if isinstance(r, dict) and isinstance(r.get('id'), str)]
        if len(ids) > 1:
            gaps.append(Gap('unresolved_name', f'{name} matches more than one {kind}'))
            return None
        if ids:
            return Principal(name, kind, ids[0])
    gaps.append(Gap('unresolved_name', f'{name} was not found in workspace SCIM'))
    return None


def _lookup_id(reader: _Reader, scim_id: str, gaps: list[Gap]) -> Principal | None:
    refused = False
    for kind in ('user', 'service_principal', 'group'):
        resource, attribute = LOOKUPS[kind]
        try:
            record = reader.get(f'{SCIM}/{resource}/{quote(scim_id, safe="")}')
        except _ReadError as exc:
            refused = refused or str(exc) == 'PermissionDenied'
            continue
        if record.get('id') == scim_id and isinstance(record.get(attribute), str):
            return Principal(record[attribute], kind, scim_id)
    gaps.append(
        Gap(
            'unresolved_name',
            f'SCIM ID {scim_id} from the plan (lookup needs workspace admin)'
            if refused
            else f'SCIM ID {scim_id} from the plan was not found',
        )
    )
    return None


def _member_kind(member: dict) -> str:
    kind = member.get('type')
    if not isinstance(kind, str):
        parts = str(member.get('$ref', '')).rstrip('/').split('/')
        kind = parts[-2] if len(parts) >= 2 else ''
    return MEMBER_KINDS.get(kind.lower().replace('_', ''), 'unknown')


def _read_identities(
    reader: _Reader, plan: Plan, grants: list[Grant], limit: int, gaps: list[Gap]
) -> tuple[dict[str, Principal], list[Membership], set[str]]:
    names = {g.principal for g in grants}
    for resource in plan.changed_grants():
        names |= set(resource.before or {}) | set(resource.after or {})
    for resource in plan.changed_owners():
        names |= {x for x in (resource.before, resource.after) if x}
    principals: dict[str, Principal] = {}
    by_id: dict[str, Principal] = {}
    for name in sorted(names):
        found = Principal(name, 'group') if name in BUILTIN_GROUPS else _lookup_name(reader, name, gaps)
        if found:
            principals[name] = found
            if found.scim_id:
                by_id[found.scim_id] = found
    pending = [p.scim_id for p in principals.values() if p.kind == 'group' and p.scim_id]
    for edge in plan.changed_memberships():
        pending.append(edge.group_id)
        gaps.append(
            Gap(
                'membership_scope',
                f'{edge.address}: grants the group holds outside the objects this plan touches were not read',
            )
        )
        if edge.member_id not in by_id and (found := _lookup_id(reader, edge.member_id, gaps)):
            principals.setdefault(found.name, found)
            by_id[edge.member_id] = found
    memberships: list[Membership] = []
    unread: set[str] = set()
    expanded: set[str] = set()
    count = 0
    while pending:
        group_id = pending.pop(0)
        if group_id in expanded:
            continue
        expanded.add(group_id)
        path = f'{SCIM}/Groups/{quote(group_id, safe="")}'
        try:
            record = reader.get(path)
            name, members = record.get('displayName'), record.get('members', [])
            if record.get('id') != group_id or not isinstance(name, str) or not isinstance(members, list):
                raise _ReadError('InvalidGroup')
        except _ReadError as exc:
            if str(exc) == 'PermissionDenied':
                # Workspace SCIM shows members only to admins; every further group would be refused too.
                gaps.append(
                    Gap(
                        'membership_incomplete',
                        'group members not read: workspace SCIM shows members '
                        'only to workspace admins (PermissionDenied)',
                    )
                )
                unread |= {by_id[g].name for g in [group_id, *pending] if g in by_id}
                return principals, memberships, unread
            gaps.append(Gap('membership_incomplete', f'group {group_id} ({exc})'))
            if group_id in by_id:
                unread.add(by_id[group_id].name)
            continue
        group = by_id.get(group_id) or Principal(name, 'group', group_id)
        by_id[group_id] = group
        principals.setdefault(group.name, group)
        for member in members:
            member_id = member.get('value') if isinstance(member, dict) else None
            if not isinstance(member_id, str):
                gaps.append(Gap('membership_incomplete', f'malformed member entry in {group.name}'))
                continue
            count += 1
            if count > limit:
                gaps.append(Gap('limit_reached', f'group members beyond {limit} were not read'))
                return principals, memberships, unread
            known = by_id.get(member_id)
            if known is None:
                kind = _member_kind(member)
                display = member['display'] if isinstance(member.get('display'), str) else member_id
                known = Principal(display if kind == 'group' else f'{display} ({kind} {member_id})', kind, member_id)
                by_id[member_id] = known
                principals.setdefault(known.name, known)
            memberships.append(Membership(known.name, group.name, f'GET {path}: members.value={member_id}'))
            if known.kind == 'group':
                pending.append(member_id)
    return principals, memberships, unread


def _caller(reader: _Reader, gaps: list[Gap]) -> tuple[str, frozenset[str]] | None:
    """The caller's grant name (a service principal's application ID) and that name plus its direct groups."""
    try:
        me = reader.get(f'{SCIM}/Me')
    except _ReadError as exc:
        gaps.append(Gap('unreadable_object', f"the caller's identity (SCIM Me: {exc})"))
        return None
    user = me.get('userName')
    if not isinstance(user, str) or not user:
        gaps.append(Gap('unreadable_object', "the caller's identity (SCIM Me: InvalidResponse)"))
        return None
    groups = {g['display'] for g in me.get('groups') or [] if isinstance(g, dict) and isinstance(g.get('display'), str)}
    return user, frozenset({user} | groups)


def _metastore_admin(reader: _Reader, names: frozenset[str]) -> bool:
    try:
        return reader.get(f'{UC}/metastore_summary').get('owner') in names
    except _ReadError:
        return False


def _hidden(
    reader: _Reader, name: str, caller, admin: bool, securables: dict[str, Securable], cleared: set[str]
) -> str | None:
    """None when the caller sees every grant on the object; otherwise why not.

    Databricks shows other callers only their own grants, without an error. Objects are checked parents first, so a
    cleared parent clears its children (READ METADATA and MANAGE inherit; ownership covers children).
    """
    if caller is None:
        return 'the caller could not be identified, so the list may hold only its own grants'
    user, names = caller
    chain = ancestors(name)
    if (
        admin
        or any(n in cleared for n in chain[1:])
        or any(n in securables and securables[n].owner in names for n in chain)
    ):
        cleared.add(name)
        return None
    path = f'{UC}/effective-permissions/{kind_of(name)}/{quote(name, safe="")}'
    try:
        items = reader.pages(path, 'privilege_assignments', {'principal': user})
    except _ReadError as exc:
        if str(exc) == 'PermissionDenied':  # the caller cannot read the object at all
            return f'the caller cannot see this object (PermissionDenied); {NEEDS}'
        return f'visibility check failed ({exc})'
    held = {
        normalize_privilege(p['privilege'])
        for item in items
        if isinstance(item, dict)
        for p in item.get('privileges') or []
        if isinstance(p, dict) and isinstance(p.get('privilege'), str)
    }
    if held & SEES_ALL:
        cleared.add(name)
        return None
    return HIDDEN


def collect(plan: Plan, client, config: Config, *, deep: bool) -> State:
    host = str(client.config.host).rstrip('/')
    if plan.hosts and host not in plan.hosts:
        raise ValueError('the plan targets a different workspace host than the authenticated one')
    notes = () if plan.hosts else ('Target workspace is not stated in the plan.',)
    reader, gaps = _Reader(client), []
    changed = changed_objects(plan)
    base = sorted(with_ancestors(changed))  # always read: the object limit truncates only deep children
    children = sorted(_children(reader, changed, config.limit_deep_children, gaps) - set(base)) if deep else []
    dropped = min(len(children), max(len(base) + len(children) - config.limit_objects, 0))
    if dropped:
        gaps.append(
            Gap(
                'limit_reached',
                f'{len(base) + len(children)} objects in scope; {dropped} child objects '
                f'under --deep were not read (limit {config.limit_objects})',
            )
        )
        children = children[: len(children) - dropped]
    names = base + children
    caller = _caller(reader, gaps)
    admin = caller is not None and _metastore_admin(reader, caller[1])
    securables, grants, live, cleared = {}, [], {}, set()
    for name in names:  # parents first: names are sorted, and a name sorts before its children
        securables[name] = _read_securable(reader, name, name in changed and kind_of(name) == 'table', gaps)
        reason = _hidden(reader, name, caller, admin, securables, cleared)
        if reason:
            gaps.append(Gap('unreadable_object', f'grants on {name} ({reason}); partial data discarded'))
            continue
        object_grants = _read_grants(reader, name, gaps)
        if object_grants is not None:
            grants += object_grants
            held = live.setdefault(name, {})
            for grant in object_grants:
                held[grant.principal] = held.get(grant.principal, frozenset()) | grant.privileges
    _check_since_plan(plan, live, gaps)
    principals, memberships, unread = _read_identities(reader, plan, grants, config.limit_members, gaps)
    if reader.attempted and not reader.succeeded:
        raise RuntimeError(
            f'no Databricks read succeeded; first failure: {reader.first_failure}. Check the '
            'workspace entitlement (e.g. workspace-consume) and the READ METADATA grant of the '
            'identity reachdiff runs as'
        )
    return State(
        'live',
        principals,
        securables,
        tuple(grants),
        tuple(memberships),
        tuple(sorted(set(gaps))),
        notes,
        unread_groups=frozenset(unread),
    )


def collect_live(plan: Plan, config: Config, *, deep: bool, profile: str | None = None) -> State:
    try:
        from databricks.sdk import WorkspaceClient
    except ImportError:
        raise RuntimeError(
            'live mode needs the Databricks SDK: pip install "reachdiff[databricks]", or pass --offline'
        ) from None
    try:
        client = WorkspaceClient(profile=profile) if profile else WorkspaceClient()
    except Exception as exc:
        raise RuntimeError(f'Databricks login failed ({type(exc).__name__}). {LOGIN_HINT}') from None
    return collect(plan, client, config, deep=deep)
