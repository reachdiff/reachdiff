"""Current state from plan data only. Everything outside Terraform's view is a gap."""

from __future__ import annotations

from reachdiff.scope import with_ancestors
from reachdiff.state import Gap, Grant, Membership, Securable, State
from reachdiff.tfplan import Plan


def build_offline(plan: Plan) -> State:
    gaps = list(plan.gaps) + [
        Gap('offline_blind_spot', 'grants, memberships and tags not managed by this plan were not read (offline mode)')
    ]
    grants = []
    for resource in plan.grants:
        for principal, privileges in sorted((resource.before or {}).items()):
            grants.append(Grant(principal, resource.securable, privileges, f'plan before: {resource.address}'))
    memberships = []
    for edge in plan.memberships:
        if not edge.before:
            continue
        group, member = plan.identities.get(edge.group_id), plan.identities.get(edge.member_id)
        if group is None or member is None:
            gaps.append(Gap('unresolved_name', f'{edge.address}: SCIM IDs are not named in the plan'))
            continue
        memberships.append(Membership(member.name, group.name, f'plan before: {edge.address}'))
    names = with_ancestors([g.securable for g in plan.grants] + [o.securable for o in plan.owners])
    securables = {name: Securable(name) for name in sorted(names)}
    for resource in plan.owners:
        securables[resource.securable] = Securable(resource.securable, resource.before)
    principals = {p.name: p for p in plan.identities.values()}
    return State('offline', principals, securables, tuple(grants), tuple(memberships), tuple(sorted(set(gaps))))
