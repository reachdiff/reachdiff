"""Apply a plan's changes to a state using Terraform provider semantics."""

from __future__ import annotations

from dataclasses import replace

from reachdiff.state import Gap, Grant, Membership, Securable, State
from reachdiff.tfplan import Plan


def apply_plan(state: State, plan: Plan) -> State:
    grants = list(state.grants)
    # Authoritative resources first, then principal resources, so the result does not depend on list order.
    for resource in sorted(plan.changed_grants(), key=lambda r: not r.authoritative):
        target = resource.after or {}
        if resource.authoritative:
            grants = [g for g in grants if g.securable != resource.securable]
        else:
            names = set(target) | set(resource.before or {})
            grants = [g for g in grants if not (g.securable == resource.securable and g.principal in names)]
        for principal, privileges in sorted(target.items()):
            grants.append(Grant(principal, resource.securable, privileges, f'plan after: {resource.address}'))

    ids = {p.scim_id: p for p in state.principals.values() if p.scim_id}
    ids.update(plan.identities)
    principals = dict(state.principals)
    gaps = list(state.gaps)
    memberships = list(state.memberships)
    for edge in plan.changed_memberships():
        group, member = ids.get(edge.group_id), ids.get(edge.member_id)
        if group is None or member is None:
            gaps.append(Gap('unresolved_name', f'{edge.address}: SCIM IDs could not be named'))
            continue
        principals.setdefault(group.name, group)
        principals.setdefault(member.name, member)
        link = Membership(member.name, group.name, f'plan after: {edge.address}')
        memberships = [m for m in memberships if m != link]
        if edge.after:
            memberships.append(link)

    securables = dict(state.securables)
    for resource in plan.changed_owners():
        current = securables.get(resource.securable, Securable(resource.securable))
        securables[resource.securable] = replace(current, owner=resource.after)
    return replace(
        state,
        principals=principals,
        securables=securables,
        grants=tuple(grants),
        memberships=tuple(memberships),
        gaps=tuple(sorted(set(gaps))),
    )
