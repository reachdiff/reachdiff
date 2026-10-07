"""Which objects a plan touches."""

from __future__ import annotations

from collections.abc import Iterable

from reachdiff.state import ancestors
from reachdiff.tfplan import Plan


def changed_objects(plan: Plan) -> set[str]:
    names = {g.securable for g in plan.changed_grants()}
    return names | {o.securable for o in plan.changed_owners()}


def with_ancestors(names: Iterable[str]) -> set[str]:
    return {a for name in names for a in ancestors(name)}


def has_access_changes(plan: Plan) -> bool:
    return bool(changed_objects(plan)) or bool(plan.changed_memberships())
