"""Build small State objects for pure-logic tests."""

from reachdiff.state import Grant, Membership, Principal, Securable, State


def state(grants=(), members=(), principals=(), owners=None, tags=None, source='offline', gaps=()):
    """grants: (principal, securable, 'PRIV PRIV'); members: (member, group); principals: (name, kind)."""
    securables = {}
    for _, securable, _ in grants:
        securables.setdefault(securable, Securable(securable))
    for name, owner in (owners or {}).items():
        securables[name] = Securable(name, owner, securables.get(name, Securable(name)).tags)
    for name, keys in (tags or {}).items():
        securables[name] = Securable(name, securables.get(name, Securable(name)).owner, frozenset(keys))
    return State(
        source,
        {n: Principal(n, k) for n, k in principals},
        securables,
        tuple(Grant(p, s, frozenset(v.split()), 'test') for p, s, v in grants),
        tuple(Membership(m, g, 'test') for m, g in members),
        tuple(gaps),
    )
