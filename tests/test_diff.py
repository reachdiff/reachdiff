import unittest

from reachdiff.apply import apply_plan
from reachdiff.collect.offline import build_offline
from reachdiff.diff import compute_diff, members_of
from reachdiff.tfplan import read_plan
from tests.plans import grant, grants, identity, member, moved, owner, plan
from tests.states import state

BASE = [
    grants('databricks_grants.prod', 'prod', {'account users': 'USE_CATALOG'}, {'account users': 'USE_CATALOG'}),
    identity('databricks_group.analysts', 'databricks_group', '101', 'analysts'),
    identity('databricks_group.finance', 'databricks_group', '102', 'finance'),
    identity('databricks_user.alice', 'databricks_user', '201', 'alice@example.com'),
    identity('databricks_user.bob', 'databricks_user', '202', 'bob@example.com'),
    identity('databricks_user.carol', 'databricks_user', '203', 'carol@example.com'),
    member('databricks_group_member.a1', '101', '201', True, True),
    member('databricks_group_member.a2', '101', '202', True, True),
    member('databricks_group_member.a3', '101', '203', True, True),
    member('databricks_group_member.f2', '102', '202', True, True),
]
FINANCE = grants(
    'databricks_grants.sales', 'prod.sales', {'finance': 'USE_SCHEMA SELECT'}, {'finance': 'USE_SCHEMA SELECT'}
)


def run(*resources, deep=False, limit=5000, base=BASE):
    p = read_plan(plan(*base, *resources))
    before = build_offline(p)
    return compute_diff(before, apply_plan(before, p), p, members_limit=limit, deep=deep)


def rows(diff):
    return [(r.direction, r.principal, r.level, r.securable) for r in diff.rows]


class DiffTests(unittest.TestCase):
    def test_group_gain_counts_members_who_already_had_it(self):
        d = run(
            grants(
                'databricks_grants.sales',
                'prod.sales',
                {'finance': 'USE_SCHEMA SELECT'},
                {'finance': 'USE_SCHEMA SELECT', 'analysts': 'USE_SCHEMA SELECT'},
            )
        )
        self.assertEqual(rows(d), [('+', 'analysts', 'READ', 'prod.sales')])
        m = d.rows[0].members
        self.assertEqual((m.total, m.changed, m.unchanged), (3, 2, 1))
        self.assertEqual(m.names, ('alice@example.com', 'carol@example.com'))
        self.assertIn(('bob@example.com', 'READ', 'prod.sales'), [rc[0] for rc in d.route_changes])

    def test_table_grant_covered_by_parent_is_no_change(self):
        d = run(FINANCE, grants('databricks_grants.orders', 'prod.sales.orders', None, {'bob@example.com': 'SELECT'}))
        self.assertEqual(rows(d), [])
        self.assertEqual(d.gained, frozenset())

    def test_membership_gain_is_an_individual_row(self):
        d = run(FINANCE, member('databricks_group_member.f1', '102', '201', False, True))
        self.assertEqual(rows(d), [('+', 'alice@example.com', 'READ', 'prod.sales')])
        self.assertEqual(d.rows[0].routes[0].main.chain, ('finance',))

    def test_lost_write(self):
        d = run(
            grants('databricks_grants.sales', 'prod.sales', {'finance': 'USE_SCHEMA'}, {'finance': 'USE_SCHEMA'}),
            grant('databricks_grant.bob', 'prod.sales.orders', 'bob@example.com', 'SELECT MODIFY', 'SELECT'),
        )
        self.assertEqual(rows(d), [('-', 'bob@example.com', 'WRITE', 'prod.sales.orders')])

    def test_child_rows_collapse_under_parent_rows(self):
        d = run(
            grants('databricks_grants.sales', 'prod.sales', None, {'analysts': 'USE_SCHEMA SELECT'}),
            grants('databricks_grants.orders', 'prod.sales.orders', None, {'analysts': 'SELECT'}),
        )
        self.assertEqual(rows(d), [('+', 'analysts', 'READ', 'prod.sales')])

    def test_new_usage_grant_is_a_gap_unless_deep(self):
        resources = (
            grants('databricks_grants.orders', 'prod.sales.orders', {'analysts': 'SELECT'}, {'analysts': 'SELECT'}),
            grants('databricks_grants.sales', 'prod.sales', None, {'analysts': 'USE_SCHEMA'}),
        )
        shallow = run(*resources)
        self.assertEqual(rows(shallow), [])
        self.assertIn('latent_grants', {g.category for g in shallow.gaps})
        deep = run(*resources, deep=True)
        self.assertEqual(rows(deep), [('+', 'analysts', 'READ', 'prod.sales.orders')])
        self.assertNotIn('latent_grants', {g.category for g in deep.gaps})

    def test_usage_gaps_follow_the_live_grants_a_create_replaces(self):
        p = read_plan(
            plan(
                grants(
                    'databricks_grants.sales',
                    'prod.sales',
                    None,
                    {'finance': 'USE_SCHEMA SELECT', 'analysts': 'USE_SCHEMA SELECT'},
                )
            )
        )
        before = state(
            [('finance', 'prod.sales', 'USE_SCHEMA SELECT'), ('etl', 'prod.sales', 'USE_SCHEMA')], source='live'
        )
        gaps = {
            (g.category, g.detail.split(' on ')[0])
            for g in compute_diff(before, apply_plan(before, p), p, members_limit=5000, deep=False).gaps
        }
        self.assertEqual(
            gaps, {('latent_grants', 'analysts gains USE_SCHEMA'), ('deactivated_grants', 'etl loses USE_SCHEMA')}
        )

    def test_member_limit_stops_expansion_visibly(self):
        d = run(
            grants(
                'databricks_grants.sales',
                'prod.sales',
                {'finance': 'USE_SCHEMA SELECT'},
                {'finance': 'USE_SCHEMA SELECT', 'analysts': 'USE_SCHEMA SELECT'},
            ),
            limit=1,
        )
        self.assertIn('limit_reached', {g.category for g in d.gaps})
        self.assertFalse(d.rows[0].members.expanded)

    def test_member_limit_is_decided_once_with_one_gap(self):
        add_analysts = grants(
            'databricks_grants.sales',
            'prod.sales',
            {'finance': 'USE_SCHEMA SELECT'},
            {'finance': 'USE_SCHEMA SELECT', 'analysts': 'USE_SCHEMA SELECT'},
        )
        d = run(add_analysts, limit=3)  # finance fits, analysts does not; its 3 members alone would
        self.assertEqual(rows(d), [('+', 'analysts', 'READ', 'prod.sales')])
        self.assertFalse(d.rows[0].members.expanded)
        both = run(add_analysts, limit=1)
        self.assertEqual(
            [g.detail for g in both.gaps if g.category == 'limit_reached'],
            ['members of analysts, finance were not expanded beyond 1'],
        )

    def test_deep_evaluates_holders_whose_grants_a_usage_change_activates_or_deactivates(self):
        grant_usage = grants('databricks_grants.prod', 'prod', None, {'account users': 'USE_CATALOG'})
        self.assertEqual(
            rows(run(FINANCE, grant_usage, deep=True, base=BASE[1:])), [('+', 'finance', 'READ', 'prod.sales')]
        )
        revoke_usage = grants('databricks_grants.prod', 'prod', {'account users': 'USE_CATALOG'}, None)
        self.assertEqual(
            rows(run(FINANCE, revoke_usage, deep=True, base=BASE[1:])), [('-', 'finance', 'READ', 'prod.sales')]
        )

    def test_members_of_is_transitive_and_cycle_safe(self):
        s = state(members=[('alice@example.com', 'a'), ('b', 'a'), ('bob@example.com', 'b'), ('a', 'b')])
        self.assertEqual(members_of(s, 'a'), {'alice@example.com', 'b', 'bob@example.com'})
        self.assertEqual(members_of(s, 'account users'), set())

    def test_nested_group_rows_keep_member_counts_when_the_parent_is_expanded(self):
        interns = (
            identity('databricks_group.interns', 'databricks_group', '103', 'interns'),
            identity('databricks_user.dave', 'databricks_user', '204', 'dave@example.com'),
            member('databricks_group_member.i1', '101', '103', True, True),
            member('databricks_group_member.i2', '103', '204', True, True),
        )
        d = run(*interns, grants('databricks_grants.sales', 'prod.sales', None, {'analysts': 'USE_SCHEMA SELECT'}))
        self.assertEqual(
            {r.principal: (r.members.total, r.members.changed) for r in d.rows}, {'analysts': (4, 4), 'interns': (1, 1)}
        )

    def test_a_member_with_a_route_outside_the_group_row_gets_their_own_row(self):
        d = run(
            grants(
                'databricks_grants.sales',
                'prod.sales',
                None,
                {'analysts': 'USE_SCHEMA SELECT', 'alice@example.com': 'SELECT'},
            )
        )
        self.assertEqual(
            rows(d), [('+', 'alice@example.com', 'READ', 'prod.sales'), ('+', 'analysts', 'READ', 'prod.sales')]
        )
        self.assertEqual({r.main.chain for r in d.rows[0].routes}, {(), ('analysts',)})
        self.assertEqual(d.rows[1].members.changed, 3)

    def test_an_ownership_transfer_moves_read_and_write_with_it(self):
        usage = grants(
            'databricks_grants.sales', 'prod.sales', {'account users': 'USE_SCHEMA'}, {'account users': 'USE_SCHEMA'}
        )
        d = run(
            usage, owner('databricks_sql_table.orders', 'prod.sales.orders', 'alice@example.com', 'carol@example.com')
        )
        self.assertEqual(
            rows(d),
            [
                ('+', 'carol@example.com', 'MANAGE', 'prod.sales.orders'),
                ('+', 'carol@example.com', 'READ', 'prod.sales.orders'),
                ('+', 'carol@example.com', 'WRITE', 'prod.sales.orders'),
                ('-', 'alice@example.com', 'MANAGE', 'prod.sales.orders'),
                ('-', 'alice@example.com', 'READ', 'prod.sales.orders'),
                ('-', 'alice@example.com', 'WRITE', 'prod.sales.orders'),
            ],
        )

    def test_a_change_of_name_case_only_is_no_change(self):
        d = run(moved('databricks_grants.sales', 'prod.sales', 'prod.Sales', {'finance': 'USE_SCHEMA SELECT'}))
        self.assertEqual((rows(d), d.route_changes), ([], ()))
        self.assertNotIn('conflicting_grant_resources', {g.category for g in d.gaps})
