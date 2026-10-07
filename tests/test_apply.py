import unittest

from reachdiff.apply import apply_plan
from reachdiff.collect.offline import build_offline
from reachdiff.tfplan import read_plan
from tests.plans import grant, grants, identity, member, owner, plan


def applied(*resources):
    p = read_plan(plan(*resources))
    return apply_plan(build_offline(p), p)


def held(state, securable):
    return {g.principal: g.privileges for g in state.grants if g.securable == securable}


class ApplyTests(unittest.TestCase):
    def test_authoritative_grants_replace_every_principal(self):
        s = applied(
            grants(
                'databricks_grants.sales',
                'prod.sales',
                {'finance': 'SELECT', 'bob@example.com': 'SELECT'},
                {'analysts': 'SELECT'},
            )
        )
        self.assertEqual(held(s, 'prod.sales'), {'analysts': frozenset({'SELECT'})})
        self.assertTrue(all(g.evidence == 'plan after: databricks_grants.sales' for g in s.grants))

    def test_principal_grant_changes_only_its_principal(self):
        s = applied(
            grants('databricks_grants.sales', 'prod.sales', {'finance': 'SELECT'}, {'finance': 'SELECT'}),
            grant('databricks_grant.bob', 'prod.sales', 'bob@example.com', 'SELECT MODIFY', 'SELECT'),
        )
        self.assertEqual(
            held(s, 'prod.sales'), {'finance': frozenset({'SELECT'}), 'bob@example.com': frozenset({'SELECT'})}
        )

    def test_mixed_grant_resources_on_one_securable_apply_in_a_fixed_order_and_are_a_gap(self):
        both = (
            grants(
                'databricks_grants.sales',
                'prod.sales',
                {'finance': 'SELECT'},
                {'finance': 'SELECT', 'analysts': 'SELECT'},
            ),
            grant('databricks_grant.bob', 'prod.sales', 'bob@example.com', None, 'SELECT'),
        )
        select = frozenset({'SELECT'})
        expected = {'finance': select, 'analysts': select, 'bob@example.com': select}
        self.assertEqual(held(applied(*both), 'prod.sales'), expected)
        self.assertEqual(held(applied(*both[::-1]), 'prod.sales'), expected)
        self.assertIn('conflicting_grant_resources', {g.category for g in read_plan(plan(*both)).gaps})

    def test_deleted_principal_grant_removes_it(self):
        s = applied(grant('databricks_grant.bob', 'prod.sales', 'bob@example.com', 'SELECT', None))
        self.assertEqual(held(s, 'prod.sales'), {})

    def test_memberships_and_owners(self):
        s = applied(
            member('databricks_group_member.alice', '101', '201', False, True),
            member('databricks_group_member.bob', '101', '202', True, False),
            member('databricks_group_member.ghost', '101', '999', False, True),
            owner('databricks_schema.sales', 'prod.sales', 'data-eng', 'alice@example.com'),
            identity('databricks_group.analysts', 'databricks_group', '101', 'analysts'),
            identity('databricks_user.alice', 'databricks_user', '201', 'alice@example.com'),
            identity('databricks_user.bob', 'databricks_user', '202', 'bob@example.com'),
        )
        self.assertEqual([(m.member, m.group) for m in s.memberships], [('alice@example.com', 'analysts')])
        self.assertEqual(s.securables['prod.sales'].owner, 'alice@example.com')
        self.assertIn('unresolved_name', {g.category for g in s.gaps})
