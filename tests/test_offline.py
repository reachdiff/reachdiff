import unittest

from reachdiff.collect.offline import build_offline
from reachdiff.scope import changed_objects, has_access_changes, with_ancestors
from reachdiff.state import Grant
from reachdiff.tfplan import read_plan
from tests.plans import grants, identity, member, owner, plan


def demo():
    return read_plan(
        plan(
            grants(
                'databricks_grants.prod', 'prod', {'account users': 'USE_CATALOG'}, {'account users': 'USE_CATALOG'}
            ),
            grants(
                'databricks_grants.sales',
                'prod.sales',
                {'finance': 'USE_SCHEMA SELECT'},
                {'finance': 'USE_SCHEMA SELECT', 'analysts': 'USE_SCHEMA SELECT'},
            ),
            grants('databricks_grants.new', 'prod.new', None, {'analysts': 'USE_SCHEMA'}),
            member('databricks_group_member.bob', '101', '202', True, True),
            member('databricks_group_member.ghost', '101', '999', True, True),
            owner('databricks_schema.sales', 'prod.sales', 'data-eng', 'data-eng'),
            identity('databricks_group.analysts', 'databricks_group', '101', 'analysts'),
            identity('databricks_user.bob', 'databricks_user', '202', 'bob@example.com'),
        )
    )


class ScopeTests(unittest.TestCase):
    def test_changed_objects_and_ancestors(self):
        p = demo()
        self.assertEqual(changed_objects(p), {'prod.sales', 'prod.new'})
        self.assertEqual(with_ancestors({'prod.sales.orders'}), {'prod', 'prod.sales', 'prod.sales.orders'})
        self.assertTrue(has_access_changes(p))
        self.assertFalse(
            has_access_changes(
                read_plan(plan(grants('databricks_grants.prod', 'prod', {'x': 'USE_CATALOG'}, {'x': 'USE_CATALOG'})))
            )
        )


class OfflineTests(unittest.TestCase):
    def test_current_state_comes_from_plan_before_values_only(self):
        s = build_offline(demo())
        self.assertEqual(s.source, 'offline')
        self.assertIn(Grant('finance', 'prod.sales', frozenset({'USE_SCHEMA', 'SELECT'}), ''), s.grants)
        self.assertFalse(any(g.principal == 'analysts' for g in s.grants))
        self.assertTrue(all(g.evidence.startswith('plan before:') for g in s.grants))
        self.assertEqual([(m.member, m.group) for m in s.memberships], [('bob@example.com', 'analysts')])
        self.assertEqual(s.securables['prod.sales'].owner, 'data-eng')
        self.assertEqual(s.principals['analysts'].kind, 'group')
        categories = {g.category for g in s.gaps}
        self.assertIn('offline_blind_spot', categories)
        self.assertIn('unresolved_name', categories)
