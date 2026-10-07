import unittest

from reachdiff.resolve import groups_of, resolve
from tests.states import state

USE = [('account users', 'prod', 'USE_CATALOG'), ('account users', 'prod.sales', 'USE_SCHEMA')]


class ResolveTests(unittest.TestCase):
    def test_read_needs_select_and_both_usage_privileges(self):
        s = state([('bob@example.com', 'prod.sales.orders', 'SELECT'), ('account users', 'prod', 'USE_CATALOG')])
        self.assertEqual(resolve(s, ['bob@example.com'], ['prod.sales.orders']), {})
        s = state(USE + [('bob@example.com', 'prod.sales.orders', 'SELECT')])
        entries = resolve(s, ['bob@example.com'], ['prod.sales.orders'])
        self.assertEqual(set(entries), {('bob@example.com', 'READ', 'prod.sales.orders')})
        route = entries[('bob@example.com', 'READ', 'prod.sales.orders')][0]
        self.assertEqual((route.main.privilege, route.main.chain), ('SELECT', ()))
        self.assertEqual([h.privilege for h in route.prerequisites], ['USE_CATALOG', 'USE_SCHEMA'])

    def test_catalog_grants_inherit_to_children(self):
        s = state([('analysts', 'prod', 'USE_CATALOG USE_SCHEMA SELECT')], members=[('alice@example.com', 'analysts')])
        entries = resolve(s, ['alice@example.com'], ['prod', 'prod.sales', 'prod.sales.orders'])
        self.assertEqual({e[2] for e in entries if e[1] == 'READ'}, {'prod', 'prod.sales', 'prod.sales.orders'})
        self.assertEqual(entries[('alice@example.com', 'READ', 'prod.sales')][0].main.chain, ('analysts',))

    def test_write_requires_read_and_all_privileges_excludes_manage(self):
        s = state(USE + [('bob@example.com', 'prod.sales.orders', 'MODIFY')])
        self.assertEqual(resolve(s, ['bob@example.com'], ['prod.sales.orders']), {})
        s = state(USE + [('bob@example.com', 'prod.sales.orders', 'ALL_PRIVILEGES')])
        self.assertEqual({e[1] for e in resolve(s, ['bob@example.com'], ['prod.sales.orders'])}, {'READ', 'WRITE'})

    def test_manage_from_privilege_or_ownership_of_a_parent(self):
        s = state([('ops', 'prod.sales', 'MANAGE')], owners={'prod': 'carol@example.com'})
        self.assertIn(('ops', 'MANAGE', 'prod.sales.orders'), resolve(s, ['ops'], ['prod.sales.orders']))
        owned = resolve(s, ['carol@example.com'], ['prod.sales.orders'])
        self.assertEqual(owned[('carol@example.com', 'MANAGE', 'prod.sales.orders')][0].main.privilege, 'OWNER')

    def test_memberships_are_transitive_cycle_safe_and_include_account_users(self):
        s = state(members=[('alice@example.com', 'a'), ('a', 'b'), ('b', 'a')])
        self.assertEqual(
            groups_of(s, 'alice@example.com'),
            {'alice@example.com': (), 'account users': ('account users',), 'a': ('a',), 'b': ('a', 'b')},
        )
        self.assertEqual(groups_of(s, 'account users'), {'account users': ()})

    def test_owners_hold_all_privileges_on_the_object_and_its_children(self):
        s = state([], owners={'prod.sales.orders': 'carol@example.com'})
        self.assertEqual(
            set(resolve(s, ['carol@example.com'], ['prod.sales.orders'])),
            {('carol@example.com', 'MANAGE', 'prod.sales.orders')},
        )
        s = state(USE, owners={'prod.sales.orders': 'carol@example.com'})
        self.assertEqual(
            {e[1] for e in resolve(s, ['carol@example.com'], ['prod.sales.orders'])}, {'READ', 'WRITE', 'MANAGE'}
        )
        s = state([], owners={'prod': 'dana@example.com'})
        entries = resolve(s, ['dana@example.com'], ['prod.sales.orders'])
        self.assertEqual({e[1] for e in entries}, {'READ', 'WRITE', 'MANAGE'})
        route = entries[('dana@example.com', 'READ', 'prod.sales.orders')][0]
        self.assertEqual((route.main.privilege, route.main.securable), ('OWNER', 'prod'))
