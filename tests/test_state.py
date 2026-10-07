import unittest

from reachdiff.state import Grant, ancestors, kind_of, normalize_privilege, parent_of
from tests.states import state


class StateTests(unittest.TestCase):
    def test_names_define_kind_and_parents(self):
        self.assertEqual(kind_of('prod'), 'catalog')
        self.assertEqual(kind_of('prod.sales'), 'schema')
        self.assertEqual(kind_of('prod.sales.orders'), 'table')
        self.assertEqual(parent_of('prod.sales.orders'), 'prod.sales')
        self.assertIsNone(parent_of('prod'))
        self.assertEqual(ancestors('prod.sales.orders'), ('prod.sales.orders', 'prod.sales', 'prod'))
        for bad in ('', 'a..b', 'a.b.c.d'):
            with self.assertRaises(ValueError):
                kind_of(bad)

    def test_privileges_are_normalized(self):
        self.assertEqual(normalize_privilege(' use catalog '), 'USE_CATALOG')
        self.assertEqual(normalize_privilege('ALL PRIVILEGES'), 'ALL_PRIVILEGES')

    def test_grant_equality_ignores_evidence(self):
        a = Grant('analysts', 'prod', frozenset({'USE_CATALOG'}), 'GET /x')
        b = Grant('analysts', 'prod', frozenset({'USE_CATALOG'}), 'plan after: y')
        self.assertEqual(a, b)

    def test_principal_kind_falls_back_to_memberships_and_email(self):
        s = state(members=[('alice@example.com', 'analysts')], principals=[('sp-1', 'service_principal')])
        self.assertEqual(s.kind('sp-1'), 'service_principal')
        self.assertEqual(s.kind('analysts'), 'group')
        self.assertEqual(s.kind('account users'), 'group')
        self.assertEqual(s.kind('bob@example.com'), 'user')
        self.assertEqual(s.kind('0f3c-app-id'), 'unknown')
