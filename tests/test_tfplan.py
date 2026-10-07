import unittest

from reachdiff.tfplan import read_plan
from tests.plans import grant, grants, identity, member, moved, owner, plan, secret


class PlanReaderTests(unittest.TestCase):
    def test_a_grant_resource_moved_to_another_securable_is_two_changes(self):
        p = read_plan(
            plan(moved('databricks_grants.x', 'prod.sales.orders', 'prod.hr.salaries', {'finance': 'SELECT'}))
        )
        select = {'finance': frozenset({'SELECT'})}
        self.assertEqual(
            [(g.securable, g.before, g.after) for g in p.changed_grants()],
            [('prod.sales.orders', select, None), ('prod.hr.salaries', None, select)],
        )
        to_volume = read_plan(
            plan(
                moved(
                    'databricks_grants.x',
                    'prod.sales.orders',
                    'prod.sales.files',
                    {'finance': 'SELECT'},
                    new_attr='volume',
                )
            )
        )
        self.assertEqual(
            [(g.securable, g.before, g.after) for g in to_volume.grants], [('prod.sales.orders', select, None)]
        )
        self.assertEqual(to_volume.not_evaluated, ('databricks_grants.x: grants on a volume',))

    def test_authoritative_and_principal_grants(self):
        p = read_plan(
            plan(
                grants(
                    'databricks_grants.sales',
                    'prod.sales',
                    {'finance': 'USE_SCHEMA SELECT'},
                    {'finance': 'USE_SCHEMA SELECT', 'analysts': 'use_schema select'},
                ),
                grant('databricks_grant.bob', 'prod', 'bob@example.com', None, 'USE_CATALOG'),
            )
        )
        sales, bob = sorted(p.grants, key=lambda g: g.address)[::-1]
        self.assertTrue(sales.authoritative)
        self.assertEqual(sales.after['analysts'], frozenset({'USE_SCHEMA', 'SELECT'}))
        self.assertFalse(bob.authoritative)
        self.assertIsNone(bob.before)
        self.assertEqual(len(p.changed_grants()), 2)

    def test_memberships_owners_and_identities(self):
        p = read_plan(
            plan(
                member('databricks_group_member.a', '101', '201', False, True),
                owner('databricks_schema.sales', 'prod.sales', 'data-eng', 'alice@example.com'),
                identity('databricks_group.analysts', 'databricks_group', '101', 'analysts'),
                prior=[
                    {
                        'address': 'data.databricks_user.alice',
                        'mode': 'data',
                        'type': 'databricks_user',
                        'name': 'alice',
                        'values': {'id': '201', 'user_name': 'alice@example.com'},
                    }
                ],
            )
        )
        self.assertEqual(p.changed_memberships()[0].group_id, '101')
        self.assertEqual(p.changed_owners()[0].after, 'alice@example.com')
        self.assertEqual(p.identities['101'].name, 'analysts')
        self.assertEqual(p.identities['201'].kind, 'user')

    def test_unknown_after_apply_keeps_before_and_records_gap(self):
        p = read_plan(
            plan(
                grants(
                    'databricks_grants.sales',
                    'prod.sales',
                    {'finance': 'SELECT'},
                    {'finance': 'SELECT'},
                    after_unknown={'grant': [{'principal': True}]},
                )
            )
        )
        self.assertEqual(p.grants[0].after, p.grants[0].before)
        self.assertEqual([g.category for g in p.gaps], ['unknown_after_apply'])

    def test_sensitive_relevant_value_is_skipped(self):
        p = read_plan(
            plan(
                grants(
                    'databricks_grants.sales',
                    'prod.sales',
                    None,
                    {'finance': 'SELECT'},
                    after_sensitive={'grant': True},
                )
            )
        )
        self.assertEqual(p.grants, ())
        self.assertEqual([g.category for g in p.gaps], ['sensitive_value'])

    def test_other_securables_and_unmodeled_privileges_are_not_evaluated(self):
        p = read_plan(
            plan(
                grants('databricks_grants.vol', 'prod.sales.files', None, {'eng': 'READ_VOLUME'}, attr='volume'),
                grants('databricks_grants.sales', 'prod.sales', None, {'eng': 'SELECT CREATE_TABLE'}),
            )
        )
        self.assertEqual(len(p.not_evaluated), 2)
        self.assertTrue(any('volume' in x for x in p.not_evaluated))
        self.assertTrue(any('CREATE_TABLE' in x for x in p.not_evaluated))
        self.assertEqual([g.securable for g in p.grants], ['prod.sales'])

    def test_secrets_in_unrelated_resources_are_never_read(self):
        p = read_plan(
            plan(
                secret('databricks_secret.token', 's3cr3t-value-123'),
                grants('databricks_grants.p', 'prod', None, {'finance': 'USE_CATALOG'}),
            )
        )
        self.assertNotIn('s3cr3t-value-123', repr(p))

    def test_hosts_providers_and_fixture_label(self):
        p = read_plan(plan(host='https://ws.example.net/', synthetic=True))
        self.assertEqual(p.hosts, ('https://ws.example.net',))
        self.assertTrue(p.synthetic)
        two = read_plan(
            plan(
                providers={
                    'databricks': {'name': 'databricks', 'expressions': {}},
                    'databricks.ws2': {'name': 'databricks', 'expressions': {}},
                    'databricks.account': {
                        'name': 'databricks',
                        'expressions': {'account_id': {'constant_value': 'x'}},
                    },
                }
            )
        )
        self.assertEqual([g.category for g in two.gaps], ['multiple_workspace_providers'])

    def test_rejects_unsupported_input(self):
        for raw in ([], {'format_version': '2.0'}, {'format_version': '1.2', 'resource_changes': {}}):
            with self.assertRaises(ValueError):
                read_plan(raw)
        for providers in (
            {'databricks': 'x'},
            {'databricks': {'name': 'databricks', 'expressions': []}},
            {'databricks': {'name': 'databricks', 'expressions': {'host': 'https://ws'}}},
        ):
            with self.assertRaises(ValueError):
                read_plan(plan(providers=providers))

    def test_invalid_securable_names_are_reported_by_address_only(self):
        with self.assertRaises(ValueError) as caught:
            read_plan(
                plan(grants('databricks_grants.bad', 'prod.sales.tbl.extra', None, {'eng': 'SELECT'}, attr='table'))
            )
        self.assertIn('databricks_grants.bad', str(caught.exception))
        self.assertNotIn('extra', str(caught.exception))

    def test_identity_names_marked_sensitive_are_not_read(self):
        p = read_plan(
            plan(
                identity(
                    'databricks_user.a',
                    'databricks_user',
                    '201',
                    'alice@example.com',
                    after_sensitive={'user_name': True},
                ),
                prior=[
                    {
                        'address': 'databricks_user.b',
                        'mode': 'managed',
                        'type': 'databricks_user',
                        'name': 'b',
                        'values': {'id': '202', 'user_name': 'bob@example.com'},
                        'sensitive_values': {'user_name': True},
                    }
                ],
            )
        )
        self.assertEqual(p.identities, {})

    def test_delete_replace_and_forget_actions(self):
        select, analysts = {'finance': frozenset({'SELECT'})}, {'analysts': frozenset({'SELECT'})}
        deleted = read_plan(plan(grants('databricks_grants.s', 'prod.sales', {'finance': 'SELECT'}, None)))
        self.assertEqual([(g.before, g.after) for g in deleted.changed_grants()], [(select, None)])
        replaced = read_plan(
            plan(
                grants(
                    'databricks_grants.s',
                    'prod.sales',
                    {'finance': 'SELECT'},
                    {'analysts': 'SELECT'},
                    actions=['delete', 'create'],
                )
            )
        )
        self.assertEqual([(g.before, g.after) for g in replaced.changed_grants()], [(select, analysts)])
        forgotten = read_plan(
            plan(grants('databricks_grants.s', 'prod.sales', {'finance': 'SELECT'}, None, actions=['forget']))
        )
        self.assertEqual(forgotten.changed_grants(), ())
        self.assertEqual([(g.before, g.after) for g in forgotten.grants], [(select, select)])

    def test_two_authoritative_grant_resources_on_one_securable_are_a_gap(self):
        p = read_plan(
            plan(
                grants('databricks_grants.a', 'prod.sales', {'finance': 'SELECT'}, {'finance': 'SELECT'}),
                grants('databricks_grants.b', 'prod.sales', None, {'analysts': 'SELECT'}),
            )
        )
        self.assertEqual(
            [g.detail for g in p.gaps if g.category == 'conflicting_grant_resources'],
            [
                'prod.sales: databricks_grants.a, databricks_grants.b each manage all of its grants; '
                'the applied result depends on apply order'
            ],
        )

    def test_two_principal_grant_resources_conflict_only_for_the_same_principal(self):
        def conflicts(other):
            p = read_plan(
                plan(
                    grant('databricks_grant.a', 'prod.sales', 'bob@example.com', None, 'SELECT'),
                    grant('databricks_grant.b', 'prod.sales', other, 'MODIFY', 'MODIFY'),
                )
            )
            return [g.detail for g in p.gaps if g.category == 'conflicting_grant_resources']

        self.assertEqual(
            conflicts('bob@example.com'),
            [
                'prod.sales: databricks_grant.a, databricks_grant.b each manage the grants of bob@example.com; '
                'the applied result depends on apply order'
            ],
        )
        self.assertEqual(conflicts('alice@example.com'), [])

    def test_securable_names_are_lowercased(self):
        p = read_plan(
            plan(
                grants('databricks_grants.s', 'Prod.Sales', None, {'finance': 'SELECT'}),
                owner('databricks_sql_table.o', 'Prod.Sales.Orders', 'a@example.com', 'b@example.com'),
            )
        )
        self.assertEqual([g.securable for g in p.grants], ['prod.sales'])
        self.assertEqual([o.securable for o in p.owners], ['prod.sales.orders'])
