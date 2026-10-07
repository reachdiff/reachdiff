import json
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from reachdiff.collect.live import collect
from reachdiff.config import Config
from reachdiff.state import Gap
from reachdiff.tfplan import read_plan
from tests.plans import grant, grants, member, plan

HOST = 'https://ws.example.net'
UC = '/api/2.1/unity-catalog'
SCIM = '/api/2.0/preview/scim/v2'
REAL = Path(__file__).resolve().parent / 'fixtures' / 'real'
ETL, SCANNER = '00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002'  # sanitized IDs


def real(name):
    return json.loads((REAL / name).read_text(encoding='utf-8'))


def workspace():
    return {
        (f'{UC}/permissions/catalog/prod', None): {
            'privilege_assignments': [{'principal': 'account users', 'privileges': ['USE_CATALOG']}]
        },
        (f'{UC}/permissions/schema/prod.sales', None): {
            'privilege_assignments': [{'principal': 'finance', 'privileges': ['USE_SCHEMA', 'SELECT']}]
        },
        (f'{UC}/catalogs/prod', None): {'name': 'prod', 'owner': 'data-eng'},
        (f'{UC}/schemas/prod.sales', None): {'full_name': 'prod.sales', 'owner': 'data-eng'},
        (f'{UC}/entity-tag-assignments/catalogs/prod/tags', None): {'tag_assignments': []},
        (f'{UC}/entity-tag-assignments/schemas/prod.sales/tags', None): {'tag_assignments': [{'tag_key': 'pii'}]},
        (f'{SCIM}/Groups', 'displayName eq "analysts"'): {'Resources': [{'id': '101'}]},
        (f'{SCIM}/Groups', 'displayName eq "finance"'): {'Resources': [{'id': '102'}]},
        (f'{SCIM}/Groups/101', None): {
            'id': '101',
            'displayName': 'analysts',
            'members': [
                {'value': '201', 'type': 'User', 'display': 'Alice'},
                {'value': '202', 'type': 'User', 'display': 'Bob'},
                {'value': '103', 'type': 'Group', 'display': 'interns'},
            ],
        },
        (f'{SCIM}/Groups/102', None): {
            'id': '102',
            'displayName': 'finance',
            'members': [{'value': '202', 'type': 'User', 'display': 'Bob'}],
        },
        (f'{SCIM}/Groups/103', None): {
            'id': '103',
            'displayName': 'interns',
            'members': [{'value': '204', '$ref': 'Users/204', 'display': 'Dave'}],
        },
        (f'{SCIM}/Users/205', None): {'id': '205', 'userName': 'erin@example.com'},
        (f'{SCIM}/Me', None): {'userName': 'scanner-app', 'groups': [{'display': 'users', 'value': '1'}]},
        (f'{UC}/metastore_summary', None): {'owner': 'metastore-admins'},
        (f'{UC}/effective-permissions/catalog/prod', None): {
            'privilege_assignments': [
                {
                    'principal': 'scanner-app',
                    'privileges': [{'privilege': 'READ_METADATA', 'inherited_from_type': 'METASTORE'}],
                }
            ]
        },
    }


class FakeAPI:
    def __init__(self, responses):
        self.responses, self.calls, self.filters = responses, [], []

    def do(self, method, path, query=None, **kwargs):
        # The only mocked boundary: the remote HTTP request.
        assert method == 'GET', 'collector attempted a write'
        query = dict(query or {})
        self.calls.append(path)
        self.filters.append(query.get('filter'))
        key = (path, query.get('page_token') or query.get('filter'))
        if key not in self.responses:
            raise LookupError(path)
        value = self.responses[key]
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)


class Unauthenticated(Exception):
    pass


class PermissionDenied(Exception):
    pass


class NotFound(Exception):
    pass


SALES = {'finance': 'USE_SCHEMA SELECT'}
ADD_ANALYSTS = grants('databricks_grants.sales', 'prod.sales', SALES, {**SALES, 'analysts': 'USE_SCHEMA SELECT'})


def run(*resources, responses=None, config=None, deep=False, host=HOST):
    api = FakeAPI(responses if responses is not None else workspace())
    client = SimpleNamespace(config=SimpleNamespace(host=HOST), api_client=api)
    return collect(read_plan(plan(*resources, host=host)), client, config or Config(), deep=deep), api


class LiveCollectorTests(unittest.TestCase):
    def test_reads_only_the_touched_scope_and_expands_groups(self):
        state, api = run(ADD_ANALYSTS, member('databricks_group_member.e', '101', '205', False, True))
        self.assertEqual(set(api.calls), {path for path, _ in workspace()})
        self.assertEqual(state.source, 'live')
        self.assertEqual(state.securables['prod.sales'].tags, frozenset({'pii'}))
        self.assertEqual(state.securables['prod.sales'].owner, 'data-eng')
        pairs = {(m.member, m.group) for m in state.memberships}
        self.assertTrue(
            {('Dave (user 204)', 'interns'), ('interns', 'analysts'), ('Bob (user 202)', 'finance')} <= pairs
        )
        self.assertEqual(state.principals['erin@example.com'].scim_id, '205')
        self.assertIn('membership_scope', {g.category for g in state.gaps})

    def test_follows_pages_after_an_empty_page(self):
        responses = workspace()
        path = f'{UC}/permissions/schema/prod.sales'
        responses[(path, None)] = {'privilege_assignments': [], 'next_page_token': 't2'}
        responses[(path, 't2')] = {
            'privilege_assignments': [{'principal': 'finance', 'privileges': ['USE_SCHEMA', 'SELECT']}]
        }
        state, _ = run(ADD_ANALYSTS, responses=responses)
        self.assertIn('finance', {g.principal for g in state.grants if g.securable == 'prod.sales'})

    def test_unreadable_object_is_a_redacted_gap(self):
        responses = workspace()
        responses[(f'{UC}/permissions/catalog/prod', None)] = RuntimeError('TOKEN=secret-do-not-print')
        state, _ = run(ADD_ANALYSTS, responses=responses)
        self.assertIn('unreadable_object', {g.category for g in state.gaps})
        self.assertNotIn('secret-do-not-print', repr(state))
        self.assertFalse(any(g.securable == 'prod' for g in state.grants))
        self.assertTrue(any(g.securable == 'prod.sales' for g in state.grants))

    def test_member_limit_and_change_since_plan(self):
        state, _ = run(
            grants(
                'databricks_grants.sales',
                'prod.sales',
                {'finance': 'USE_SCHEMA'},
                {'finance': 'USE_SCHEMA', 'analysts': 'SELECT'},
            ),
            config=Config(limit_members=2),
        )
        categories = {g.category for g in state.gaps}
        self.assertIn('limit_reached', categories)
        self.assertIn('changed_since_plan', categories)

    def test_host_checks_and_authentication(self):
        with self.assertRaises(ValueError):
            run(ADD_ANALYSTS, host='https://other.example.net')
        state, _ = run(ADD_ANALYSTS, host=None)
        self.assertEqual(state.notes, ('Target workspace is not stated in the plan.',))
        responses = workspace()
        responses[(f'{UC}/permissions/catalog/prod', None)] = Unauthenticated('bad token')
        with self.assertRaises(RuntimeError):
            run(ADD_ANALYSTS, responses=responses)

    def test_a_failed_login_names_the_login_settings_without_sdk_text(self):
        hint = (
            'Databricks login failed ({} on GET /api/2.0/preview/scim/v2/Me). Check DATABRICKS_AUTH_TYPE or the '
            "profile, the client ID and, with token federation, the policy's issuer, subject and audience"
        )
        for exc in (ValueError('invalid_grant: TOKEN_SUBJECT_INVALID (repo:me/x)'), Unauthenticated('bad token')):
            responses = workspace()
            responses[(f'{SCIM}/Me', None)] = exc
            with self.assertRaises(RuntimeError) as caught:
                run(ADD_ANALYSTS, responses=responses)
            self.assertEqual(str(caught.exception), hint.format(type(exc).__name__))

    def test_a_total_outage_is_an_error(self):
        with self.assertRaises(RuntimeError) as caught:
            run(ADD_ANALYSTS, responses={})
        self.assertEqual(
            str(caught.exception),
            'no Databricks read succeeded; first failure: LookupError on GET '
            f'{SCIM}/Me. Check the workspace entitlement (e.g. workspace-consume) and the READ '
            'METADATA grant of the identity reachdiff runs as',
        )

    def test_deep_reads_child_tables(self):
        responses = workspace()
        responses[(f'{UC}/tables', None)] = {'tables': [{'full_name': 'prod.sales.orders'}]}
        responses[(f'{UC}/permissions/table/prod.sales.orders', None)] = {
            'privilege_assignments': [{'principal': 'analysts', 'privileges': ['SELECT']}]
        }
        responses[(f'{UC}/tables/prod.sales.orders', None)] = {'full_name': 'prod.sales.orders', 'owner': 'data-eng'}
        responses[(f'{UC}/entity-tag-assignments/tables/prod.sales.orders/tags', None)] = {'tag_assignments': []}
        state, _ = run(ADD_ANALYSTS, responses=responses, deep=True)
        self.assertIn('prod.sales.orders', state.securables)
        self.assertIn('analysts', {g.principal for g in state.grants if g.securable == 'prod.sales.orders'})

    def test_object_and_deep_children_limits_keep_the_changed_objects(self):
        responses = workspace()
        responses[(f'{UC}/schemas', None)] = {'schemas': [{'full_name': 'prod.alpha'}, {'full_name': 'prod.zeta'}]}
        responses[(f'{UC}/tables', None)] = {'tables': []}
        changes = (
            grants('databricks_grants.prod', 'prod', None, {'finance': 'USE_CATALOG'}),
            grants('databricks_grants.zeta', 'prod.zeta', None, {'finance': 'USE_SCHEMA'}),
        )
        state, _ = run(*changes, responses=responses, config=Config(limit_objects=2), deep=True)
        self.assertEqual(set(state.securables), {'prod', 'prod.zeta'})
        self.assertIn('limit_reached', {g.category for g in state.gaps})
        state, _ = run(*changes, responses=responses, config=Config(limit_deep_children=1), deep=True)
        self.assertEqual(set(state.securables), {'prod', 'prod.alpha', 'prod.zeta'})
        self.assertIn('2 child objects under --deep; only the first 1 were read', {g.detail for g in state.gaps})

    def test_names_that_cannot_be_filtered_safely_are_not_looked_up(self):
        state, api = run(grants('databricks_grants.sales', 'prod.sales', SALES, {**SALES, 'bad"name': 'SELECT'}))
        self.assertIn('bad"name cannot be looked up safely', {g.detail for g in state.gaps})
        self.assertFalse(any('bad' in f for f in api.filters if f))

    def test_admin_only_membership_is_one_gap_and_stops_reading_groups(self):
        responses = workspace()
        responses[(f'{SCIM}/Groups/101', None)] = PermissionDenied('only admins')
        state, api = run(ADD_ANALYSTS, responses=responses)
        gaps = [g for g in state.gaps if g.category == 'membership_incomplete']
        self.assertEqual(
            [g.detail for g in gaps],
            ['group members not read: workspace SCIM shows members only to workspace admins (PermissionDenied)'],
        )
        self.assertNotIn(f'{SCIM}/Groups/102', api.calls)
        self.assertEqual(state.unread_groups, frozenset({'analysts', 'finance'}))

    def test_other_membership_errors_stay_per_group(self):
        responses = workspace()
        responses[(f'{SCIM}/Groups/101', None)] = NotFound('gone')
        state, api = run(ADD_ANALYSTS, responses=responses)
        self.assertIn(Gap('membership_incomplete', 'group 101 (NotFound)'), state.gaps)
        self.assertIn(f'{SCIM}/Groups/102', api.calls)
        self.assertEqual(state.unread_groups, frozenset({'analysts'}))

    def test_a_refused_plan_id_lookup_names_the_admin_requirement(self):
        responses = workspace()
        responses[(f'{SCIM}/Users/205', None)] = PermissionDenied('only admins')
        state, _ = run(
            ADD_ANALYSTS, member('databricks_group_member.e', '101', '205', False, True), responses=responses
        )
        self.assertIn(Gap('unresolved_name', 'SCIM ID 205 from the plan (lookup needs workspace admin)'), state.gaps)

    def test_listed_child_names_are_lowercased(self):
        responses = workspace()
        responses[(f'{UC}/tables', None)] = {'tables': [{'full_name': 'prod.sales.Orders'}]}
        state, _ = run(ADD_ANALYSTS, responses=responses, deep=True)
        self.assertIn('prod.sales.orders', state.securables)

    def test_children_inherit_visibility_without_another_check(self):
        _, api = run(ADD_ANALYSTS)
        self.assertEqual(
            [c for c in api.calls if 'effective-permissions' in c], [f'{UC}/effective-permissions/catalog/prod']
        )

    def test_lists_the_caller_cannot_see_completely_are_discarded(self):
        responses = workspace()
        responses[(f'{UC}/effective-permissions/catalog/prod', None)] = {'privilege_assignments': []}
        responses[(f'{UC}/effective-permissions/schema/prod.sales', None)] = {
            'privilege_assignments': [{'principal': 'users', 'privileges': [{'privilege': 'BROWSE'}]}]
        }
        state, api = run(
            grants(
                'databricks_grants.sales',
                'prod.sales',
                {'finance': 'USE_SCHEMA'},
                {'finance': 'USE_SCHEMA', 'analysts': 'SELECT'},
            ),
            responses=responses,
        )
        self.assertEqual(state.grants, ())
        self.assertIn(
            Gap(
                'unreadable_object',
                "grants on prod.sales (only the caller's own grants are visible; "
                'needs READ METADATA, MANAGE or ownership); partial data discarded',
            ),
            state.gaps,
        )
        self.assertNotIn('changed_since_plan', {g.category for g in state.gaps})
        self.assertNotIn(f'{UC}/permissions/schema/prod.sales', api.calls)

    def test_ownership_or_metastore_admin_makes_lists_visible(self):
        for me, summary in (
            ({'userName': 'scanner-app', 'groups': [{'display': 'data-eng'}]}, {'owner': 'x'}),
            ({'userName': 'scanner-app', 'groups': [{'display': 'uc-admins'}]}, {'owner': 'uc-admins'}),
        ):
            responses = workspace()
            responses[(f'{SCIM}/Me', None)] = me
            responses[(f'{UC}/metastore_summary', None)] = summary
            del responses[(f'{UC}/effective-permissions/catalog/prod', None)]
            state, api = run(ADD_ANALYSTS, responses=responses)
            self.assertIn('finance', {g.principal for g in state.grants})
            self.assertFalse([c for c in api.calls if 'effective-permissions' in c])

    def test_an_unknown_caller_makes_every_list_unverifiable(self):
        responses = workspace()
        responses[(f'{SCIM}/Me', None)] = PermissionDenied('no entitlement')
        state, _ = run(ADD_ANALYSTS, responses=responses)
        self.assertEqual(state.grants, ())
        self.assertIn(Gap('unreadable_object', "the caller's identity (SCIM Me: PermissionDenied)"), state.gaps)
        self.assertIn('unreadable_object', {g.category for g in state.gaps if g.detail.startswith('grants on prod ')})

    def test_a_refused_visibility_check_says_the_caller_cannot_see_the_object(self):
        for error, reason in (
            (
                PermissionDenied('no access'),
                'the caller cannot see this object (PermissionDenied); needs READ METADATA, MANAGE or ownership',
            ),
            (NotFound('gone'), 'visibility check failed (NotFound)'),
        ):
            responses = workspace()
            responses[(f'{UC}/effective-permissions/catalog/prod', None)] = error
            state, _ = run(ADD_ANALYSTS, responses=responses)
            self.assertIn(Gap('unreadable_object', f'grants on prod ({reason}); partial data discarded'), state.gaps)

    def test_real_effective_permissions_clear_visibility(self):
        for name in ('R7-effective.json', 'R5-effective-salaries.json'):  # direct, and inherited from the catalog
            responses = workspace()
            responses[(f'{UC}/effective-permissions/catalog/prod', None)] = real(name)
            state, _ = run(ADD_ANALYSTS, responses=responses)
            self.assertIn('finance', {g.principal for g in state.grants})

    def test_real_response_shapes(self):
        """Sanitized responses from the live sessions; only the identity and owner reads are hand-built."""
        sales, customers = 'gp_validation.sales', 'gp_validation.sales.customers'
        tags = f'{UC}/entity-tag-assignments'
        responses = {
            (f'{SCIM}/Me', None): {'userName': SCANNER, 'groups': [{'display': 'users'}]},
            (f'{UC}/metastore_summary', None): {'owner': 'metastore-admins'},
            (f'{UC}/effective-permissions/catalog/gp_validation', None): real('R7-effective.json'),
            (f'{UC}/permissions/catalog/gp_validation', None): {'privilege_assignments': []},
            (f'{UC}/permissions/schema/{sales}', None): real('S9-probe-grants-Sales.json'),
            (f'{UC}/permissions/table/{customers}', None): real('S3.readback.json'),
            (f'{UC}/permissions/table/gp_validation.sales.orders', None): {'privilege_assignments': []},
            (f'{UC}/catalogs/gp_validation', None): {'owner': 'x'},
            (f'{UC}/schemas/{sales}', None): {'owner': 'x'},
            (f'{UC}/tables/{customers}', None): {'owner': 'x', 'columns': [{'name': 'email'}]},
            (f'{UC}/tables/gp_validation.sales.orders', None): {'owner': 'x'},
            (f'{tags}/catalogs/gp_validation/tags', None): {'tag_assignments': []},
            (f'{tags}/schemas/{sales}/tags', None): {'tag_assignments': []},
            (f'{tags}/tables/{customers}/tags', None): real('S0-tag-salaries.json'),  # a key-only table tag
            (f'{tags}/columns/{customers}.email/tags', None): real('P1-column.json'),
            (f'{tags}/tables/gp_validation.sales.orders/tags', None): {'tag_assignments': []},
            (f'{UC}/tables', None): real('P1-page1.json'),
            (f'{UC}/tables', 'page-1'): real('P1-page2.json'),
        }
        usage = {'gp-pii-readers': 'SELECT USE_SCHEMA', ETL: 'USE_SCHEMA'}
        state, api = run(
            grants('databricks_grants.sales', sales, usage, {**usage, 'gp-analysts': 'SELECT USE_SCHEMA'}),
            grant('databricks_grant.customers', customers, ETL, 'MODIFY', 'MODIFY SELECT'),
            responses=responses,
            deep=True,
        )
        self.assertEqual(
            {(g.principal, g.securable, g.privileges) for g in state.grants},
            {
                (ETL, sales, frozenset({'USE_SCHEMA'})),
                ('gp-pii-readers', sales, frozenset({'SELECT', 'USE_SCHEMA'})),
                (ETL, customers, frozenset({'MODIFY'})),
            },
        )
        self.assertIn('gp_validation.sales.orders', state.securables)  # listed on the second page
        self.assertEqual(state.securables[customers].tags, frozenset({'sensitive', 'pii'}))
        categories = {g.category for g in state.gaps}
        self.assertFalse({'unreadable_object', 'changed_since_plan', 'tags_unavailable'} & categories)
        self.assertEqual(
            [c for c in api.calls if 'effective-permissions' in c],
            [f'{UC}/effective-permissions/catalog/gp_validation'],
        )
