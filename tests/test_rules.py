import json
import unittest
from dataclasses import replace
from fnmatch import fnmatchcase
from pathlib import Path

from reachdiff.apply import apply_plan
from reachdiff.collect.offline import build_offline
from reachdiff.config import DEFAULT_TAGS, Config, parse_config
from reachdiff.diff import compute_diff
from reachdiff.rules import _object_matches, evaluate, status_of
from reachdiff.state import Securable
from reachdiff.tfplan import read_plan
from tests.plans import grant, grants, identity, member, owner, plan

BASE = [
    grants('databricks_grants.prod', 'prod', {'account users': 'USE_CATALOG'}, {'account users': 'USE_CATALOG'}),
    identity('databricks_group.pii', 'databricks_group', '101', 'pii-readers'),
    identity('databricks_group.mkt', 'databricks_group', '102', 'marketing'),
    identity('databricks_user.bob', 'databricks_user', '202', 'bob@example.com'),
    grants(
        'databricks_grants.pii',
        'prod.pii',
        {'pii-readers': 'USE_SCHEMA SELECT', 'marketing': 'USE_SCHEMA SELECT'},
        {'pii-readers': 'USE_SCHEMA SELECT', 'marketing': 'USE_SCHEMA SELECT'},
    ),
]
PII_RULE = {
    'rule': [
        {
            'id': 'pii-only-approved',
            'severity': 'BLOCK',
            'sensitive': True,
            'unless_via': ['pii-readers'],
            'message': 'New PII access outside approved groups',
        }
    ]
}


def findings(*resources, **options):
    return outcome(*resources, **options)[1]


def outcome(*resources, config=None, tags=None, deep=False, base=BASE, live=False):
    """(diff, findings). live=True stands in for a live collection that recorded no gaps."""
    p = read_plan(plan(*base, *resources))
    before = build_offline(p)
    if live:
        before = replace(before, source='live', gaps=())
    if tags:
        before = replace(
            before,
            securables={n: Securable(n, s.owner, frozenset(tags.get(n, ()))) for n, s in before.securables.items()},
        )
    after = apply_plan(before, p)
    diff = compute_diff(before, after, p, members_limit=5000, deep=deep)
    return diff, evaluate(diff, p, before, after, config or Config(), deep=deep)


def rules(found):
    return {(f.rule, f.severity) for f in found}


class ConfigTests(unittest.TestCase):
    def test_validation(self):
        self.assertEqual(parse_config({}).fail_on, 'block')
        self.assertEqual(parse_config({'builtin': {'broad_principal': 'off'}}).builtin['broad_principal'], 'off')
        for bad in (
            {'fail_om': 'warn'},
            {'builtin': {'unverified': 'off'}},
            {'limits': {'members': 0}},
            {'rule': [{'id': 'unverified', 'severity': 'BLOCK', 'message': 'x'}]},
            {'rule': [{'id': 'r', 'severity': 'FAIL', 'message': 'x'}]},
            {'rule': [{'id': 'r', 'severity': 'WARN', 'message': 'x', 'colour': 'red'}]},
        ):
            with self.assertRaises(ValueError):
                parse_config(bad)

    def test_default_tags_match_data_classification(self):
        path = Path(__file__).resolve().parent / 'fixtures' / 'real' / 'P2-final-customers-email.json'
        keys = {t['tag_key'] for t in json.loads(path.read_text(encoding='utf-8'))['tag_assignments']}
        classified = {k for k in keys if k.startswith('class.')}
        self.assertTrue(classified)
        self.assertTrue(all(any(fnmatchcase(k, glob) for glob in DEFAULT_TAGS) for k in classified))


class RuleTests(unittest.TestCase):
    def test_no_access_changes_is_pass_even_offline(self):
        self.assertEqual(status_of(findings()), 'PASS')

    def test_offline_access_changes_warn_as_unverified(self):
        found = findings(
            grants('databricks_grants.sales', 'prod.sales', None, {'bob@example.com': 'USE_SCHEMA SELECT'})
        )
        self.assertIn(('unverified', 'WARN'), rules(found))
        self.assertIn('offline_blind_spot', {f.subject for f in found})
        self.assertEqual(status_of(found), 'WARN')

    def test_values_known_only_after_apply_never_pass(self):
        found = findings(
            grants(
                'databricks_grants.sales',
                'prod.sales',
                {'bob@example.com': 'SELECT'},
                {'bob@example.com': 'SELECT'},
                after_unknown={'grant': True},
            )
        )
        self.assertEqual(status_of(found), 'WARN')
        self.assertIn('unknown_after_apply', {f.subject for f in found})

    def test_revoked_usage_privilege_is_never_pass(self):
        found = findings(
            grants('databricks_grants.prod', 'prod', {'account users': 'USE_CATALOG'}, {}), base=BASE[1:], live=True
        )
        self.assertNotEqual(status_of(found), 'PASS')
        self.assertIn('deactivated_grants', {f.subject for f in found})

    def test_deep_gains_whose_column_tags_were_not_read_are_never_pass(self):
        orders = grants('databricks_grants.orders', 'prod.sales.orders', {'analysts': 'SELECT'}, {'analysts': 'SELECT'})
        on_schema = findings(
            orders,
            grants('databricks_grants.sales', 'prod.sales', None, {'analysts': 'USE_SCHEMA SELECT'}),
            deep=True,
            live=True,
        )
        self.assertNotEqual(status_of(on_schema), 'PASS')
        self.assertIn(
            ('sensitivity_not_evaluated', 'column tags of child tables under prod.sales were not read'),
            {(f.subject, f.message) for f in on_schema},
        )
        on_table = findings(
            orders,
            grants('databricks_grants.sales', 'prod.sales', None, {'analysts': 'USE_SCHEMA'}),
            deep=True,
            live=True,
        )
        self.assertIn(
            ('sensitivity_not_evaluated', 'column tags of prod.sales.orders were not read'),
            {(f.subject, f.message) for f in on_table},
        )

    def test_builtin_rules(self):
        found = findings(
            grants(
                'databricks_grants.sales',
                'prod.sales',
                None,
                {'account users': 'USE_SCHEMA SELECT', 'ops': 'ALL_PRIVILEGES'},
            ),
            owner('databricks_schema.sales', 'prod.sales', 'data-eng', 'bob@example.com'),
        )
        self.assertTrue(
            {('broad_principal', 'WARN'), ('broad_privilege', 'WARN'), ('individual_owner', 'WARN')} <= rules(found)
        )

    def test_sensitive_access_and_every_route_unless_via(self):
        tags = {'prod.pii': ['pii']}
        both = findings(
            member('databricks_group_member.p', '101', '202', False, True),
            member('databricks_group_member.m', '102', '202', False, True),
            config=parse_config(PII_RULE),
            tags=tags,
        )
        self.assertIn(('sensitive_access', 'WARN'), rules(both))
        self.assertIn(('pii-only-approved', 'BLOCK'), rules(both))
        self.assertEqual(status_of(both), 'BLOCK')
        approved = findings(
            member('databricks_group_member.p', '101', '202', False, True), config=parse_config(PII_RULE), tags=tags
        )
        self.assertNotIn(('pii-only-approved', 'BLOCK'), rules(approved))

    def test_configured_rule_matching_fails_closed(self):
        def rule(**match):
            return parse_config({'rule': [{'id': 'watch', 'severity': 'BLOCK', 'message': 'watched', **match}]})

        on_catalog = [
            grant('databricks_grant.bob', catalog, 'bob@example.com', None, 'USE_CATALOG USE_SCHEMA SELECT')
            for catalog in ('prod', 'dev')
        ]
        self.assertIn('watch', {f.rule for f in findings(on_catalog[0], base=(), config=rule(objects=['prod.*']))})
        self.assertNotIn('watch', {f.rule for f in findings(on_catalog[1], base=(), config=rule(objects=['prod.*']))})
        self.assertIn('watch', {f.rule for f in findings(on_catalog[0], base=(), config=rule(objects=['*pii*']))})
        unknown_kind = grants('databricks_grants.sales', 'prod.sales', None, {'ops': 'USE_SCHEMA SELECT'})
        self.assertIn('watch', {f.rule for f in findings(unknown_kind, config=rule(principal_kinds=['user']))})

    def test_configured_rules_see_child_rows_that_a_parent_row_absorbs(self):
        found = findings(
            identity('databricks_group.ctr', 'databricks_group', '103', 'contractors'),
            member('databricks_group_member.c', '103', '202', True, True),
            grants('databricks_grants.ssn', 'prod.pii.ssn', None, {'contractors': 'SELECT'}),
            member('databricks_group_member.p', '101', '202', False, True),
            config=parse_config(PII_RULE),
            tags={'prod.pii': ['pii']},
        )
        self.assertIn(('pii-only-approved', 'bob@example.com READ prod.pii.ssn'), {(f.rule, f.subject) for f in found})
        self.assertNotIn(('pii-only-approved', 'bob@example.com READ prod.pii'), {(f.rule, f.subject) for f in found})

    def test_a_route_only_change_produces_no_finding(self):
        diff, found = outcome(
            member('databricks_group_member.m', '102', '202', True, True),
            grant('databricks_grant.bob', 'prod.pii.ssn', 'bob@example.com', None, 'SELECT'),
            live=True,
        )
        self.assertEqual([k for k, _, _ in diff.route_changes], [('bob@example.com', 'READ', 'prod.pii.ssn')])
        self.assertEqual((diff.rows, found), ((), ()))

    def test_object_globs_match_every_parent_of_a_name_they_could_match(self):
        cases = [
            ('*pii*', 'prod', True),
            ('prod*orders', 'prod', True),
            ('prod*orders', 'prod.sales', True),
            ('dev.*', 'prod', False),
            ('prod.*', 'prod', True),
            ('prod.*', 'dev', False),
            ('*.pii.*', 'prod', True),
            ('*.pii.*', 'prod.pii', True),
            ('*.pii.*', 'prod.pii.ssn', True),
            ('*.pii.*', 'prod.sales', False),
            ('prod.s[a-z]les.orders', 'prod.sales', True),
            ('prod.[!s]*', 'prod.sales', False),
            ('prod[.x', 'prod', False),
            ('PROD.*', 'prod.sales', True),
            ('Prod.Sales.Orders', 'prod.sales.orders', True),
        ]
        self.assertEqual([(p, s, _object_matches(s, p)) for p, s, _ in cases], cases)

    def test_unless_via_sees_a_member_route_that_avoids_the_approved_group(self):
        found = findings(
            member('databricks_group_member.p', '101', '202', True, True),
            grants(
                'databricks_grants.hr',
                'prod.hr',
                None,
                {'pii-readers': 'USE_SCHEMA SELECT', 'bob@example.com': 'SELECT'},
            ),
            config=parse_config(PII_RULE),
            tags={'prod.hr': ['pii']},
        )
        self.assertIn(('pii-only-approved', 'bob@example.com READ prod.hr'), {(f.rule, f.subject) for f in found})
        self.assertEqual(status_of(found), 'BLOCK')

    def test_grant_resource_conflicts_block_by_default(self):
        moved_between_types = (
            grants('databricks_grants.hr', 'prod.hr', {'pii-readers': 'USE_SCHEMA'}, None),
            grant('databricks_grant.hr', 'prod.hr', 'pii-readers', None, 'USE_SCHEMA'),
        )
        two_authoritative = (
            grants('databricks_grants.a', 'prod.hr', None, {'pii-readers': 'USE_SCHEMA'}),
            grants('databricks_grants.b', 'prod.hr', None, {'marketing': 'USE_SCHEMA'}),
        )
        self.assertEqual(Config().builtin['grant_resource_conflict'], 'BLOCK')
        for resources in (moved_between_types, two_authoritative):
            found = findings(*resources)
            self.assertIn(('grant_resource_conflict', 'BLOCK'), rules(found))
            self.assertEqual(status_of(found), 'BLOCK')
        off = findings(*moved_between_types, config=parse_config({'builtin': {'grant_resource_conflict': 'off'}}))
        self.assertNotIn('grant_resource_conflict', {f.rule for f in off})
        self.assertEqual(status_of(off), 'WARN')
