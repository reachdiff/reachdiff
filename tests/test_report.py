import json
import unittest
from dataclasses import replace

from reachdiff.apply import apply_plan
from reachdiff.collect.offline import build_offline
from reachdiff.config import Config
from reachdiff.diff import compute_diff
from reachdiff.report import build_report, render_json, render_markdown, render_text, route_text
from reachdiff.resolve import Hop, Route
from reachdiff.rules import evaluate, status_of
from reachdiff.tfplan import read_plan
from tests.plans import grants, identity, plan

REPORT = {
    'schema_version': 1,
    'tool': 'reachdiff',
    'status': 'WARN',
    'mode': 'offline',
    'synthetic': True,
    'access_changes': True,
    'summary': {'gained': 1, 'lost': 1, 'findings': 1},
    'changes': [
        {
            'direction': '+',
            'principal': 'analysts',
            'kind': 'group',
            'level': 'READ',
            'securable': 'prod.sales',
            'via': ['SELECT on prod.sales + USE_CATALOG on prod + USE_SCHEMA on prod.sales'],
            'members': {
                'expanded': True,
                'total': 3,
                'changed': 2,
                'unchanged': 1,
                'names': ['alice@example.com', 'carol@example.com'],
            },
        },
        {
            'direction': '-',
            'principal': 'bob@example.com',
            'kind': 'user',
            'level': 'WRITE',
            'securable': 'prod.sales.orders',
            'via': [
                'MODIFY on prod.sales.orders + USE_CATALOG on prod + USE_SCHEMA on prod.sales + SELECT on prod.sales.orders'
            ],
            'members': None,
        },
    ],
    'findings': [{'severity': 'WARN', 'rule': 'unverified', 'subject': 'offline_blind_spot', 'message': 'not read'}],
    'not_evaluated': [],
    'gaps': [{'category': 'offline_blind_spot', 'detail': 'not read'}],
    'route_changes': [],
    'notes': [],
    'standing_limitations': ['admin powers'],
}

EXPECTED = """## reachdiff: WARN

_SYNTHETIC FIXTURE · offline mode_

**1 gained · 1 lost · 1 findings**

| | Principal | Access | On | Via |
|---|---|---|---|---|
| + | analysts (3 members, 2 new, 1 already had it) | READ | prod.sales (all tables) | SELECT on prod.sales + USE_CATALOG on prod + USE_SCHEMA on prod.sales |
| - | bob@example.com | WRITE | prod.sales.orders | MODIFY on prod.sales.orders + USE_CATALOG on prod + USE_SCHEMA on prod.sales + SELECT on prod.sales.orders |

### Findings

- **WARN** `unverified` offline_blind_spot: not read

<details><summary>Details</summary>

- analysts READ prod.sales: alice@example.com, carol@example.com
- gap `offline_blind_spot`: not read

</details>

<sub>Not evaluated in any run: admin powers.</sub>
"""


def built(*resources):
    p = read_plan(plan(*resources))
    before = build_offline(p)
    after = apply_plan(before, p)
    diff = compute_diff(before, after, p, members_limit=5000, deep=False)
    findings = evaluate(diff, p, before, after, Config(), deep=False)
    return build_report(p, before, after, diff, findings, status_of(findings))


class ReportTests(unittest.TestCase):
    def test_markdown_golden(self):
        self.assertEqual(render_markdown(REPORT), EXPECTED)

    def test_text_names_the_fixture_and_rows(self):
        text = render_text(REPORT)
        self.assertIn('reachdiff: WARN (offline mode, SYNTHETIC FIXTURE)', text)
        self.assertIn('- bob@example.com  WRITE  prod.sales.orders', text)

    def test_pipes_in_names_cannot_break_the_table(self):
        report = dict(REPORT, changes=[dict(REPORT['changes'][1], principal='a|b')])
        self.assertIn('a\\|b', render_markdown(report))

    def test_built_report_round_trips_as_json(self):
        p = read_plan(
            plan(grants('databricks_grants.prod', 'prod', None, {'bob@example.com': 'USE_CATALOG USE_SCHEMA SELECT'}))
        )
        before = build_offline(p)
        after = apply_plan(before, p)
        diff = compute_diff(before, after, p, members_limit=5000, deep=False)
        findings = evaluate(diff, p, before, after, Config(), deep=False)
        report = build_report(p, before, after, diff, findings, status_of(findings))
        self.assertEqual(json.loads(render_json(report)), report)
        self.assertEqual(report['changes'][0]['via'], ['SELECT on prod + USE_CATALOG on prod + USE_SCHEMA on prod'])

    def test_text_lists_route_changes_and_notes(self):
        report = dict(
            REPORT,
            notes=['Target workspace is not stated in the plan.'],
            route_changes=[
                {'principal': 'bob@example.com', 'level': 'READ', 'securable': 'prod.sales', 'before': [], 'after': []}
            ],
        )
        text = render_text(report)
        self.assertIn('\nRoute changes:\n  bob@example.com READ prod.sales\n', text)
        self.assertIn('\nNotes:\n  Target workspace is not stated in the plan.\n', text)

    def test_untrusted_text_cannot_break_markdown(self):
        hostile = 'x`\n<img src=y>'
        report = dict(
            REPORT,
            changes=[dict(REPORT['changes'][0], principal='<b>crew</b>')],
            findings=[{'severity': 'WARN', 'rule': 'r', 'subject': hostile, 'message': hostile}],
            not_evaluated=[hostile],
            gaps=[{'category': 'c', 'detail': hostile}],
            notes=[hostile],
            route_changes=[{'principal': hostile, 'level': 'READ', 'securable': 'prod', 'before': [], 'after': []}],
        )
        markdown = render_markdown(report)
        for raw in ('<img', '<b>', 'x`'):
            self.assertNotIn(raw, markdown)
        self.assertIn("x' &lt;img src=y&gt;", markdown)
        self.assertIn('| &lt;b&gt;crew&lt;/b&gt; (3 members', markdown)
        self.assertIn('- &lt;b&gt;crew&lt;/b&gt; READ prod.sales: alice@example.com', markdown)

    def test_changes_without_evaluated_rows_are_not_called_no_access_changes(self):
        changed = built(grants('databricks_grants.prod', 'prod', None, {'bob@example.com': 'USE_CATALOG'}))
        unchanged = built(
            grants(
                'databricks_grants.prod', 'prod', {'bob@example.com': 'USE_CATALOG'}, {'bob@example.com': 'USE_CATALOG'}
            )
        )
        for render in (render_text, render_markdown):
            self.assertIn('No evaluated access changes; see findings.', render(changed))
            self.assertNotIn('No access changes.', render(changed))
            self.assertIn('No access changes.', render(unchanged))

    def test_crafted_names_cannot_forge_lines_or_links(self):
        report = dict(
            REPORT,
            changes=[dict(REPORT['changes'][1], principal='eve\nFAKE\r+ mallory')],
            findings=[
                {'severity': 'WARN', 'rule': 'r', 'subject': '[x](https://e.x)', 'message': 'a\\[b](https://e.x)'}
            ],
        )
        text = render_text(report)
        self.assertNotIn('\nFAKE', text)
        self.assertNotIn('\r', text)
        markdown = render_markdown(report)
        self.assertIn('\\[x\\](https://e.x)', markdown)
        self.assertNotIn('[x](', markdown)
        self.assertNotIn('[b](', markdown)

    def test_unread_membership_is_named_not_counted(self):
        p = read_plan(
            plan(
                identity('databricks_group.analysts', 'databricks_group', '101', 'analysts'),
                grants('databricks_grants.prod', 'prod', None, {'analysts': 'USE_CATALOG USE_SCHEMA SELECT'}),
            )
        )
        before = replace(build_offline(p), unread_groups=frozenset({'analysts'}))
        after = apply_plan(before, p)
        diff = compute_diff(before, after, p, members_limit=5000, deep=False)
        report = build_report(p, before, after, diff, (), 'WARN')
        self.assertTrue(report['changes'][0]['members']['unread'])
        self.assertIn('+ analysts (members not read)  READ  prod (all schemas)', render_text(report))
        self.assertIn('| + | analysts (members not read) |', render_markdown(report))
        self.assertEqual(json.loads(render_json(report)), report)

    def test_one_member_is_singular(self):
        members = dict(REPORT['changes'][0]['members'], total=1, changed=1, unchanged=0)
        report = dict(REPORT, changes=[dict(REPORT['changes'][0], members=members)])
        self.assertIn('analysts (1 member, 1 new, 0 already had it)', render_text(report))

    def test_route_text_shows_each_hop_once(self):
        owner = Hop((), 'OWNER', 'prod.hr', 'owner of prod.hr')
        route = Route(owner, (Hop((), 'USE_CATALOG', 'prod', 'grant'), owner, owner))
        self.assertEqual(route_text(route), 'OWNER on prod.hr + USE_CATALOG on prod')
