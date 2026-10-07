import json
import tempfile
import unittest
from pathlib import Path

from reachdiff.tfplan import read_plan
from tests.plans import grants, identity, plan, secret
from validation.sanitize import Pseudonyms, attributes, leftovers, main, sanitize_plan, sanitize_response

REAL = Path(__file__).resolve().parent / 'fixtures' / 'real'
APP = '12345678-1234-1234-1234-123456789abc'  # shaped like an application ID, obviously made up
FIRST_APP = '00000000-0000-4000-8000-000000000001'


class SanitizerTests(unittest.TestCase):
    def test_keeps_only_what_reachdiff_reads(self):
        user = identity('databricks_user.op', 'databricks_user', '123456789012', 'op@corp.example.org')
        user['change']['after']['external_id'] = 'idp-internal-id'
        marked = grants(
            'databricks_grants.hr',
            'realcat.hr',
            None,
            {'hidden-principal': 'SELECT'},
            after_sensitive={'grant': [{'principal': True}]},
        )
        raw = plan(
            secret('databricks_secret.s', 'TOKEN=do-not-copy'),
            user,
            marked,
            grants('databricks_grants.sales', 'realcat.sales', None, {APP: 'SELECT'}),
            host='https://adb-1234567890123456.7.azuredatabricks.net',
        )
        doc = sanitize_plan(raw, Pseudonyms({'realcat': 'gp_validation'}))
        text = json.dumps(doc)
        for real in (
            'do-not-copy',
            'databricks_secret',
            'idp-internal-id',
            'hidden-principal',
            'op@corp',
            '123456789012',
            APP,
            'adb-1234',
            'realcat',
        ):
            self.assertNotIn(real, text)
        self.assertEqual(leftovers(text, {'realcat': 'gp_validation'}), [])
        p = read_plan(doc)
        self.assertEqual(p.hosts, ('https://adb-0000000000000000.0.azuredatabricks.net',))
        self.assertEqual(
            [(g.securable, g.after) for g in p.grants], [('gp_validation.sales', {FIRST_APP: frozenset({'SELECT'})})]
        )
        self.assertIn('sensitive_value', {g.category for g in p.gaps})
        self.assertEqual(p.identities['10001'].name, 'user-1@example.com')

    def test_one_run_maps_a_plan_and_its_responses_alike(self):
        names = Pseudonyms({})
        doc = sanitize_plan(plan(grants('databricks_grants.sales', 'cat.sales', None, {APP: 'SELECT'})), names)
        response = sanitize_response(
            {
                'privilege_assignments': [{'principal': APP, 'privileges': ['SELECT']}],
                'next_page_token': 'opaque-123456789',
            },
            names,
        )
        self.assertEqual(doc['resource_changes'][0]['change']['after']['grant'][0]['principal'], FIRST_APP)
        self.assertEqual(
            response,
            {
                'privilege_assignments': [{'principal': FIRST_APP, 'privileges': ['SELECT']}],
                'next_page_token': 'page-1',
            },
        )

    def test_output_that_still_holds_an_identifier_is_not_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / 'tags.json', Path(tmp) / 'out'
            source.write_text(json.dumps({'tag_assignments': [{'tag_key': 'owner', 'tag_value': 'realcat-team'}]}))
            self.assertEqual(main([str(source), '--rename', 'realcat=gp_validation', '--out', str(out)]), 1)
            self.assertFalse(out.exists())

    def test_a_second_run_gives_identical_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'S.plan.json'
            source.write_text(json.dumps(plan(grants('databricks_grants.sales', 'cat.sales', None, {APP: 'SELECT'}))))
            for out in ('a', 'b'):
                self.assertEqual(main([str(source), '--out', str(Path(tmp) / out)]), 0)
            self.assertEqual((Path(tmp) / 'a' / source.name).read_bytes(), (Path(tmp) / 'b' / source.name).read_bytes())

    def test_committed_fixtures_hold_only_allowlisted_data(self):
        files = sorted(REAL.glob('*.json'))
        self.assertTrue(files)
        for path in files:
            text = path.read_text(encoding='utf-8')
            self.assertEqual(leftovers(text, {}), [], path.name)
            if path.name.endswith('.plan.json'):
                for rc in json.loads(text)['resource_changes']:
                    for side in ('before', 'after'):
                        self.assertLessEqual(set(rc['change'][side] or {}), set(attributes(rc['type'])), path.name)
