"""Sanitized real plans from the Azure live sessions (1 and 2 October 2026), run offline end to end.

Each test asserts what the plan decides and the live session confirmed (local results, M1a re-check).
"""

import contextlib
import io
import json
import unittest
from pathlib import Path

from reachdiff.cli import main

REAL = Path(__file__).resolve().parent / 'fixtures' / 'real'
ETL = '00000000-0000-4000-8000-000000000001'  # gp-etl's application ID


def run(name, *args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(['plan', '--tfplan', str(REAL / f'{name}.plan.json'), '--offline', '--format', 'json', *args])
    return code, json.loads(out.getvalue())


def rows(report):
    return [
        (
            c['direction'],
            c['principal'],
            c['level'],
            c['securable'],
            c['members'] and (c['members']['total'], c['members']['changed'], c['members']['unchanged']),
        )
        for c in report['changes']
    ]


class ScenarioTests(unittest.TestCase):
    def test_s1_a_group_gain_counts_members_who_already_had_it(self):
        code, report = run('S1')
        self.assertEqual((code, report['status']), (0, 'WARN'))
        self.assertEqual(
            rows(report),
            [
                ('+', 'gp-analysts', 'READ', 'gp_validation.sales', (2, 1, 1)),
                ('+', 'gp-interns', 'READ', 'gp_validation.sales', (1, 1, 0)),
            ],
        )
        self.assertIn('latent_grants', {g['category'] for g in report['gaps']})

    def test_s3_a_principal_grant_replaces_its_privileges(self):
        _, report = run('S3')
        self.assertEqual(
            rows(report),
            [
                ('-', ETL, 'READ', 'gp_validation.sales.customers', None),
                ('-', ETL, 'WRITE', 'gp_validation.sales.customers', None),
            ],
        )

    def test_s5_ownership_moves_to_a_user(self):
        _, report = run('S5')
        self.assertEqual(
            rows(report),
            [
                ('-', 'gp-pii-readers', 'MANAGE', 'gp_validation.hr.salaries', (1, 0, 1)),
                ('-', 'gp-pii-readers', 'WRITE', 'gp_validation.hr.salaries', (1, 0, 1)),
            ],
        )
        self.assertIn('individual_owner', {f['rule'] for f in report['findings']})
        self.assertEqual(
            report['changes'][1]['via'],
            ['OWNER on gp_validation.hr.salaries + USE_CATALOG on gp_validation + USE_SCHEMA on gp_validation.hr'],
        )

    def test_s7_moving_grants_between_resource_types_blocks(self):
        code, report = run('S7')
        self.assertEqual((code, report['status'], report['changes']), (2, 'BLOCK', []))
        self.assertIn(
            ('BLOCK', 'grant_resource_conflict', 'gp_validation.hr.salaries'),
            {(f['severity'], f['rule'], f['subject']) for f in report['findings']},
        )

    def test_s9_a_change_of_name_case_only_passes(self):
        code, report = run('S9')
        self.assertEqual((code, report['status'], report['changes'], report['findings']), (0, 'PASS', [], []))
