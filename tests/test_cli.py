import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reachdiff.cli import main
from tests.plans import grants, moved, plan, secret

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / 'examples' / 'schema-grant.plan.json'


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_example_reproduces_the_design_table(self):
        code, out, _ = run('plan', '--tfplan', EXAMPLE, '--offline')
        self.assertEqual(code, 0)
        self.assertIn('reachdiff: WARN (offline mode, SYNTHETIC FIXTURE)', out)
        self.assertIn('+ analysts (3 members, 2 new, 1 already had it)  READ  prod.sales (all tables)', out)
        self.assertIn('- bob@example.com  WRITE  prod.sales.orders', out)

    def test_fail_on_controls_the_exit_code(self):
        self.assertEqual(run('plan', '--tfplan', EXAMPLE, '--offline', '--fail-on', 'warn')[0], 1)
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'reachdiff.toml'
            config.write_text('[builtin]\nunverified = "BLOCK"\n')
            self.assertEqual(run('plan', '--tfplan', EXAMPLE, '--offline', '--config', config)[0], 2)
            self.assertEqual(
                run('plan', '--tfplan', EXAMPLE, '--offline', '--config', config, '--fail-on', 'never')[0], 0
            )

    def test_invalid_input_is_exit_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad_config = Path(tmp) / 'bad.toml'
            bad_config.write_text('fail_om = "warn"\n')
            bad_plan = Path(tmp) / 'bad.json'
            bad_plan.write_text('{"format_version": "2.0"}')
            self.assertEqual(run('plan', '--tfplan', EXAMPLE, '--offline', '--config', bad_config)[0], 3)
            self.assertEqual(run('plan', '--tfplan', bad_plan, '--offline')[0], 3)
            self.assertEqual(run('plan', '--tfplan', bad_plan, '--offline', '--fail-on', 'never')[0], 3)
        self.assertEqual(run('plan')[0], 3)

    def test_malformed_values_and_unexpected_errors_are_exit_3_without_details(self):
        bad = grants('databricks_grants.sales', 'prod.sales', None, {'finance': 'SELECT'})
        bad['change']['after'] = 'not-an-object'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'plan.json'
            path.write_text(json.dumps(plan(bad)))
            self.assertEqual(
                run('plan', '--tfplan', path, '--offline'),
                (
                    3,
                    '',
                    'reachdiff: error: '
                    'databricks_grants.sales: change.before and change.after must be objects or null\n',
                ),
            )
        with mock.patch('reachdiff.cli.read_plan', side_effect=KeyError('s3cr3t-detail')):
            self.assertEqual(
                run('plan', '--tfplan', EXAMPLE, '--offline'), (3, '', 'reachdiff: error: unexpected KeyError\n')
            )

    def test_deep_cannot_be_combined_with_offline(self):
        self.assertEqual(
            run('plan', '--tfplan', EXAMPLE, '--offline', '--deep'),
            (3, '', 'reachdiff: error: --deep needs live mode; it cannot be combined with --offline\n'),
        )

    def test_live_mode_needs_a_pinned_login(self):
        with (
            mock.patch.dict('os.environ', {}, clear=True),
            mock.patch('reachdiff.collect.live.collect_live') as collect,
        ):
            self.assertEqual(
                run('plan', '--tfplan', EXAMPLE),
                (
                    3,
                    '',
                    'reachdiff: error: live mode needs --profile '
                    'or DATABRICKS_AUTH_TYPE, so a missing credential cannot fall back to another login\n',
                ),
            )
            collect.assert_not_called()
        for name in ('DATABRICKS_AUTH_TYPE', 'DATABRICKS_CONFIG_PROFILE'):
            with (
                mock.patch.dict('os.environ', {name: 'set'}, clear=True),
                mock.patch('reachdiff.collect.live.collect_live', side_effect=RuntimeError('stub')) as collect,
            ):
                self.assertEqual(run('plan', '--tfplan', EXAMPLE), (3, '', 'reachdiff: error: stub\n'))
                collect.assert_called_once()

    def test_secrets_in_unrelated_resources_never_reach_any_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'plan.json'
            path.write_text(
                json.dumps(
                    plan(
                        secret('databricks_secret.token', 's3cr3t-value-123'),
                        grants('databricks_grants.prod', 'prod', None, {'bob@example.com': 'USE_CATALOG'}),
                    )
                )
            )
            for fmt in ('text', 'json', 'md'):
                code, out, err = run('plan', '--tfplan', path, '--offline', '--format', fmt)
                self.assertEqual(code, 0)
                self.assertNotIn('s3cr3t-value-123', out + err)

    def test_moving_a_grant_resource_loses_the_old_object_and_gains_the_new_one(self):
        def usage(address, securable, privilege):
            return grants(address, securable, {'account users': privilege}, {'account users': privilege})

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'plan.json'
            path.write_text(
                json.dumps(
                    plan(
                        usage('databricks_grants.prod', 'prod', 'USE_CATALOG'),
                        usage('databricks_grants.sales', 'prod.sales', 'USE_SCHEMA'),
                        usage('databricks_grants.hr', 'prod.hr', 'USE_SCHEMA'),
                        moved('databricks_grants.x', 'prod.sales.orders', 'prod.hr.salaries', {'finance': 'SELECT'}),
                    )
                )
            )
            _, out, _ = run('plan', '--tfplan', path, '--offline', '--format', 'json')
        report = json.loads(out)
        self.assertNotEqual(report['status'], 'PASS')
        self.assertEqual(
            [(c['direction'], c['principal'], c['level'], c['securable']) for c in report['changes']],
            [('+', 'finance', 'READ', 'prod.hr.salaries'), ('-', 'finance', 'READ', 'prod.sales.orders')],
        )

    def test_markdown_to_an_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'report.md'
            code, out, _ = run('plan', '--tfplan', EXAMPLE, '--offline', '--format', 'md', '--output', target)
            self.assertEqual((code, out), (0, ''))
            self.assertIn(
                '| + | analysts (3 members, 2 new, 1 already had it) | READ | prod.sales (all tables) |',
                target.read_text(),
            )

    def test_plan_config_and_output_files_use_utf8_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, target = Path(tmp) / 'reachdiff.toml', Path(tmp) / 'report.md'
            config.write_text('fail_on = "never"\n', encoding='utf-8')
            result = subprocess.run(
                [
                    sys.executable,
                    '-X',
                    'warn_default_encoding',
                    '-W',
                    'error::EncodingWarning',
                    '-m',
                    'reachdiff',
                    'plan',
                    '--tfplan',
                    str(EXAMPLE),
                    '--offline',
                    '--config',
                    str(config),
                    '--output',
                    str(target),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding='utf-8',
            )
        self.assertEqual((result.returncode, result.stderr), (0, ''))
