import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from ci.publish import PublishError, main

MARKER = '<!-- reachdiff key=default -->'
REPORT = '## reachdiff: WARN\n\n_live mode_\n\n| rows |\n'
GITHUB = 'https://api.test/repos/me/repo/issues'
THREADS = 'https://dev.test/org/project-id/_apis/git/repositories/repo-id/pullRequests/7/threads'
FORBIDDEN = PublishError('GET /user 403')


class FakeHttp:
    """Answers by (method, URL substring) in order; any other request fails the test."""

    def __init__(self, *answers):
        self.answers, self.calls = answers, []

    def __call__(self, method, url, body=None):
        self.calls.append((method, url, body))
        for verb, part, answer in self.answers:
            if verb == method and part in url:
                if isinstance(answer, Exception):
                    raise answer
                return answer
        raise AssertionError(f'unexpected request {method} {url}')

    def writes(self):
        return [(method, url, body) for method, url, body in self.calls if method != 'GET']


def github_env(tmp: Path, visibility='private', event='pull_request', head='me/repo'):
    repository = {'full_name': 'me/repo'}
    if visibility is not None:
        repository['visibility'] = visibility
    payload = {'repository': repository, 'pull_request': {'number': 7, 'head': {'repo': {'full_name': head}}}}
    (tmp / 'event.json').write_text(json.dumps(payload), encoding='utf-8')
    return {
        'GITHUB_EVENT_PATH': str(tmp / 'event.json'),
        'GITHUB_EVENT_NAME': event,
        'GITHUB_REPOSITORY': 'me/repo',
        'GITHUB_API_URL': 'https://api.test',
        'GITHUB_STEP_SUMMARY': str(tmp / 'summary.md'),
        'GITHUB_OUTPUT': str(tmp / 'output.txt'),
    }


def ado_env():
    return {
        'SYSTEM_COLLECTIONURI': 'https://dev.test/org/',
        'SYSTEM_TEAMPROJECTID': 'project-id',
        'BUILD_REPOSITORY_ID': 'repo-id',
        'BUILD_REPOSITORY_PROVIDER': 'TfsGit',
        'SYSTEM_PULLREQUEST_PULLREQUESTID': '7',
    }


def publish(platform, tmp: Path, env, http, *flags, report=REPORT, exit_code=0):
    path = tmp / 'report.md'
    if report is not None:
        path.write_text(report, encoding='utf-8')
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([platform, '--report', str(path), '--exit-code', str(exit_code), *flags], env=env, http=http)
    return code, out.getvalue(), err.getvalue()


class GitHubTests(unittest.TestCase):
    def test_updates_its_own_comment_and_ignores_a_quote_by_someone_else(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            http = FakeHttp(
                ('GET', '/user', FORBIDDEN),
                (
                    'GET',
                    '/issues/7/comments',
                    [
                        {'id': 1, 'body': f'{MARKER}\nquoted', 'user': {'login': 'someone'}},
                        {'id': 2, 'body': f'{MARKER}\nold', 'user': {'login': 'github-actions[bot]'}},
                    ],
                ),
                ('PATCH', '/issues/comments/2', {}),
            )
            code, out, _ = publish('github', tmp, github_env(tmp), http, '--comment')
            self.assertEqual(code, 0)
            self.assertEqual(http.writes(), [('PATCH', f'{GITHUB}/comments/2', {'body': f'{MARKER}\n{REPORT}'})])
            self.assertEqual(out, 'reachdiff: WARN\n::warning::reachdiff: WARN\n')
            self.assertEqual((tmp / 'summary.md').read_text(encoding='utf-8'), REPORT + '\n')
            self.assertEqual(
                (tmp / 'output.txt').read_text(encoding='utf-8'),
                f'status=WARN\nexit-code=0\nreport-path={tmp / "report.md"}\n',
            )

    def test_reads_every_page_then_creates_a_comment(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            foreign = [{'id': n, 'body': 'hello', 'user': {'login': 'someone'}} for n in range(100)]
            http = FakeHttp(
                ('GET', '/user', FORBIDDEN),
                ('GET', '&page=1', foreign),
                ('GET', '&page=2', []),
                ('POST', '/issues/7/comments', {}),
            )
            self.assertEqual(publish('github', tmp, github_env(tmp), http, '--comment')[0], 0)
            self.assertEqual(http.writes(), [('POST', f'{GITHUB}/7/comments', {'body': f'{MARKER}\n{REPORT}'})])

    def test_no_comment_on_pull_request_target_from_a_fork(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            env = github_env(tmp, event='pull_request_target', head='fork/repo')
            code, out, _ = publish('github', tmp, env, FakeHttp(), '--comment')
            self.assertEqual(code, 0)
            self.assertIn('reachdiff: no comment (pull_request_target from a fork)\n', out)


class AzureDevOpsTests(unittest.TestCase):
    def test_updates_its_own_thread_and_marks_a_failure_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            http = FakeHttp(
                ('GET', '_apis/projects/project-id', {'visibility': 'private'}),
                ('GET', '_apis/connectionData', {'authenticatedUser': {'id': 'me'}}),
                (
                    'GET',
                    '/threads',
                    {
                        'value': [
                            {'id': 5, 'comments': [{'id': 1, 'content': f'{MARKER}\nq', 'author': {'id': 'other'}}]},
                            {'id': 6, 'comments': [{'id': 1, 'content': f'{MARKER}\nold', 'author': {'id': 'me'}}]},
                        ]
                    },
                ),
                ('PATCH', '/threads/6', {}),
            )
            report = REPORT.replace('WARN', 'BLOCK')
            code, out, _ = publish('azure-devops', Path(tmp), ado_env(), http, '--comment', report=report, exit_code=2)
            self.assertEqual(code, 2)
            self.assertEqual(
                http.writes(),
                [
                    ('PATCH', f'{THREADS}/6/comments/1?api-version=7.1', {'content': f'{MARKER}\n{report}'}),
                    ('PATCH', f'{THREADS}/6?api-version=7.1', {'status': 'active'}),
                ],
            )
            self.assertIn(f'##vso[task.uploadsummary]{Path(tmp) / "report.md"}\n', out)
            self.assertIn('##vso[task.setvariable variable=status;isOutput=true]BLOCK\n', out)
            self.assertNotIn('SucceededWithIssues', out)

    def test_creates_a_closed_thread_and_succeeds_with_issues_on_warn(self):
        with tempfile.TemporaryDirectory() as tmp:
            http = FakeHttp(
                ('GET', '_apis/projects/project-id', {'visibility': 'private'}),
                ('GET', '_apis/connectionData', {'authenticatedUser': {'id': 'me'}}),
                ('GET', '/threads', {'value': []}),
                ('POST', '/threads', {}),
            )
            code, out, _ = publish('azure-devops', Path(tmp), ado_env(), http, '--comment')
            self.assertEqual(code, 0)
            self.assertEqual(
                http.writes(),
                [
                    (
                        'POST',
                        f'{THREADS}?api-version=7.1',
                        {
                            'comments': [{'parentCommentId': 0, 'content': f'{MARKER}\n{REPORT}', 'commentType': 1}],
                            'status': 'closed',
                        },
                    )
                ],
            )
            self.assertTrue(out.endswith('##vso[task.complete result=SucceededWithIssues;]reachdiff: WARN\n'))


class GuardTests(unittest.TestCase):
    def test_reports_are_withheld_unless_the_repository_is_private(self):
        withheld = 'reachdiff: WARN (report withheld: the repository is not private)\n'
        for visibility in ('public', 'internal', None):
            with self.subTest(visibility=visibility), tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                http = FakeHttp()
                code, out, _ = publish('github', tmp, github_env(tmp, visibility), http, '--comment')
                self.assertEqual((code, out.split('::')[0], http.calls), (0, withheld, []))
                self.assertFalse((tmp / 'summary.md').exists())
        with tempfile.TemporaryDirectory() as tmp:
            http = FakeHttp(('GET', '_apis/projects/', PublishError('GET /org/_apis/projects/project-id 401')))
            code, out, _ = publish('azure-devops', Path(tmp), ado_env(), http, '--comment')
            self.assertEqual((code, out.split('##vso')[0]), (0, withheld))
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            http = FakeHttp(
                ('GET', '/user', FORBIDDEN), ('GET', '/issues/7/comments', []), ('POST', '/issues/7/comments', {})
            )
            env = github_env(tmp, 'public')
            self.assertEqual(publish('github', tmp, env, http, '--comment', '--allow-public')[0], 0)
            self.assertEqual(len(http.writes()), 1)
            self.assertTrue((tmp / 'summary.md').exists())

    def test_long_reports_errors_and_failed_posts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            long = REPORT + 'x' * 70000
            http = FakeHttp(
                ('GET', '/user', FORBIDDEN), ('GET', '/issues/7/comments', []), ('POST', '/issues/7/comments', {})
            )
            publish('github', tmp, github_env(tmp), http, '--comment', report=long)
            self.assertEqual(
                http.writes()[0][2]['body'],
                f'{MARKER}\n## reachdiff: WARN\n\nThe report is too long '
                f'for a comment ({len(long)} characters); it is in the run summary.\n',
            )
        for report, exit_code in ((None, 3), ('not a report\n', 0)):
            with self.subTest(report=report), tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                http = FakeHttp(
                    ('GET', '/user', FORBIDDEN), ('GET', '/issues/7/comments', []), ('POST', '/issues/7/comments', {})
                )
                code, out, _ = publish(
                    'github', tmp, github_env(tmp), http, '--comment', report=report, exit_code=exit_code
                )
                self.assertEqual((code, out), (3, 'reachdiff: ERROR\n'))
                self.assertEqual(
                    http.writes()[0][2]['body'],
                    f'{MARKER}\n## reachdiff: ERROR\n\nThe check failed; see the run log.\n',
                )
                self.assertFalse((tmp / 'summary.md').exists())
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            http = FakeHttp(
                ('GET', '/user', FORBIDDEN),
                ('GET', '/issues/7/comments', []),
                ('POST', '/issues/7/comments', PublishError('POST /repos/me/repo/issues/7/comments 403')),
            )
            code, _, err = publish('github', tmp, github_env(tmp), http, '--comment')
            self.assertEqual((code, err), (3, 'reachdiff: comment failed: POST /repos/me/repo/issues/7/comments 403\n'))
            self.assertIn('exit-code=3\n', (tmp / 'output.txt').read_text(encoding='utf-8'))

    def test_bad_arguments_are_exit_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            self.assertEqual(publish('github', tmp, github_env(tmp), FakeHttp(), '--key', 'a -->')[0], 3)
