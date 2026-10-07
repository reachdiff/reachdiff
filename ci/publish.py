"""Publish a reachdiff Markdown report in CI: run summary, warning, outputs and one pull-request comment.

The GitHub Action and the Azure DevOps template run this after reachdiff, which itself never posts anywhere.
Standard library only; it is not installed with the package.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HEADER = re.compile(r'## reachdiff: (PASS|WARN|BLOCK)')
KEY = re.compile(r'[A-Za-z0-9._-]+')
DEFAULT_BOT = 'github-actions[bot]'  # the author of comments posted with the default GITHUB_TOKEN


class PublishError(Exception):
    """A failed API call. The message holds only the method, the path and the status, never a body or token."""


def status_of(report: str | None, exit_code: int) -> str:
    if exit_code == 3 or report is None:
        return 'ERROR'
    match = HEADER.fullmatch(report.split('\n', 1)[0])
    return match.group(1) if match else 'ERROR'


def comment_body(marker: str, status: str, report: str | None, limit: int) -> str:
    if status == 'ERROR':
        return f'{marker}\n## reachdiff: ERROR\n\nThe check failed; see the run log.\n'
    body = f'{marker}\n{report}'
    if len(body) <= limit:
        return body
    return (
        f'{marker}\n## reachdiff: {status}\n\nThe report is too long for a comment ({len(report)} characters); '
        'it is in the run summary.\n'
    )


def urllib_http(token: str):
    def http(method: str, url: str, body: dict | None = None):
        request = urllib.request.Request(
            url,
            method=method,
            data=None if body is None else json.dumps(body).encode('utf-8'),
            headers={
                'Authorization': f'Bearer {token}',
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'User-Agent': 'reachdiff-ci',
            },
        )
        path = urllib.parse.urlsplit(url).path
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                text = response.read().decode('utf-8')
        except urllib.error.HTTPError as exc:
            raise PublishError(f'{method} {path} {exc.code}') from None
        except OSError:
            raise PublishError(f'{method} {path} unreachable') from None
        return json.loads(text) if text else None

    return http


class GitHub:
    limit = 65536

    def __init__(self, env, http):
        self.env, self.http = env, http
        self.event = json.loads(Path(env['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
        self.issues = f'{env.get("GITHUB_API_URL", "https://api.github.com")}/repos/{env["GITHUB_REPOSITORY"]}/issues'

    def private(self) -> bool:
        return (self.event.get('repository') or {}).get('visibility') == 'private'

    def summary(self, path: Path, report: str) -> None:
        with open(self.env['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as handle:
            handle.write(report + '\n')

    def outputs(self, status: str, code: int, path: Path) -> None:
        with open(self.env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as handle:
            handle.write(f'status={status}\nexit-code={code}\nreport-path={path}\n')

    def warn(self) -> None:
        print('::warning::reachdiff: WARN')

    def pull_request(self) -> tuple[int | None, str]:
        name, pr = self.env.get('GITHUB_EVENT_NAME'), self.event.get('pull_request') or {}
        if name not in ('pull_request', 'pull_request_target') or 'number' not in pr:
            return None, 'not a pull request run'
        head = ((pr.get('head') or {}).get('repo') or {}).get('full_name')
        if name == 'pull_request_target' and head != self.event['repository']['full_name']:
            return None, 'pull_request_target from a fork'
        return pr['number'], ''

    def post(self, number: int, marker: str, body: str, failed: bool) -> None:
        try:
            login = self.http('GET', f'{self.env.get("GITHUB_API_URL", "https://api.github.com")}/user')['login']
        except PublishError:  # the default GITHUB_TOKEN cannot read /user
            login = DEFAULT_BOT
        page = 1
        while True:
            comments = self.http('GET', f'{self.issues}/{number}/comments?per_page=100&page={page}')
            for comment in comments:
                if comment['body'].startswith(marker) and comment['user']['login'] == login:
                    self.http('PATCH', f'{self.issues}/comments/{comment["id"]}', {'body': body})
                    return
            if len(comments) < 100:
                break
            page += 1
        self.http('POST', f'{self.issues}/{number}/comments', {'body': body})


class AzureDevOps:
    limit = 150000

    def __init__(self, env, http):
        self.env, self.http = env, http
        self.collection, self.project = env['SYSTEM_COLLECTIONURI'], env['SYSTEM_TEAMPROJECTID']

    def private(self) -> bool:
        try:
            project = self.http('GET', f'{self.collection}_apis/projects/{self.project}?api-version=7.1')
            return project['visibility'] == 'private'
        except (PublishError, KeyError, TypeError):
            return False

    def summary(self, path: Path, report: str) -> None:
        print(f'##vso[task.uploadsummary]{path}')

    def outputs(self, status: str, code: int, path: Path) -> None:
        for name, value in (('status', status), ('exitCode', code), ('reportPath', path)):
            print(f'##vso[task.setvariable variable={name};isOutput=true]{value}')

    def warn(self) -> None:
        print('##vso[task.logissue type=warning]reachdiff: WARN')
        print('##vso[task.complete result=SucceededWithIssues;]reachdiff: WARN')

    def pull_request(self) -> tuple[str | None, str]:
        number = self.env.get('SYSTEM_PULLREQUEST_PULLREQUESTID')
        if not number:
            return None, 'not a pull request run'
        if self.env.get('BUILD_REPOSITORY_PROVIDER') != 'TfsGit':
            return None, 'the repository is not in Azure Repos'
        return number, ''

    def post(self, number: str, marker: str, body: str, failed: bool) -> None:
        me = self.http('GET', f'{self.collection}_apis/connectionData')['authenticatedUser']['id']
        threads = (
            f'{self.collection}{self.project}/_apis/git/repositories/{self.env["BUILD_REPOSITORY_ID"]}'
            f'/pullRequests/{number}/threads'
        )
        status = 'active' if failed else 'closed'
        for thread in self.http('GET', f'{threads}?api-version=7.1')['value']:
            first = (thread.get('comments') or [{}])[0]
            if first.get('content', '').startswith(marker) and (first.get('author') or {}).get('id') == me:
                self.http(
                    'PATCH', f'{threads}/{thread["id"]}/comments/{first["id"]}?api-version=7.1', {'content': body}
                )
                self.http('PATCH', f'{threads}/{thread["id"]}?api-version=7.1', {'status': status})
                return
        self.http(
            'POST',
            f'{threads}?api-version=7.1',
            {'comments': [{'parentCommentId': 0, 'content': body, 'commentType': 1}], 'status': status},
        )


def _key(text: str) -> str:
    if not KEY.fullmatch(text):
        raise argparse.ArgumentTypeError('use letters, digits, ".", "_" or "-"')
    return text


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='publish.py', description='Publish a reachdiff Markdown report in CI.')
    parser.add_argument('platform', choices=('github', 'azure-devops'))
    parser.add_argument('--report', required=True, type=Path, help='reachdiff --format md output')
    parser.add_argument('--exit-code', required=True, type=int, help="reachdiff's exit code")
    parser.add_argument('--key', default='default', type=_key, help='separates comments for several plans')
    parser.add_argument('--comment', action='store_true', help='post or update the pull-request comment')
    parser.add_argument('--allow-public', action='store_true', help='publish even if the repository is not private')
    return parser


def _publish(site, args, report: str | None, status: str) -> int:
    code = 3 if status == 'ERROR' else args.exit_code
    if not (args.allow_public or site.private()):
        print(f'reachdiff: {status} (report withheld: the repository is not private)')
        return code
    print(f'reachdiff: {status}')
    if status != 'ERROR':
        site.summary(args.report, report)
    if not args.comment:
        return code
    number, reason = site.pull_request()
    if number is None:
        print(f'reachdiff: no comment ({reason})')
        return code
    marker = f'<!-- reachdiff key={args.key} -->'
    try:
        site.post(number, marker, comment_body(marker, status, report, site.limit), failed=code != 0)
    except PublishError as exc:
        print(f'reachdiff: comment failed: {exc}', file=sys.stderr)
        return 3
    return code


def main(argv: list[str] | None = None, env: dict[str, str] | None = None, http=None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # argparse uses 2 for usage errors; 2 means BLOCK here
        return 0 if exc.code == 0 else 3
    try:
        env = dict(os.environ) if env is None else env
        token = env.get('GH_TOKEN' if args.platform == 'github' else 'SYSTEM_ACCESSTOKEN', '')
        site = (GitHub if args.platform == 'github' else AzureDevOps)(env, http or urllib_http(token))
        report = args.report.read_text(encoding='utf-8') if args.report.is_file() else None
        status = status_of(report, args.exit_code)
        code = _publish(site, args, report, status)
        site.outputs(status, code, args.report)
        if status == 'WARN' and code == 0:
            site.warn()
        return code
    except Exception as exc:  # never exit 1 or 2, which mean WARN and BLOCK
        print(f'reachdiff: error: unexpected {type(exc).__name__}', file=sys.stderr)
        return 3


if __name__ == '__main__':
    sys.exit(main())
