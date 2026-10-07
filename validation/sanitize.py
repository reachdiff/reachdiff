"""Turn real plans and saved API responses into committable test fixtures.

Each document is rebuilt from an allowlist of what reachdiff reads; nothing else is copied. Identifiers become
stable placeholders, and output that still looks like it holds one is not written. Run from the repository root:

    python3 -m validation.sanitize local/validation/S7.plan.json --rename <catalog>=gp_validation --out tests/fixtures/real

Files given in one run share one mapping, so a plan and the responses used with it stay consistent.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from reachdiff.tfplan import IDENTITY_TYPES, RELEVANT

EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
WORKSPACE_HOST = re.compile(r'https://adb-\d+\.\d+\.azuredatabricks\.net')
SECRET = re.compile(r'sk-|ghp_|gho_|AKIA|xox[baprs]-|-----BEGIN|Bearer |dapi[0-9a-f]{8}')
HOST = 'https://adb-0000000000000000.0.azuredatabricks.net'
PLACEHOLDERS = re.compile(r'00000000-0000-4000-8000-\d{12}|user-\d+@example\.com|' + re.escape(HOST))
LEFTOVERS = (
    ('an email address', EMAIL),
    ('a UUID', UUID),
    ('a workspace host', re.compile(r'adb-\d+')),
    ('a long number', re.compile(r'\d{6,}')),
    ('a secret pattern', SECRET),
)
CHANGE_KEYS = ('before', 'after', 'after_unknown', 'before_sensitive', 'after_sensitive')
NESTED = {'grant': ('principal', 'privileges')}
PRIVILEGE_KEYS = ('privilege', 'inherited_from_type', 'inherited_from_name')
TAG_KEYS = ('entity_name', 'entity_type', 'tag_key', 'tag_value', 'source_type', 'inherited')


class Pseudonyms:
    """Real value -> placeholder, numbered in order of first appearance."""

    def __init__(self, renames: dict[str, str]) -> None:
        self.renames = renames
        self.seen: dict[tuple[str, str], str] = {}
        self.counts: dict[str, int] = {}

    def _get(self, kind: str, real: str, make) -> str:
        if (kind, real) not in self.seen:
            self.counts[kind] = self.counts.get(kind, 0) + 1
            self.seen[(kind, real)] = make(self.counts[kind])
        return self.seen[(kind, real)]

    def text(self, value: str) -> str:
        value = EMAIL.sub(lambda m: self._get('email', m.group().lower(), lambda n: f'user-{n}@example.com'), value)
        value = UUID.sub(
            lambda m: self._get('uuid', m.group().lower(), lambda n: f'00000000-0000-4000-8000-{n:012d}'), value
        )
        value = WORKSPACE_HOST.sub(HOST, value)
        if value.isdigit() and len(value) >= 6:
            value = self._get('id', value, lambda n: str(10000 + n))
        return '.'.join(self.renames.get(part, part) for part in value.split('.'))

    def token(self, value: str) -> str:
        return self._get('token', value, lambda n: f'page-{n}')


def _clean(value, names: Pseudonyms):
    if isinstance(value, str):
        return names.text(value)
    if isinstance(value, list):
        return [_clean(v, names) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v, names) for k, v in value.items()}
    return value


def _pick(value, keys: tuple[str, ...]):
    """The listed attributes of a values or marks object, with nested blocks filtered too. Non-objects as is."""
    if not isinstance(value, dict):
        return value
    picked = {}
    for key in keys:
        if key not in value:
            continue
        item = value[key]
        if key in NESTED and isinstance(item, list):
            item = [_pick(block, NESTED[key]) for block in item]
        picked[key] = item
    return picked


def _marked(marks) -> bool:
    if marks is True:
        return True
    if isinstance(marks, dict):
        return any(_marked(m) for m in marks.values())
    return isinstance(marks, list) and any(_marked(m) for m in marks)


def _unmark(values, marks):
    """Attributes Terraform marks sensitive become null. reachdiff never reads them; the marks stay."""
    if marks is True:
        return None
    if not isinstance(values, dict) or not isinstance(marks, dict):
        return values
    return {k: None if _marked(marks.get(k)) else v for k, v in values.items()}


def attributes(rtype: str) -> tuple[str, ...]:
    """The attributes reachdiff reads from a resource type: tfplan's allowlist, or ID and name for identities."""
    return ('id', IDENTITY_TYPES[rtype][1]) if rtype in IDENTITY_TYPES else RELEVANT[rtype]


def _providers(configs: dict) -> dict:
    kept = {}
    for key, config in configs.items():
        if not isinstance(config, dict) or config.get('name') != 'databricks':
            continue
        expressions = config.get('expressions') or {}
        out = {}
        if 'account_id' in expressions:
            out['account_id'] = {}
        host = (expressions.get('host') or {}).get('constant_value')
        if isinstance(host, str):
            out['host'] = {'constant_value': host}
        kept[key] = {'name': 'databricks', 'expressions': out}
    return kept


def _prior(module: dict) -> dict:
    resources = []
    for r in module.get('resources') or []:
        if r.get('type') in IDENTITY_TYPES:
            keys, marks = attributes(r['type']), _pick(r.get('sensitive_values'), attributes(r['type']))
            resources.append(
                {
                    'address': r['address'],
                    'mode': r['mode'],
                    'type': r['type'],
                    'name': r['name'],
                    'values': _unmark(_pick(r.get('values'), keys), marks),
                    'sensitive_values': marks,
                }
            )
    out = {'resources': resources}
    children = [_prior(child) for child in module.get('child_modules') or []]
    if children:
        out['child_modules'] = children
    return out


def sanitize_plan(raw: dict, names: Pseudonyms) -> dict:
    changes = []
    for rc in raw.get('resource_changes') or []:
        if rc.get('type') not in RELEVANT and rc.get('type') not in IDENTITY_TYPES:
            continue
        keys, change = attributes(rc['type']), rc['change']
        kept = {k: _pick(change[k], keys) for k in CHANGE_KEYS if k in change}
        for side in ('before', 'after'):
            if side in kept:
                kept[side] = _unmark(kept[side], kept.get(f'{side}_sensitive'))
        changes.append(
            {
                'address': rc['address'],
                'mode': rc['mode'],
                'type': rc['type'],
                'name': rc['name'],
                'change': {'actions': change['actions'], **kept},
            }
        )
    doc = {
        'format_version': raw['format_version'],
        'terraform_version': raw.get('terraform_version'),
        'reachdiff_fixture': 'sanitized',
        'configuration': {'provider_config': _providers((raw.get('configuration') or {}).get('provider_config') or {})},
        'resource_changes': changes,
    }
    root = ((raw.get('prior_state') or {}).get('values') or {}).get('root_module')
    if root:
        doc['prior_state'] = {'values': {'root_module': _prior(root)}}
    return _clean(doc, names)


def sanitize_response(raw: dict, names: Pseudonyms) -> dict:
    if 'privilege_assignments' in raw:
        doc = {
            'privilege_assignments': [
                {
                    'principal': a.get('principal'),
                    'privileges': [
                        p if isinstance(p, str) else _pick(p, PRIVILEGE_KEYS) for p in a.get('privileges') or []
                    ],
                }
                for a in raw['privilege_assignments']
            ]
        }
    elif 'tag_assignments' in raw:
        doc = {'tag_assignments': [_pick(t, TAG_KEYS) for t in raw['tag_assignments']]}
    elif 'tables' in raw or 'schemas' in raw:
        key = 'tables' if 'tables' in raw else 'schemas'
        doc = {key: [{'full_name': item.get('full_name')} for item in raw[key]]}
    else:
        raise ValueError('not a plan or a supported API response')
    if raw.get('next_page_token'):
        doc['next_page_token'] = names.token(raw['next_page_token'])
    return _clean(doc, names)


def leftovers(text: str, renames: dict[str, str]) -> list[str]:
    """What in the output still looks like a real identifier or secret."""
    rest = PLACEHOLDERS.sub('', text)
    found = [what for what, pattern in LEFTOVERS if pattern.search(rest)]
    if any(real in rest for real in renames):
        found.append('a --rename source name')
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog='python3 -m validation.sanitize',
        description='Rebuild real plans and API responses as committable fixtures.',
    )
    parser.add_argument('files', nargs='+', type=Path)
    parser.add_argument('--out', required=True, type=Path, help='directory for the fixtures')
    parser.add_argument(
        '--rename',
        action='append',
        default=[],
        metavar='REAL=PLACEHOLDER',
        help='a name the patterns cannot recognise, such as the catalog in use',
    )
    args = parser.parse_args(argv)
    renames = {}
    for item in args.rename:
        real, _, placeholder = item.partition('=')
        if not real or not placeholder or '.' in real + placeholder:
            parser.error(f'--rename needs REAL=PLACEHOLDER with single-part names: {item}')
        renames[real] = placeholder
    names, outputs = Pseudonyms(renames), {}
    for path in args.files:
        raw = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(raw, dict):
            print(f'{path.name}: not a JSON object', file=sys.stderr)
            return 1
        try:
            doc = sanitize_plan(raw, names) if 'resource_changes' in raw else sanitize_response(raw, names)
        except ValueError as exc:
            print(f'{path.name}: {exc}', file=sys.stderr)
            return 1
        text = json.dumps(doc, indent=2) + '\n'
        problems = leftovers(text, renames)
        if problems:
            print(f'{path.name}: not written; the output still holds {", ".join(problems)}', file=sys.stderr)
            return 1
        outputs[args.out / path.name] = text
    args.out.mkdir(parents=True, exist_ok=True)
    for target, text in outputs.items():
        target.write_text(text, encoding='utf-8')
    return 0


if __name__ == '__main__':
    sys.exit(main())
