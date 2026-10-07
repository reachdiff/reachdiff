"""Load and validate reachdiff TOML. Unknown keys are errors, so a typo cannot disable a rule."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from reachdiff.resolve import LEVELS

BUILTIN_RULES = (
    'broad_principal',
    'broad_privilege',
    'grant_resource_conflict',
    'individual_owner',
    'sensitive_access',
    'unverified',
)
BUILTIN_DEFAULTS = {'grant_resource_conflict': 'BLOCK'}  # every other built-in rule defaults to WARN
SEVERITIES = ('WARN', 'BLOCK')
PRINCIPAL_KINDS = ('user', 'service_principal', 'group', 'unknown')
DEFAULT_TAGS = ('pii*', 'sensitive*', 'class.*')
RULE_KEYS = ('id', 'severity', 'message', 'when', 'levels', 'objects', 'principal_kinds', 'sensitive', 'unless_via')


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    message: str
    when: str = 'gain'
    levels: frozenset[str] = frozenset()
    objects: tuple[str, ...] = ()
    principal_kinds: frozenset[str] = frozenset()
    sensitive: bool | None = None
    unless_via: frozenset[str] = frozenset()


def builtin_defaults() -> dict[str, str]:
    return {rule: BUILTIN_DEFAULTS.get(rule, 'WARN') for rule in BUILTIN_RULES}


@dataclass(frozen=True)
class Config:
    fail_on: str = 'block'
    sensitive_tags: tuple[str, ...] = DEFAULT_TAGS
    builtin: dict[str, str] = field(default_factory=builtin_defaults)
    limit_objects: int = 500
    limit_members: int = 5000
    limit_deep_children: int = 1000
    rules: tuple[Rule, ...] = ()


def _keys(table: object, allowed: tuple[str, ...], where: str) -> dict:
    if not isinstance(table, dict):
        raise ValueError(f'{where} must be a table')
    unknown = sorted(set(table) - set(allowed))
    if unknown:
        raise ValueError(f'unknown config key in {where}: {", ".join(unknown)}')
    return table


def _strings(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ValueError(f'{where} must be a list of nonempty strings')
    return tuple(value)


def _choice(value: object, choices: tuple[str, ...], where: str) -> str:
    if value not in choices:
        raise ValueError(f'{where} must be one of {", ".join(choices)}')
    return value


def _rule(raw: object, index: int) -> Rule:
    where = f'rule[{index}]'
    raw = _keys(raw, RULE_KEYS, where)
    for key in ('id', 'message'):
        if not isinstance(raw.get(key), str) or not raw[key]:
            raise ValueError(f'{where}.{key} is required')
    sensitive = raw.get('sensitive')
    if sensitive is not None and type(sensitive) is not bool:
        raise ValueError(f'{where}.sensitive must be true or false')
    levels = _strings(raw.get('levels', []), f'{where}.levels')
    kinds = _strings(raw.get('principal_kinds', []), f'{where}.principal_kinds')
    for value in levels:
        _choice(value, LEVELS, f'{where}.levels')
    for value in kinds:
        _choice(value, PRINCIPAL_KINDS, f'{where}.principal_kinds')
    return Rule(
        raw['id'],
        _choice(raw.get('severity'), SEVERITIES, f'{where}.severity'),
        raw['message'],
        _choice(raw.get('when', 'gain'), ('gain', 'lose', 'any'), f'{where}.when'),
        frozenset(levels),
        _strings(raw.get('objects', []), f'{where}.objects'),
        frozenset(kinds),
        sensitive,
        frozenset(_strings(raw.get('unless_via', []), f'{where}.unless_via')),
    )


def parse_config(data: dict) -> Config:
    _keys(data, ('fail_on', 'sensitive', 'builtin', 'limits', 'rule'), 'config')
    fail_on = _choice(data.get('fail_on', 'block'), ('block', 'warn', 'never'), 'fail_on')
    sensitive = _keys(data.get('sensitive', {}), ('tags',), '[sensitive]')
    tags = _strings(sensitive.get('tags', list(DEFAULT_TAGS)), 'sensitive.tags')
    builtin = builtin_defaults()
    for name, value in _keys(data.get('builtin', {}), BUILTIN_RULES, '[builtin]').items():
        allowed = SEVERITIES if name == 'unverified' else SEVERITIES + ('off',)
        builtin[name] = _choice(value, allowed, f'builtin.{name}')
    limits = _keys(data.get('limits', {}), ('objects', 'members', 'deep_children'), '[limits]')
    values = {}
    for key, default in (('objects', 500), ('members', 5000), ('deep_children', 1000)):
        value = limits.get(key, default)
        if type(value) is not int or value < 1:
            raise ValueError(f'limits.{key} must be a positive integer')
        values[key] = value
    raw_rules = data.get('rule', [])
    if not isinstance(raw_rules, list):
        raise ValueError('rule must be an array of tables ([[rule]])')
    rules = tuple(_rule(raw, i) for i, raw in enumerate(raw_rules))
    ids = [r.id for r in rules]
    if len(set(ids)) != len(ids) or set(ids) & set(BUILTIN_RULES):
        raise ValueError('rule ids must be unique and must not reuse built-in rule names')
    return Config(fail_on, tags, builtin, values['objects'], values['members'], values['deep_children'], rules)


def load_config(path: Path | None) -> Config:
    if path is None:
        return Config()
    try:
        return parse_config(tomllib.loads(path.read_text(encoding='utf-8')))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f'invalid config TOML: {exc}') from None
