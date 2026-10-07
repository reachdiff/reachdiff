"""Build synthetic `terraform show -json` documents. Shapes follow Terraform's JSON output format 1.x."""

ATTRS = ('catalog', 'schema', 'table')


def _change(
    address,
    rtype,
    before,
    after,
    *,
    actions=None,
    after_unknown=None,
    before_sensitive=None,
    after_sensitive=None,
    mode='managed',
):
    if actions is None:
        actions = (
            ['create']
            if before is None
            else ['delete']
            if after is None
            else ['no-op']
            if before == after
            else ['update']
        )
    return {
        'address': address,
        'mode': mode,
        'type': rtype,
        'name': address.split('.')[-1],
        'change': {
            'actions': actions,
            'before': before,
            'after': after,
            'after_unknown': after_unknown or {},
            'before_sensitive': before_sensitive or {},
            'after_sensitive': after_sensitive or {},
        },
    }


def grants(address, securable, before, after, *, attr=None, **marks):
    """before/after: {principal: 'PRIV PRIV'} or None."""
    attr = attr or ATTRS[securable.count('.')]

    def body(mapping):
        if mapping is None:
            return None
        return {
            attr: securable,
            'grant': [{'principal': p, 'privileges': sorted(v.split())} for p, v in sorted(mapping.items())],
        }

    return _change(address, 'databricks_grants', body(before), body(after), **marks)


def grant(address, securable, principal, before, after, *, attr=None, **marks):
    """before/after: 'PRIV PRIV' or None."""
    attr = attr or ATTRS[securable.count('.')]

    def body(privileges):
        return (
            None
            if privileges is None
            else {attr: securable, 'principal': principal, 'privileges': sorted(privileges.split())}
        )

    return _change(address, 'databricks_grant', body(before), body(after), **marks)


def moved(address, old, new, mapping, *, new_attr=None):
    """A databricks_grants resource whose securable changes from `old` to `new` (replaced)."""
    change = grants(address, old, mapping, mapping)
    change['change']['after'] = grants(address, new, None, mapping, attr=new_attr)['change']['after']
    change['change']['actions'] = ['delete', 'create']
    return change


def member(address, group_id, member_id, before, after, **marks):
    body = {'group_id': group_id, 'member_id': member_id}
    return _change(address, 'databricks_group_member', body if before else None, body if after else None, **marks)


def owner(address, securable, before, after):
    parts = securable.split('.')
    rtype = ('databricks_catalog', 'databricks_schema', 'databricks_sql_table')[len(parts) - 1]

    def body(value):
        values = {'name': parts[-1], 'owner': value}
        if len(parts) >= 2:
            values['catalog_name'] = parts[0]
        if len(parts) == 3:
            values['schema_name'] = parts[1]
        return values

    return _change(address, rtype, body(before), body(after))


def identity(address, rtype, scim_id, name, **marks):
    field = {
        'databricks_group': 'display_name',
        'databricks_user': 'user_name',
        'databricks_service_principal': 'application_id',
    }[rtype]
    body = {'id': scim_id, field: name}
    return _change(address, rtype, body, body, **marks)


def secret(address, value):
    body = {'scope': 'ops', 'key': 'token', 'string_value': value}
    return _change(
        address,
        'databricks_secret',
        body,
        body,
        before_sensitive={'string_value': True},
        after_sensitive={'string_value': True},
    )


def plan(*resources, host=None, synthetic=False, providers=None, prior=None):
    expressions = {'host': {'constant_value': host}} if host else {}
    if providers is None:
        providers = {'databricks': {'name': 'databricks', 'expressions': expressions}}
    data = {
        'format_version': '1.2',
        'terraform_version': '1.9.0',
        'resource_changes': list(resources),
        'configuration': {'provider_config': providers},
    }
    if prior is not None:
        data['prior_state'] = {'values': {'root_module': {'resources': prior}}}
    if synthetic:
        data['reachdiff_fixture'] = 'synthetic'
    return data
