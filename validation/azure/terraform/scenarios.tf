# Scenario data. Keys name principals and objects (see the maps below). Privileges are space-separated so every
# scenario has the same shape. Each scenario is the baseline plus overrides; ../predictions.md says what each tests.

locals {
  groups             = { analysts = "gp-analysts", pii_readers = "gp-pii-readers", interns = "gp-interns", unassigned = "gp-unassigned" }
  service_principals = { etl = "gp-etl", scanner = "gp-scanner" }

  # Grants name groups by display name, service principals by application ID and users by user name.
  names = merge(
    { for k, g in databricks_group.this : k => g.display_name },
    { for k, sp in databricks_service_principal.this : k => sp.application_id },
    { operator = var.operator },
  )
  ids = merge(
    { for k, g in databricks_group.this : k => g.id },
    { for k, sp in databricks_service_principal.this : k => sp.id },
    { operator = data.databricks_user.operator.id },
  )

  catalog = var.catalog_mode == "new" ? one(databricks_catalog.this[*].name) : var.existing_catalog
  tables = {
    orders    = { schema = "sales", columns = ["id", "amount"] }
    customers = { schema = "sales", columns = ["id", "email"] }
    salaries  = { schema = "hr", columns = ["id", "salary"] }
  }
  objects = {
    catalog   = { kind = "catalog", name = local.catalog }
    sales     = { kind = "schema", name = databricks_schema.this["sales"].id }
    hr        = { kind = "schema", name = databricks_schema.this["hr"].id }
    orders    = { kind = "table", name = databricks_sql_table.this["orders"].id }
    customers = { kind = "table", name = databricks_sql_table.this["customers"].id }
    salaries  = { kind = "table", name = databricks_sql_table.this["salaries"].id }
  }
  # S9 spells the sales schema with a capital letter in its grant resource only (Q7).
  securable = merge({ for k, o in local.objects : k => o.name },
  { for k, v in { sales = "${local.catalog}.Sales" } : k => v if var.scenario == "S9" })

  scanner_privileges = ["", "BROWSE", "READ_METADATA", "BROWSE READ_METADATA USE_CATALOG USE_SCHEMA"][var.scanner_stage]

  baseline = {
    grants = {                                                                                                              # databricks_grants: object key => principal key => privileges
      catalog  = { analysts = "USE_CATALOG", pii_readers = "USE_CATALOG", etl = "USE_CATALOG", operator = "READ_METADATA" } # gp-unassigned: S4 only
      sales    = { pii_readers = "SELECT USE_SCHEMA", etl = "USE_SCHEMA" }
      hr       = { pii_readers = "USE_SCHEMA" }
      orders   = { etl = "MODIFY SELECT", analysts = "SELECT" }
      salaries = { pii_readers = "SELECT" }
    }
    grant   = { "customers/etl" = "MODIFY SELECT" } # databricks_grant: "table key/principal key" => privileges
    members = ["analysts/operator", "analysts/interns", "interns/etl", "pii_readers/operator", "unassigned/etl"]
    owners  = { salaries = "pii_readers" } # table key => principal key; other tables keep their creator
  }
  b = local.baseline

  scenarios = {
    baseline = local.b
    S1 = merge(local.b, { grants = merge(local.b.grants, {
      sales = merge(local.b.grants.sales, { analysts = "SELECT USE_SCHEMA" })
    }) })
    S2 = merge(local.b, { grants = merge(local.b.grants, { orders = { analysts = "SELECT" } }) })
    S3 = merge(local.b, { grant = { "customers/etl" = "MODIFY" } })
    S4 = merge(local.b, {
      members = concat(local.b.members, ["pii_readers/interns"])
      grants = merge(local.b.grants, {
        catalog  = merge(local.b.grants.catalog, { unassigned = "USE_CATALOG" })
        hr       = merge(local.b.grants.hr, { unassigned = "USE_SCHEMA" })
        salaries = merge(local.b.grants.salaries, { unassigned = "SELECT" })
      })
    })
    S5 = merge(local.b, { owners = { salaries = "operator" } })
    S6 = merge(local.b, { grants = { for k, v in local.b.grants : k => v if k != "hr" } })
    S7 = merge(local.b, {
      grants = { for k, v in local.b.grants : k => v if k != "salaries" }
      grant  = merge(local.b.grant, { "salaries/pii_readers" = "SELECT" })
    })
    S8 = merge(local.b, { grants = merge(local.b.grants, {
      orders = merge(local.b.grants.orders, { interns = "SELECT" })
    }) })
    S9 = local.b
    S10 = merge(local.b, {
      grants = merge(local.b.grants, { sales = merge(local.b.grants.sales, { analysts = "USE_SCHEMA" }) })
      grant  = merge(local.b.grant, { "customers/analysts" = "SELECT" })
    })
    # M3 demo D2: plan only, never applied. gp-interns, not gp-analysts: the operator is in gp-analysts, and a
    # route change would print the operator's user name.
    demo = merge(local.b, {
      grants = merge(local.b.grants, { hr = merge(local.b.grants.hr, { interns = "SELECT USE_SCHEMA" }) })
      grant  = merge(local.b.grant, { "salaries/interns" = "SELECT" })
    })
  }
  scenario = local.scenarios[var.scenario]
}
