terraform {
  required_version = ">= 1.9"
  required_providers {
    databricks = {
      source  = "databricks/databricks"
      version = "1.135.0"
    }
  }
  # State stays in the ignored local/ directory.
  backend "local" {
    path = "../../../local/validation/terraform.tfstate"
  }
}

provider "databricks" {
  alias      = "account"
  host       = "https://accounts.azuredatabricks.net"
  account_id = var.account_id
  auth_type  = "azure-cli"
}

provider "databricks" {
  profile = var.workspace_profile
}

# Identities live at account level, where Unity Catalog grants point.

resource "databricks_group" "this" {
  provider     = databricks.account
  for_each     = local.groups
  display_name = each.value
}

resource "databricks_service_principal" "this" {
  provider                 = databricks.account
  for_each                 = local.service_principals
  display_name             = each.value
  disable_as_user_deletion = false # delete, not deactivate, on destroy
}

data "databricks_user" "operator" {
  provider  = databricks.account
  user_name = var.operator
}

resource "databricks_mws_permission_assignment" "this" {
  provider     = databricks.account
  for_each     = toset(["analysts", "pii_readers", "interns", "etl", "scanner"]) # gp-unassigned stays unassigned
  workspace_id = var.workspace_id
  principal_id = local.ids[each.key]
  permissions  = ["USER"]
}

# New workspaces grant the users group no entitlements; every API the collector calls needs one.
resource "databricks_entitlements" "scanner" {
  service_principal_id = databricks_service_principal.this["scanner"].id
  workspace_consume    = true # the least of the three entitlements the API accepts; excludes databricks_sql_access
  depends_on           = [databricks_mws_permission_assignment.this]
}

resource "databricks_group_member" "this" {
  provider  = databricks.account
  for_each  = toset(local.scenario.members)
  group_id  = local.ids[split("/", each.key)[0]]
  member_id = local.ids[split("/", each.key)[1]]
}

# Objects.

resource "databricks_catalog" "this" {
  count         = var.catalog_mode == "new" ? 1 : 0
  name          = "gp_validation"
  force_destroy = true
}

resource "databricks_schema" "this" {
  for_each      = toset(["sales", "hr"])
  catalog_name  = local.catalog
  name          = each.key
  force_destroy = true
}

resource "databricks_sql_table" "this" {
  for_each     = local.tables
  catalog_name = local.catalog
  schema_name  = databricks_schema.this[each.value.schema].name
  name         = each.key
  table_type   = "MANAGED"
  warehouse_id = var.warehouse_id
  owner        = try(local.names[local.scenario.owners[each.key]], null)

  dynamic "column" {
    for_each = each.value.columns
    content {
      name = column.value
      type = "STRING"
    }
  }
}

resource "databricks_entity_tag_assignment" "email" {
  entity_type = "columns"
  entity_name = "${databricks_sql_table.this["customers"].id}.email"
  tag_key     = "pii"
  tag_value   = "email"
}

resource "databricks_entity_tag_assignment" "salaries" {
  entity_type = "tables"
  entity_name = databricks_sql_table.this["salaries"].id
  tag_key     = "sensitive"
  tag_value   = "" # provider 1.135.0 reads a key-only tag back as "" and fails the apply if this is unset
}

# P7: gp-scanner owns a probe table without SELECT on it. Reading it tests what ownership confers (Q10).
resource "databricks_sql_table" "probe" {
  count        = var.probe_ownership ? 1 : 0
  catalog_name = local.catalog
  schema_name  = databricks_schema.this["hr"].name
  name         = "p7"
  table_type   = "MANAGED"
  warehouse_id = var.warehouse_id
  owner        = local.names["scanner"]

  column {
    name = "id"
    type = "STRING"
  }
}

resource "databricks_data_classification_catalog_config" "this" {
  count            = var.data_classification ? 1 : 0
  parent           = "catalogs/${local.catalog}"
  included_schemas = { names = ["sales"] }
  # Classification writes class.* tags only for classes with automatic tagging on; without it, detections stay in
  # the results page. Tags appear with the next scan, within 24 hours.
  auto_tag_configs = [{
    classification_tag = "class.email_address"
    auto_tagging_mode  = "AUTO_TAGGING_ENABLED"
  }]
}

# Grants, driven by the scenario. gp-scanner's privileges ride on the catalog and inherit downward.

resource "databricks_grants" "this" {
  for_each = local.scenario.grants
  catalog  = local.objects[each.key].kind == "catalog" ? local.securable[each.key] : null
  schema   = local.objects[each.key].kind == "schema" ? local.securable[each.key] : null
  table    = local.objects[each.key].kind == "table" ? local.securable[each.key] : null

  dynamic "grant" {
    for_each = merge(each.value, { for k, v in { scanner = local.scanner_privileges } : k => v if each.key == "catalog" && v != "" })
    content {
      principal  = local.names[grant.key]
      privileges = split(" ", grant.value)
    }
  }
}

resource "databricks_grant" "this" {
  for_each   = local.scenario.grant # tables only
  table      = local.securable[split("/", each.key)[0]]
  principal  = local.names[split("/", each.key)[1]]
  privileges = split(" ", each.value)
}

# M2: CI jobs log in as gp-scanner with their own OIDC token; no secret is stored in CI.
resource "databricks_service_principal_federation_policy" "ci" {
  provider             = databricks.account
  for_each             = var.ci_federation
  service_principal_id = tonumber(databricks_service_principal.this["scanner"].id)
  description          = "reachdiff CI check: ${each.key}"
  oidc_policy = {
    issuer    = each.value.issuer
    subject   = each.value.subject
    audiences = each.value.audience == null ? null : [each.value.audience]
  }
}
