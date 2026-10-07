# Sample configuration for the reachdiff CI check (milestone 2 live check). It grants on the live-session kit's
# synthetic sales schema. The provider reads DATABRICKS_HOST, DATABRICKS_CLIENT_ID and DATABRICKS_AUTH_TYPE from the
# environment, so the file names no workspace. There is no backend: every run plans from empty state, each grants
# resource is a create, and reachdiff reads the current grants live.

terraform {
  required_version = ">= 1.9"
  required_providers {
    databricks = {
      source  = "databricks/databricks"
      version = "1.135.0"
    }
  }
}

provider "databricks" {}

variable "catalog" {
  description = "Catalog that holds the kit's sales schema."
  type        = string
}

resource "databricks_grants" "sales" {
  schema = "${var.catalog}.sales"

  grant {
    principal  = "gp-pii-readers"
    privileges = ["SELECT", "USE_SCHEMA"]
  }

  grant {
    principal  = "gp-analysts"
    privileges = ["SELECT", "USE_SCHEMA"]
  }
}
