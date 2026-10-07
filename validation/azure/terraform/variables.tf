variable "scenario" {
  description = "Scenario to plan or apply: baseline or S1-S10 (see ../predictions.md)."
  type        = string
  default     = "baseline"
  validation {
    condition     = contains(keys(local.scenarios), var.scenario)
    error_message = "Unknown scenario; see ../predictions.md."
  }
}

variable "account_id" {
  description = "Azure Databricks account ID. Set in local/validation/session.tfvars, never in this directory."
  type        = string
}

variable "workspace_id" {
  description = "Numeric workspace ID: the <id> in https://adb-<id>.<n>.azuredatabricks.net."
  type        = string
}

variable "workspace_profile" {
  description = "Databricks CLI profile for the workspace provider."
  type        = string
  default     = "gp-trial"
}

variable "operator" {
  description = "Your Databricks user name, the only real user in the scenarios."
  type        = string
}

variable "warehouse_id" {
  description = "SQL warehouse that creates the tables."
  type        = string
}

variable "catalog_mode" {
  description = "new: create gp_validation. existing: use existing_catalog (when a new catalog needs a managed location)."
  type        = string
  default     = "new"
  validation {
    condition     = contains(["new", "existing"], var.catalog_mode)
    error_message = "catalog_mode must be new or existing."
  }
}

variable "existing_catalog" {
  description = "Catalog to use when catalog_mode = existing. Its grants are replaced by the scenarios."
  type        = string
  default     = ""
}

variable "scanner_stage" {
  description = "gp-scanner's privileges on the catalog, cumulative: 0 none, 1 BROWSE, 2 READ_METADATA, 3 + BROWSE USE_CATALOG USE_SCHEMA."
  type        = number
  default     = 3
  validation {
    condition     = contains([0, 1, 2, 3], var.scanner_stage)
    error_message = "scanner_stage must be 0, 1, 2 or 3."
  }
}

variable "data_classification" {
  description = "P2: turn on data classification for the sales schema."
  type        = bool
  default     = false
}

variable "probe_ownership" {
  description = "P7: create hr.p7 owned by gp-scanner, which holds no SELECT on it."
  type        = bool
  default     = false
}

variable "ci_federation" {
  description = "M2: OIDC federation policies that let CI jobs log in as gp-scanner, keyed by platform. Set in session.tfvars only."
  type = map(object({
    issuer   = string
    subject  = string
    audience = optional(string)
  }))
  default = {}
}
