# Live-session predictions (Azure)

Written before the session. Each row states what v0.1 assumes and what reachdiff should report, so the session
records confirmed or refuted instead of interpreting output afterwards. Observed results contain real names and go
to `local/validation/results.md`, never here.

Versions: Terraform provider `databricks/databricks` 1.135.0, Terraform 1.16.4, Databricks CLI 1.19.0,
databricks-sdk 0.140.0 (reachdiff's `databricks` extra).

## Questions

| ID | Question | Source |
|---|---|---|
| Q1 | Real `terraform show -json` shapes for grants, grant, group members and owners | v0.1 §12 |
| Q2 | What destroying or replacing `databricks_grants` and `databricks_grant` does, and whether `databricks_grant` replaces or adds privileges | v0.1 §12 |
| Q3 | The tag-read API's response shape, and the tag keys data classification applies | v0.1 §12 |
| Q4 | Whether the effective-permissions API includes privileges granted to groups | v0.1 §12 |
| Q5 | The minimum privileges the scanning identity needs | v0.1 §12 |
| Q6 | The SDK exception classes for an authentication failure and for one object that returns 403 | review T9 |
| Q7 | Whether names are case-normalized between Terraform and the API | final review |
| Q8 | Pagination: `max_results=0` and page tokens on permissions, schema and table listings | `collect/live.py` |
| Q9 | Whether workspace SCIM returns account groups, their nested members and unassigned groups, and whether plan IDs match workspace SCIM IDs | M0 spec |
| Q10 | What ownership confers: the provider docs say owners receive `ALL_PRIVILEGES`; v0.1 gives owners MANAGE only | provider docs |

## Baseline

After S0 is applied ("you" is the operator):

- Catalog `gp_validation` (or the existing catalog): owner you. `USE_CATALOG` for gp-analysts, gp-pii-readers and
  gp-etl. gp-scanner per `scanner_stage`. gp-unassigned holds no grant outside S4, so every other run reads only
  principals that workspace SCIM can see.
- `sales`: gp-pii-readers `SELECT USE_SCHEMA`; gp-etl `USE_SCHEMA`.
- `hr`: gp-pii-readers `USE_SCHEMA`.
- `sales.orders`: gp-etl `SELECT MODIFY`; gp-analysts `SELECT` (unusable: no `USE_SCHEMA` on sales).
- `sales.customers`: gp-etl `SELECT MODIFY` through `databricks_grant`. Column `email` tagged `pii=email`.
- `hr.salaries`: owner gp-pii-readers; gp-pii-readers `SELECT`. Table tag `sensitive`.
- Members: gp-analysts ⊃ you, gp-interns. gp-interns ⊃ gp-etl. gp-pii-readers ⊃ you. gp-unassigned ⊃ gp-etl
  (gp-unassigned is not assigned to the workspace).

Service principals appear under their application IDs. Live runs use `--profile gp-scanner` unless stated.

## Scenarios

| ID | Change | Answers | v0.1 assumption and expected reachdiff result |
|---|---|---|---|
| S0 | Create the baseline on an empty workspace; apply | Q1 | Values known only after apply (application IDs, object IDs, group IDs) become `unknown_after_apply` gaps. Offline: WARN. Live as gp-trial: WARN with `unreadable_object` and `unresolved_name` gaps for objects and groups that don't exist yet, likely one row `+ gp-pii-readers MANAGE …hr.salaries` from the owner. Never PASS. After apply, `run.sh plan baseline S0-after` shows no changes. |
| S1 | gp-analysts gains `SELECT USE_SCHEMA` on `sales` | Q1, Q8, Q9 | `+ gp-analysts READ sales (all tables)`: 2 members, 1 new (gp-etl), 1 already had it (you). `+ gp-interns READ sales`: 1 member, 1 new. gp-etl has no own row. Gaps `latent_grants` and `sensitivity_not_evaluated`. WARN, exit 0. |
| S2 | gp-etl dropped from the `databricks_grants` resource on `orders` | Q1 | `− gp-etl READ orders` and `− gp-etl WRITE orders`. Revocations raise no default finding: PASS, exit 0. |
| S3 | gp-etl's `databricks_grant` on `customers`: `SELECT MODIFY` → `MODIFY`; apply | Q2 | `− gp-etl READ customers`, `− gp-etl WRITE customers`, PASS. Read-back: gp-etl holds exactly `MODIFY` (replace, not add). |
| S4 | gp-interns nested in gp-pii-readers; gp-unassigned gains `USE_CATALOG`, `USE_SCHEMA` on `hr` and `SELECT` on `salaries` | Q1, Q9 | Rows for gp-interns (`READ` and `MANAGE` on `salaries`) and gp-unassigned (`READ salaries`), with gp-etl counted through both and no own row. `sensitive_access` on the `READ` rows (table tag `sensitive`). `membership_scope` gap: grants gp-pii-readers holds on `sales` are not read, so no `sales` row. If workspace SCIM can't see gp-unassigned: an `unresolved_name` gap and no member count for its row. WARN. |
| S5 | `hr.salaries` owner: gp-pii-readers → you | Q1 | `individual_owner` WARN. `− gp-pii-readers MANAGE salaries` (you keep MANAGE as catalog owner). No gain row for you. |
| S6 | Out-of-band grant gp-analysts `USE_SCHEMA` on `hr`, then the `databricks_grants` resource on `hr` is destroyed; apply | Q2 | Plan `before` includes the out-of-band grant. No rows (`USE_SCHEMA` alone gives no access entry; `salaries` is not in scope). `deactivated_grants` gaps for gp-pii-readers and gp-analysts. WARN. Read-back on `hr`: open — are all grants gone, or only those in Terraform's state? |
| S7 | `salaries` moves from `databricks_grants` to `databricks_grant` (destroy + create); apply | Q2, m4b | `conflicting_grant_resources` gap, no rows, WARN. Read-back: gp-pii-readers still holds `SELECT` if the destroy ran first; a missing `SELECT` proves order dependence. A second `run.sh plan S7 S7-after` shows whether Terraform sees drift. |
| S8 | gp-interns `SELECT` on `orders`; after planning, an out-of-band gp-analysts `MODIFY` on `orders` | Q1 | Before the out-of-band grant: no rows, PASS. After it: `changed_since_plan` gap, WARN. |
| S9 | The `sales` grant resource names the schema `….Sales` | Q7 | Open. v0.1 compares names case-sensitively: if the plan shows the change, expect a false loss on `sales` and gain on `Sales` for the same access, or a `changed_since_plan` gap. If the provider suppresses the difference, the plan shows no change. |
| S10 | gp-analysts gains `USE_SCHEMA` on `sales` and `SELECT` on `customers` (`databricks_grant`) | Q3 | `+ gp-analysts READ customers` (2 members, 0 new) and `+ gp-interns READ customers`. `sensitive_access` on both: the `email` column tag is read because `customers` changes. `latent_grants` gap (gp-analysts' `SELECT` on `orders` becomes usable). WARN. |
| S10b | No Terraform change: reachdiff `--deep` on the S1 plan | Q3, Q8 | Child tables of `sales` are listed. `+ gp-analysts READ sales (all tables)` with the `orders` activation folded in; no `latent_grants` gap. `sensitivity_not_evaluated`: column tags of child tables under `sales` were not read (v0.1 decision). WARN. |
| demo | M3 demo D2, plan only: gp-interns gains `SELECT USE_SCHEMA` on `hr` and `SELECT` on `salaries` through `databricks_grant` beside its `databricks_grants` | — | Live as gp-trial: `+ gp-interns READ hr (all tables)`, 1 member, 1 new (gp-etl). BLOCK `grant_resource_conflict` on `salaries`, `sensitive_access` for gp-interns, `conflicting_grant_resources` and `latent_grants` gaps. No route changes (you aren't in gp-interns). Exit 2. The text report must show no user name, application ID or workspace host before it is recorded. |

## Probes

| ID | Probe | Answers | Expected |
|---|---|---|---|
| P1 | `databricks api get` on the collector's tag paths for `customers.email` (columns) and `hr.salaries` (tables); one `tables` listing with `max_results=1` | Q3, Q8 | `{"tag_assignments": [{…, "tag_key": "pii", "tag_value": "email"}]}` and `tag_key: "sensitive"`. The listing returns one table and a `next_page_token`. |
| P2 | Insert ten synthetic rows into `customers`, turn on `data_classification`, poll P1's column path | Q3 | A tag whose key starts `class.` with `source_type` `TAG_ASSIGNMENT_SOURCE_TYPE_SYSTEM_DATA_CLASSIFICATION`. May not appear within the session; then unanswered and the default `[sensitive].tags` stays provisional. |
| P3 | `databricks grants get-effective` for gp-interns on `orders` (`SELECT` only through gp-analysts), and for gp-pii-readers on `salaries` (owner) | Q4, Q10 | Open: whether group-inherited `SELECT` is listed, and whether ownership shows as privileges. |
| P4 | reachdiff on the S1 plan as gp-scanner at `scanner_stage` 0, 1, 2 and 3 | Q5, Q6 | The first stage with no read-failure gap (`unreadable_object`, `tags_unavailable`, `unresolved_name`, `membership_incomplete`). v0.1 has no assumption; stage 2 or 3 likely. Gap details carry the exception class of each failed read (Q6, 403 case). |
| P5 | A client with an invalid token | Q6 | The code matches the class name `Unauthenticated`. Record the actual class and its base classes. reachdiff exits 3. |
| P6 | A temporary provider override with a literal host | Q1 | The host appears as `configuration.provider_config.databricks.expressions.host.constant_value`. Matching host: the run proceeds. A copy of the plan with another host: exit 3. |

## Re-check

Written before the re-check.
Same workspace and baseline as the first session; `catalog_mode = "existing"`. "Catalog" is the catalog in use.
Rows assume the code after the first session's fixes: ownership counts as all privileges, names are lowercase, visibility is self-checked,
unread membership is one gap.

| ID | Check | Expected |
|---|---|---|
| R0 | Apply the new baseline: the operator gains `READ_METADATA` on the catalog; gp-scanner's catalog set changes from `BROWSE MANAGE USE_CATALOG USE_SCHEMA` to `BROWSE READ_METADATA USE_CATALOG USE_SCHEMA` | One `databricks_grants` update; `plan baseline R0-after` shows no changes |
| R1 stage 0 | S1 as gp-scanner, no catalog privileges | `unreadable_object` "only the caller's own grants are visible…" for the catalog and `sales`; as in the first session, `unreadable_object` (owner of `sales`) and `tags_unavailable` (`sales`), PermissionDenied; no `changed_since_plan`; no rows; one `membership_incomplete` ("workspace SCIM shows members only to workspace admins"); WARN, exit 0 |
| R1 stage 1 | `BROWSE` | As stage 0, without the `tags_unavailable` gap (as in the first session); BROWSE does not show others' grants |
| R1 stage 2 | `READ_METADATA` only | Open: grant lists visible. If owners or tags of `sales` are refused without `BROWSE`/`USE_*`, `unreadable_object` (owner) or `tags_unavailable` gaps appear |
| R1 stage 3 | `BROWSE READ_METADATA USE_CATALOG USE_SCHEMA` | No visibility gaps; `+ gp-analysts (members not read) READ sales (all tables)`; no gp-interns row; one `membership_incomplete`; `latent_grants`; WARN |
| R2 | S1 as gp-trial | Self-check passes through the operator's `READ_METADATA`. Rows as in the first session: `+ gp-analysts (2 members, 1 new, 1 already had it) READ sales (all tables)`, `+ gp-interns (1 member, 1 new, 0 already had it) READ sales (all tables)`; WARN |
| R3 | S5 as gp-trial | `individual_owner` WARN. `− gp-pii-readers (1 member, 0 lose it, 1 keep it another way) MANAGE …hr.salaries` and the same for `WRITE`; no READ row (explicit `SELECT` stays); the operator's MANAGE and WRITE appear as route changes |
| R4 | S9 as gp-trial and gp-scanner | The replaced resource maps to the same lowercase schema with the same grants: no access changes, PASS, exit 0, in both modes |
| R5 | P7: gp-scanner owns `hr.p7` without `SELECT`; `SELECT count(*)` as gp-scanner (`sql`-scoped profile) on `hr.p7` and, as a control, on `hr.salaries` | `hr.p7`: statement `SUCCEEDED` (ownership confers SELECT, Q10 confirmed). `hr.salaries`: `FAILED` with a permission error |
| R6 | P2 column tags on `sales.customers.email` | Open: a tag whose key starts `class.`, or still only `pii=email` (P2 stays unanswered) |
| R7 | Self-check assumptions | A caller without privileges can query its own effective permissions (stage 0/1 gaps give the "only the caller's own grants" reason, not "visibility check failed"); the response spells `READ_METADATA` (stage 2/3 lists visible) |

## CI check

Written before the CI check. Same workspace; gp-scanner at the stage chosen in step 25 (`READ_METADATA` on the
catalog), not workspace admin. Each row runs on GitHub (hosted Ubuntu runner, `github-oidc`) and on Azure DevOps
(self-hosted macOS agent, `azure-devops-oidc`). The sample plan has no state, so `databricks_grants.sales` is a
create.

| ID | Check | Expected |
|---|---|---|
| F0 | `run.sh plan baseline M2-federation` with `ci_federation` set | Two `databricks_service_principal_federation_policy` creates, nothing else |
| C1 | Pull request adds `terraform/main.tf`: `databricks_grants` on `sales` for gp-pii-readers and gp-analysts (`SELECT USE_SCHEMA`), without gp-etl | `terraform plan` and reachdiff both log in as gp-scanner by federation. `+ gp-analysts (members not read) READ sales (all tables)`; gp-etl's `USE_SCHEMA` is removed, so a `deactivated_grants` gap; `latent_grants` and `sensitivity_not_evaluated` as in S1; one `membership_incomplete`; WARN, exit 0. GitHub: job succeeds with a `reachdiff: WARN` warning. Azure DevOps: "succeeded with issues". One comment (GitHub) or one `closed` thread (Azure DevOps) starting with `<!-- reachdiff key=default -->`; the full report in the run summary |
| C2 | Second commit adds `databricks_grant.interns` (`USE_SCHEMA` on `sales` for gp-interns) | `grant_resource_conflict` BLOCK, exit 2; the job fails. The C1 comment is edited, not a new one; the Azure DevOps thread becomes `active` |
| C3 | Third commit sets only reachdiff's client ID to the zero UUID (the action step's env, the template's `clientId`) | `terraform plan` still succeeds. reachdiff's token exchange fails: exit 3, the job fails, the comment becomes "reachdiff: ERROR" (Azure DevOps thread `active`). No report and no fallback to another login |
