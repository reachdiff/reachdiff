# Azure validation runbook

Checks reachdiff's live mode against a disposable Azure Databricks workspace in one session. `predictions.md` lists
the questions, scenarios and expected results, written before each run. The scenarios replace grants on the catalog
they use, so never point the kit at a workspace that matters.

## Rules

- **Writes** marks a command that changes the workspace. Read the plan or the request before each one. Everything
  else only reads.
- The only writes are `run.sh apply`, `run.sh destroy`, the out-of-band `databricks grants update` in S6 and S8,
  the SQL insert in P2, and the additive warehouse permission in R5.
- Section H adds GitHub and Azure DevOps (repositories, settings, pull requests, the agent). The kit's only new write
  there is the federation policies, through `run.sh apply`.
- If a command would do anything not in this runbook, stop and ask.
- Never print a token or paste `~/.databrickscfg` anywhere. Secrets stay out of logs, chats and tickets.
- Everything the session produces stays in `local/validation/` (ignored). No plan, report, read-back or CLI
  response is committed. Run the secret scan before any commit after the session.
- The session can pause between phases: state and output live in `local/validation/`.

In every command, replace `gp_validation` with the catalog in use if `catalog_mode = "existing"`.

## A. Setup

1. Activate the Azure trial and create a Premium Azure Databricks workspace. Note its URL
   (`https://adb-<id>.<n>.azuredatabricks.net`) and the account ID (account console, top right).
   The account console rejects personal Microsoft accounts. If yours is one, create a member user in your Entra ID
   directory, give it Global Administrator, sign in to the account console with it, and give it Admin on the
   workspace (account console, Workspaces, Permissions). That user is the operator for every step below.
2. As the operator: `az login --allow-no-subscriptions --tenant <tenant ID>`. If the browser signs in with another
   account, open the login URL that `az` prints in a private window. Don't use `--use-device-code`: Entra security
   defaults refuse it (`AADSTS530035`). Then `databricks auth login --host <workspace URL> --profile gp-trial`.
3. Give the Serverless Starter Warehouse (or any SQL warehouse) auto-stop, and note its ID.
4. Write `local/validation/session.tfvars` (none of the values is secret):

   ```hcl
   account_id   = "<account ID>"
   workspace_id = "<id from the workspace URL>"
   operator     = "<your Databricks user name>"
   warehouse_id = "<warehouse ID>"
   ```

## B. Capability check (read-only)

5. Record versions and install reachdiff with the SDK:

   ```bash
   terraform version; databricks --version
   python3 -m venv .venv && .venv/bin/pip install -e '.[databricks]'
   .venv/bin/pip show databricks-sdk | head -2
   ```

6. Check the workspace:

   ```bash
   databricks current-user me --profile gp-trial > /dev/null && echo "gp-trial works"
   databricks metastores summary --profile gp-trial -o json > local/validation/B-metastore.json
   databricks catalogs list --profile gp-trial -o json > local/validation/B-catalogs.json
   ```

   If the metastore summary has no `storage_root`, try S0 with `catalog_mode = "new"` first. If creating the
   catalog fails for lack of a managed location, add `catalog_mode = "existing"` and
   `existing_catalog = "<workspace catalog>"` to `session.tfvars`. The scenarios then replace that catalog's grants.
   The error suggests creating the catalog on Default Storage in the UI, but that only works in serverless
   workspaces; a classic workspace offers no such option. The workspace catalog is owned by the
   `_workspace_admins_…` group, not the operator, which shifts the owner expectations in `predictions.md`.

## C. Baseline and scanner

7. S0:

   ```bash
   terraform -chdir=validation/azure/terraform init -input=false
   validation/azure/run.sh plan baseline S0
   validation/azure/run.sh report S0 S0-offline --offline
   validation/azure/run.sh report S0 S0-live --profile gp-trial
   ```

   **Writes:** `validation/azure/run.sh apply baseline`. Then `validation/azure/run.sh plan baseline S0-after`
   must show no changes.
8. In the account console, open service principal gp-scanner, generate an OAuth secret, and add to
   `~/.databrickscfg`:

   ```ini
   [gp-scanner]
   host          = <workspace URL>
   client_id     = <gp-scanner application ID>
   client_secret = <the secret>
   scopes        = <the scopes chosen for the secret, e.g. unity-catalog, scim, access-management>
   auth_type     = oauth-m2m
   ```

   Leave out `scopes` only for an all-APIs secret: the SDK otherwise requests `all-apis`, which a scoped secret
   refuses. `auth_type` is required: without it the Databricks CLI silently falls back to `az login` and runs as
   the operator. Check it with `databricks current-user me --profile gp-scanner -o json | python3 -c "import json,sys; print(json.load(sys.stdin)['displayName'])"`,
   which must print `gp-scanner`.
9. P4, for each stage N in 0, 1, 2, 3: set `scanner_stage = N` in `session.tfvars`; run (**writes**)
   `validation/azure/run.sh apply baseline`; then

   ```bash
   validation/azure/run.sh plan S1 S1-stageN
   validation/azure/run.sh report S1-stageN P4-stageN --profile gp-scanner
   ```

   Keep in `session.tfvars` the first stage whose report has no read-failure gap, and run (**writes**)
   `validation/azure/run.sh apply baseline` if it differs from 3. If no stage works, later runs use
   `--profile gp-trial` and `results.md` says so.

   The kit gives gp-scanner the `workspace-consume` entitlement: new workspaces grant none to the `users` group,
   and without one every API the collector calls is refused. Expect `membership_incomplete` at every stage,
   because workspace SCIM shows group members only to admins. Below stage 3 the permissions API returns a
   filtered list without an error, which reachdiff sees only as `changed_since_plan`. In the reference run no
   stage was gap-free: scenario verdicts came from `gp-trial` runs, with `gp-scanner` runs kept for comparison.
10. P5:

    ```bash
    host=$(databricks auth profiles -o json | python3 -c "import json,sys; print(next(p['host'] for p in json.load(sys.stdin)['profiles'] if p['name'] == 'gp-trial'))")
    DATABRICKS_CONFIG_FILE=/dev/null GP_HOST="$host" .venv/bin/python -c "
    import os
    from databricks.sdk import WorkspaceClient
    try:
        WorkspaceClient(host=os.environ['GP_HOST'], token='not-a-token').api_client.do('GET', '/api/2.1/unity-catalog/catalogs')
    except Exception as exc:
        print([c.__name__ for c in type(exc).__mro__])
    " > local/validation/P5-sdk.txt
    DATABRICKS_CONFIG_FILE=/dev/null DATABRICKS_HOST="$host" DATABRICKS_TOKEN=not-a-token \
      .venv/bin/reachdiff plan --tfplan local/validation/S1-stage3.plan.json > local/validation/P5-reachdiff.txt 2>&1
    echo "exit $?" >> local/validation/P5-reachdiff.txt
    ```

## D. Scenarios

11. For S1, S2, S3, S4, S5, S9 and S10:

    ```bash
    validation/azure/run.sh plan SX
    validation/azure/run.sh report SX SX --profile gp-scanner
    ```

    Compare with `predictions.md` and record the verdict in `local/validation/results.md`.
12. S10b: `validation/azure/run.sh report S1 S10b --profile gp-scanner --deep`.
13. S3 after its report: run (**writes**) `validation/azure/run.sh apply S3`;
    `validation/azure/run.sh readback S3 table gp_validation.sales.customers`; run (**writes**)
    `validation/azure/run.sh apply baseline`.
14. S6: run (**writes**) the out-of-band grant

    ```bash
    databricks grants update schema gp_validation.hr --profile gp-trial --json '{"changes": [{"principal": "gp-analysts", "add": ["USE_SCHEMA"]}]}'
    ```

    then plan and report S6 as in step 11; run (**writes**) `validation/azure/run.sh apply S6`;
    `validation/azure/run.sh readback S6 schema gp_validation.hr`; run (**writes**)
    `validation/azure/run.sh apply baseline`.
15. S7: plan and report as in step 11; run (**writes**) `validation/azure/run.sh apply S7`;
    `validation/azure/run.sh readback S7 table gp_validation.hr.salaries`; `validation/azure/run.sh plan S7 S7-after`
    (drift check); run (**writes**) `validation/azure/run.sh apply baseline`.
16. S8: `validation/azure/run.sh plan S8` and `validation/azure/run.sh report S8 S8-before --profile gp-scanner`;
    run (**writes**)

    ```bash
    databricks grants update table gp_validation.sales.orders --profile gp-trial --json '{"changes": [{"principal": "gp-analysts", "add": ["MODIFY"]}]}'
    ```

    then `validation/azure/run.sh report S8 S8-after --profile gp-scanner`; run (**writes**)
    `validation/azure/run.sh apply baseline` (the authoritative set removes the out-of-band grant).

## E. Probes

17. P1 and the Q8 listing:

    ```bash
    databricks api get /api/2.1/unity-catalog/entity-tag-assignments/columns/gp_validation.sales.customers.email/tags --profile gp-scanner > local/validation/P1-column.json
    databricks api get /api/2.1/unity-catalog/entity-tag-assignments/tables/gp_validation.hr.salaries/tags --profile gp-scanner > local/validation/P1-table.json
    databricks api get "/api/2.1/unity-catalog/tables?catalog_name=gp_validation&schema_name=sales&max_results=1" --profile gp-scanner > local/validation/P1-page1.json
    ```

18. P3:

    ```bash
    databricks grants get-effective table gp_validation.sales.orders --principal gp-interns --profile gp-trial -o json > local/validation/P3-interns-orders.json
    databricks grants get-effective table gp_validation.hr.salaries --principal gp-pii-readers --profile gp-trial -o json > local/validation/P3-owner-salaries.json
    ```

19. P6: write `validation/azure/terraform/host_override.tf` (ignored):

    ```hcl
    provider "databricks" {
      host    = "<workspace URL>"
      profile = var.workspace_profile
    }
    ```

    then

    ```bash
    validation/azure/run.sh plan S1 P6
    validation/azure/run.sh report P6 P6-match --profile gp-scanner
    python3 -c "
    import json
    p = json.load(open('local/validation/P6.plan.json'))
    for c in p['configuration']['provider_config'].values():
        if 'host' in c.get('expressions', {}) and 'accounts.' not in str(c['expressions']['host']):
            c['expressions']['host'] = {'constant_value': 'https://adb-0000000000000000.0.azuredatabricks.net'}
    json.dump(p, open('local/validation/P6-mismatch.plan.json', 'w'))
    "
    validation/azure/run.sh report P6-mismatch P6-mismatch --profile gp-scanner
    rm validation/azure/terraform/host_override.tf
    ```

20. P2 (last, it may take a while): write `local/validation/P2-insert.json` with the warehouse ID and ten rows of
    `example.com` addresses:

    ```json
    {"warehouse_id": "<warehouse ID>", "wait_timeout": "30s",
     "statement": "INSERT INTO gp_validation.sales.customers VALUES ('c1', 'ana.lopez@example.com'), ('c2', 'ben.ng@example.com'), ('c3', 'chris.oduya@example.com'), ('c4', 'dana.kim@example.com'), ('c5', 'eli.rossi@example.com'), ('c6', 'fay.moreau@example.com'), ('c7', 'gus.larsen@example.com'), ('c8', 'hana.sato@example.com'), ('c9', 'ivo.novak@example.com'), ('c10', 'jo.silva@example.com')"}
    ```

    **Writes:** `databricks api post /api/2.0/sql/statements --profile gp-trial --json @local/validation/P2-insert.json`.
    Add `data_classification = true` to `session.tfvars`; run (**writes**) `validation/azure/run.sh apply baseline`.
    This also turns on automatic tagging for `class.email_address`: without it, classification only reports its
    detections and writes no tags. Repeat the P1 column request after a day; tags appear
    with the next scan, within 24 hours.

## G. Re-check

After changes to the collector or the rules: `git pull`; the editable install picks up the new code. Record results
under a new heading "Re-check" in `local/validation/results.md`, one verdict per row of `predictions.md` "Re-check".

24. R0: run (**writes**) `validation/azure/run.sh apply baseline`; then `validation/azure/run.sh plan baseline R0-after`
    must show no changes.
25. R1, for each stage N in 0, 1, 2, 3: set `scanner_stage = N` in `session.tfvars`; run (**writes**)
    `validation/azure/run.sh apply baseline`; then

    ```bash
    validation/azure/run.sh plan S1 R1-stageN
    validation/azure/run.sh report R1-stageN R1-stageN --profile gp-scanner
    ```

    Then set `scanner_stage` to the lowest stage with no visibility, owner or tag gap and run the apply (**writes**).
26. R2: `validation/azure/run.sh plan S1 R2`; `validation/azure/run.sh report R2 R2 --profile gp-trial`.
27. R3: `validation/azure/run.sh plan S5 R3`; report as `gp-trial` (`R3`) and `gp-scanner` (`R3-scanner`).
28. R4: `validation/azure/run.sh plan S9 R4`; report as `gp-trial` (`R4`) and `gp-scanner` (`R4-scanner`).
29. R5 (P7):
    1. In the account console, generate a second gp-scanner secret with scope `sql` and a lifetime of one day.
       Add a profile to `~/.databrickscfg`:

       ```ini
       [gp-p7]
       host          = <workspace URL>
       client_id     = <gp-scanner application ID>
       client_secret = <the sql-scoped secret>
       scopes        = sql
       auth_type     = oauth-m2m
       ```

       Check that `databricks auth profiles --skip-validate` lists `gp-p7`.
    2. Read `databricks warehouses get-permissions <warehouse ID> --profile gp-trial`. If the `users` group
       holds `CAN_USE`, gp-scanner has it as a member: skip this step. Otherwise run (**writes**)
       `databricks warehouses update-permissions <warehouse ID> --profile gp-trial --json
       '{"access_control_list": [{"service_principal_name": "<gp-scanner application ID>", "permission_level": "CAN_USE"}]}'`.
       There is no additive revoke; the entry goes when `destroy` deletes gp-scanner.
    3. Set `scanner_stage = 3` and `probe_ownership = true`; run (**writes**) `validation/azure/run.sh apply baseline`. An
       owner still needs `USE_CATALOG` and `USE_SCHEMA` (Databricks docs): at stage 2 both statements would fail for
       lack of them, and the probe could not tell whether ownership confers `SELECT`.
    4. Write `local/validation/R5-owner.json` and `R5-control.json` (`{"warehouse_id": "<warehouse ID>", "wait_timeout":
       "30s", "statement": "SELECT count(*) FROM <catalog>.hr.p7"}`, and `…hr.salaries` for the control), then

       ```bash
       databricks api post /api/2.0/sql/statements --profile gp-p7 --json @local/validation/R5-owner.json > local/validation/R5-owner.result.json
       databricks api post /api/2.0/sql/statements --profile gp-p7 --json @local/validation/R5-control.json > local/validation/R5-control.result.json
       ```

       These statements only read. If both are refused for a missing entitlement, give gp-scanner Databricks
       SQL access in the workspace admin settings and repeat. The kit cannot set it: provider 1.135.0 refuses
       `databricks_sql_access` next to `workspace_consume`, even when it is `false`.
    5. Set `scanner_stage` back to the stage chosen in step 25 and `probe_ownership = false`; run the apply (**writes**). Remove the SQL access entitlement if you added
       it, and delete the `sql`-scoped secret in the account console and the `[gp-p7]` profile.
30. R6: repeat the P1 column request into `local/validation/R6-column.json`.
31. R7: read the reasons in the R1 stage 0–1 gaps; at stage 2 or 3 also run
    `databricks api get "/api/2.1/unity-catalog/effective-permissions/catalog/<catalog>?principal=<gp-scanner application ID>" --profile gp-scanner > local/validation/R7-effective.json`.

## H. CI check

Checks the GitHub Action and the Azure DevOps template against the workspace. Predictions: `predictions.md` "CI
check". Record results under a new heading "CI" in `local/validation/results.md`. Read results with `gh` (GitHub)
and the Azure DevOps REST API or exported logs. gp-scanner keeps the stage chosen in step 25.

32. Note the reachdiff commit to pin (`git rev-parse origin/main`) and write the sample repositories' files to
    `local/validation/M2-sample/`: `terraform/main.tf` from `examples/ci/terraform/`,
    `.github/workflows/reachdiff.yml` from `examples/ci/github-workflow.yml` and `azure-pipelines.yml` from
    `examples/ci/azure-pipelines.yml`, with `OWNER`, `FULL_COMMIT_SHA` and `GITHUB_CONNECTION` filled in.
33. GitHub:
    1. Create a private repository (for example `reachdiff-ci-sample`). Its first commit on `main` holds only
       `.github/workflows/reachdiff.yml`.
    2. Only if your copy of reachdiff's repository is private: Settings → Actions → General → Access → accessible from
       repositories owned by you.
    3. In the sample repository: Settings → Secrets and variables → Actions → Variables: `GP_HOST` (workspace URL),
       `GP_CLIENT_ID` (gp-scanner's application ID), `GP_CATALOG` (the catalog in use). None is a secret.
34. Azure DevOps:
    1. Create an organization and a private project. Note the organization ID: open
       `https://dev.azure.com/<organization>/_apis/connectionData` while signed in and copy `instanceId`.
    2. Create an Azure Repos repository whose first commit on `main` holds only `azure-pipelines.yml`.
    3. Project settings → Service connections → GitHub, with read access to reachdiff's repository; its name replaces
       `GITHUB_CONNECTION`.
    4. Organization settings → Agent pools → Default → New agent → macOS: download, `./config.sh`, then `./run.sh` in
       a terminal you keep open for the session. Check that `terraform version` and `python3 --version` (3.11 or newer)
       work in that terminal.
    5. Pipelines → New pipeline → Azure Repos Git → the repository → existing `azure-pipelines.yml`; name it without
       spaces. Variables `GP_HOST`, `GP_CLIENT_ID`, `GP_CATALOG` as in step 33.3. Save without running. The first
       run may wait until you permit the pipeline to use the GitHub service connection and the `Default` pool.
    6. Project settings → Repositories → Security → "<project> Build Service (<organization>)": Contribute to pull
       requests = Allow.
    7. Project settings → Repositories → the repository → Policies → `main` → Build validation: the pipeline,
       automatic trigger, required.
35. Federation: add to `local/validation/session.tfvars`

    ```hcl
    ci_federation = {
      github = {
        issuer   = "https://token.actions.githubusercontent.com"
        subject  = "<sub_claim_prefix>:pull_request" # gh api repos/<owner>/<sample repository>/actions/oidc/customization/sub
        audience = "<workspace URL>/oidc/v1/token"
      }
      azure_devops = {
        issuer   = "https://vstoken.dev.azure.com/<organization ID>"
        subject  = "p://<organization>/<project>/<pipeline>"
        audience = "api://AzureADTokenExchange"
      }
    }
    ```

    then `validation/azure/run.sh plan baseline M2-federation` (expect two creates and nothing else) and run (**writes**)
    `validation/azure/run.sh apply baseline`.
36. C1 on both platforms: a branch `c1` that adds `terraform/main.tf`; open a pull request. Save the GitHub run
    (`gh run view --log`) and the comment (`gh api`) as `local/validation/M2-C1-github.*`.
    For Azure DevOps, export the run log and copy the comment text into `local/validation/M2-C1-ado.*`.
37. C2: push a second commit to the same branches that appends

    ```hcl
    resource "databricks_grant" "interns" {
      schema     = "${var.catalog}.sales"
      principal  = "gp-interns"
      privileges = ["USE_SCHEMA"]
    }
    ```

    Save the results as in step 36 (`M2-C2-*`). The comment must be the same one, updated.
38. C3: push a third commit to the same branches that changes only reachdiff's login: in
    `.github/workflows/reachdiff.yml` the action step's `DATABRICKS_CLIENT_ID`, and in `azure-pipelines.yml` the
    template's `clientId`, both to `00000000-0000-0000-0000-000000000000`. Terraform still logs in. Save as
    `M2-C3-*`, then push a fourth commit that reverts the third.
39. If the GitHub login fails ("Databricks login failed"): push a commit on `c1` that adds README "CI"'s debug step,
    read its output, fix the policy (the apply **writes**) and revert the debug commit. The exchange needs the
    workspace audience and GitHub's immutable subject, both in step 35. If Terraform rejects
    `azure-devops-oidc`: in `azure-pipelines.yml`, use `env-oidc` for the Terraform step with `DATABRICKS_OIDC_TOKEN`
    from a step that requests the job's OIDC token. If federation fails on the trial account
    altogether: use `oauth-m2m` with gp-scanner's scoped secret as in README "CI". Record every fallback in
    `results.md`.
40. Cleanup (before `destroy`): set `ci_federation = {}` and run (**writes**) `validation/azure/run.sh apply
    baseline`; delete the GitHub service connection, stop the agent
    (Ctrl-C) and remove it (`./config.sh remove`), disable both sample pipelines (GitHub: Actions → the workflow →
    Disable; Azure DevOps: pipeline → Settings → Disabled).

## F. Wrap-up

21. Finish `local/validation/results.md`:

    ```markdown
    | ID | Verdict (confirmed / refuted / unanswered) | Evidence file | Note |
    |---|---|---|---|
    ```

    One row per question Q1–Q10, scenario and probe.
22. **Writes:** `validation/azure/run.sh destroy`. It removes only the objects the kit created inside Databricks: delete
    the workspace's resource group in the Azure portal afterwards (the managed resource group goes with it).
23. Real plans and reports stay in `local/`: they can contain secrets and real names.
