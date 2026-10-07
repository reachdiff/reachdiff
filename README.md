# reachdiff

**Who gains or loses access to what when this Terraform plan is applied?**

reachdiff reads `terraform show -json` output for Databricks Unity Catalog grants
(`databricks_grants`, `databricks_grant`), group memberships (`databricks_group_member`)
and owners. It reports the **effective-access diff**, with the route behind each change, and
returns an exit code a pipeline can act on.

Status: beta. Live mode has been exercised against one Azure Databricks workspace; see
[Validated scope](#validated-scope) for what that covers and what it doesn't. The demo and tests use synthetic plans.

## Install

Python 3.11 or newer:

```bash
pip install reachdiff                  # offline mode, no dependencies
pip install 'reachdiff[databricks]'    # live mode, adds databricks-sdk
```

## Try the synthetic demo

Python 3.11 or newer, no dependencies:

```bash
python3 -m reachdiff plan --tfplan examples/schema-grant.plan.json --offline
```

It reports `analysts` gaining READ on all of `prod.sales` (3 members: 2 new, 1 already had it)
and `bob@example.com` losing WRITE on `prod.sales.orders`. Offline runs report what they couldn't
see, so the status is WARN.

![The synthetic demo in a terminal: reachdiff reports WARN, analysts gaining READ and bob losing WRITE](docs/demo/offline.gif)

The recording is made with [vhs](https://github.com/charmbracelet/vhs) from [`docs/demo/offline.tape`](docs/demo/offline.tape).

## Use it on a plan

```bash
terraform plan -out plan.bin
terraform show -json plan.bin > local/plan.json   # real plans can contain secrets: keep them out of Git
python3 -m venv .venv && .venv/bin/pip install -e '.[databricks]'
.venv/bin/reachdiff plan --tfplan local/plan.json --profile PROFILE --format md --output local/report.md
```

| Option | Meaning |
|---|---|
| `--offline` | Use only data in the plan. Anything Terraform doesn't manage is reported as a gap. |
| `--profile NAME` | Databricks SDK profile for live mode. Live mode only reads, and only the objects and groups the plan touches. Without a profile, live mode logs in from the SDK's environment variables and needs `DATABRICKS_AUTH_TYPE` (see [CI](#ci)). |
| `--deep` | Also read the child tables of changed schemas and catalogs. Live mode only: `--offline --deep` is a usage error (exit 3). |
| `--config FILE` | TOML rules (see below). |
| `--format text\|json\|md` | `md` is meant for PR comments. |
| `--fail-on block\|warn\|never` | Default `block`. |

Exit codes: `0` below the fail threshold, `1` WARN, `2` BLOCK, `3` invalid input, config or
authentication error, or any other operational failure. A live run in which no Databricks read
succeeds (a total outage) is exit 3, not a report full of gaps.

## Live mode setup

Live mode runs as a dedicated identity, usually a service principal in CI. It needs:

- **Workspace access:** assigned to the workspace with an entitlement. New workspaces give the `users` group none, and
  without one every API reachdiff calls is refused. `workspace-consume` is the least of the three the API accepts.
- **`READ METADATA`** on the metastore (it inherits to every object) or on each catalog in scope, so the permissions
  API returns every grant, not only the caller's own. Without it, reachdiff discards the list and reports
  `unreadable_object`, so the run cannot pass. `MANAGE` and ownership also work, but `MANAGE` lets the scanner grant
  itself data access.
- **An OAuth secret.** For a secret limited to API scopes (`unity-catalog`, `scim`, `access-management`), set the same
  `scopes` in the profile; the SDK otherwise requests `all-apis` and is refused. Set `auth_type = oauth-m2m`: without
  it the Databricks CLI silently falls back to other credentials, such as an `az login` session.
- **Group membership** comes from workspace SCIM, which shows members only to workspace admins. Without admin,
  reachdiff reports one `membership_incomplete` gap and "members not read", and runs that touch groups stay
  unverified. Making the scanner a workspace admin gives complete member counts but lets it change workspace settings
  and identities.

On Azure, the account console rejects personal Microsoft accounts: use a member user of your Entra ID directory.
`az login --allow-no-subscriptions` is enough for a user without an Azure subscription role.

## CI

Run reachdiff in the job that ran `terraform plan`, on the plan JSON in the runner's temporary directory. Never upload
the plan JSON as an artifact: it shows sensitive values in plain text.

The GitHub Action (`action.yml`) and the Azure DevOps template (`ci/azure-pipelines/reachdiff.yml`) install reachdiff
from their own checkout, run it, write the report to the run summary and, if asked, post one pull-request comment that
later runs update. reachdiff itself never posts. `ci/publish.py` does, and only:

- in private repositories and projects. Anywhere else, including GitHub `internal` repositories or when the
  visibility can't be read, the log gets only the status line, unless `allow-public` is set.
- on pull requests. On GitHub it never posts for a `pull_request_target` run from a fork.

An error replaces the comment with "reachdiff: ERROR", and a failed post fails the step with exit 3, so a comment never
shows an earlier, better status. A report too long for a comment (65,536 characters on GitHub, 150,000 on Azure
DevOps) is replaced by its status and a pointer to the run summary.

| Status | Exit code (default `fail_on = block`) | GitHub | Azure DevOps |
|---|---|---|---|
| PASS | 0 | success | succeeded |
| WARN below the threshold | 0 | success with a warning | succeeded with issues |
| WARN at the threshold, or BLOCK | 1 or 2 | failed | failed |
| ERROR | 3 | failed | failed |

**Login.** Without `--profile`, live mode logs in from the SDK's environment variables. Set them on the reachdiff step
only: `DATABRICKS_HOST`, `DATABRICKS_CLIENT_ID` and always `DATABRICKS_AUTH_TYPE`. reachdiff refuses live mode without
a profile or `DATABRICKS_AUTH_TYPE` (exit 3): the SDK would otherwise try every login it finds, such as the Terraform
deployer's `ARM_*` secrets or an `az login` session, and run with more visibility than the scanner has.

To store no secret in CI, use token federation (`github-oidc` or `azure-devops-oidc`) with a federation policy on the
scanning service principal. An account admin creates it in the account console or with the Terraform resource
`databricks_service_principal_federation_policy`:

| Platform | Issuer | Subject | Audience |
|---|---|---|---|
| GitHub Actions | `https://token.actions.githubusercontent.com` | `<prefix>:pull_request` | `https://<workspace host>/oidc/v1/token` |
| Azure DevOps | `https://vstoken.dev.azure.com/<organization ID>` | `p://ORGANIZATION/PROJECT/PIPELINE` | `api://AzureADTokenExchange` |

On GitHub, `<prefix>` is `sub_claim_prefix` from `gh api repos/OWNER/REPO/actions/oidc/customization/sub`. With
GitHub's immutable subject it includes the IDs, for example `repo:OWNER@OWNER_ID/REPO@REPO_ID`. The audience is the
one the workspace advertises (`token_federation_default_oidc_audiences` in
`https://<workspace host>/.well-known/databricks-config`), which the SDK requests. To use another audience, set the
same value in the policy and in `DATABRICKS_TOKEN_AUDIENCE`.

The scanning identity needs the privileges in [Live mode setup](#live-mode-setup). With a scoped OAuth secret
(`oauth-m2m`) instead: the SDK has no environment variable for `scopes`. Point `DATABRICKS_CONFIG_FILE` at a file that
holds only a profile with `scopes` and `auth_type = oauth-m2m`, set `DATABRICKS_CONFIG_PROFILE` to that profile, and
keep the secret in `DATABRICKS_CLIENT_SECRET`.

**If the login fails,** reachdiff exits 3 with "Databricks login failed" and the settings to check. It never prints
the SDK's message, which can name the host, the client ID and the token subject. To see it, add a temporary step
before reachdiff with the same `env:` (GitHub shown), in a private repository only, and remove it afterwards:

```yaml
- name: debug login (temporary)
  env: # the same DATABRICKS_* values as the reachdiff step
    DATABRICKS_HOST: ${{ vars.DATABRICKS_HOST }}
    DATABRICKS_CLIENT_ID: ${{ vars.SCANNER_CLIENT_ID }}
    DATABRICKS_AUTH_TYPE: github-oidc
  run: |
    python3 -m venv "$RUNNER_TEMP/dbg" && "$RUNNER_TEMP/dbg/bin/pip" install --quiet databricks-sdk==0.140.0
    "$RUNNER_TEMP/dbg/bin/python" - <<'EOF'
    import base64, json, os, urllib.parse, urllib.request
    host = os.environ['DATABRICKS_HOST'].rstrip('/')
    audience = json.load(urllib.request.urlopen(host + '/.well-known/databricks-config'))['token_federation_default_oidc_audiences'][0]
    url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'] + '&audience=' + urllib.parse.quote(audience, safe='')
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    claims = json.loads(base64.urlsafe_b64decode(json.load(urllib.request.urlopen(request))['value'].split('.')[1] + '=='))
    print({k: claims.get(k) for k in ('iss', 'sub', 'aud')}, 'aud is the advertised audience:', claims.get('aud') == audience)
    from databricks.sdk import WorkspaceClient
    try:
        print('logged in:', WorkspaceClient().current_user.me().active)
    except Exception as exc:
        print(type(exc).__name__, exc)
    EOF
```

### GitHub Actions

```yaml
permissions:
  contents: read
  pull-requests: write # the comment
  id-token: write # github-oidc
steps:
  # ... terraform plan -out "$RUNNER_TEMP/plan.bin" and show -json into "$RUNNER_TEMP/plan.json"
  - uses: reachdiff/reachdiff@f80e06059ef6d8be015dc2ccbf7702e7fcb90aa4 # v0.9.0
    with:
      plan-json: ${{ runner.temp }}/plan.json
      comment: true
    env:
      DATABRICKS_HOST: ${{ vars.DATABRICKS_HOST }}
      DATABRICKS_CLIENT_ID: ${{ vars.SCANNER_CLIENT_ID }}
      DATABRICKS_AUTH_TYPE: github-oidc
```

| Input | Default | Meaning |
|---|---|---|
| `plan-json` | required | Path to the `terraform show -json` output |
| `mode` | `live` | `live` or `offline` |
| `deep`, `config`, `fail-on` | off | As the CLI options |
| `comment` | `false` | Post or update the pull-request comment |
| `allow-public` | `false` | Write the summary and comment even if the repository is not private |
| `comment-key` | `default` | Keeps separate comments for several plans in one pull request |
| `github-token` | `github.token` | Used only for the comment |

Outputs: `status` (`PASS`, `WARN`, `BLOCK` or `ERROR`), `exit-code` and `report-path`. Pin the action to a full commit
SHA. While this repository is private, only repositories with the same owner can use it (Settings → Actions →
General → Access). Pull requests from forks get no secrets and no OIDC token, so live mode stops there with exit 3. A
full workflow is in [`examples/ci/github-workflow.yml`](examples/ci/github-workflow.yml).

### Azure DevOps

Check out this repository as a repository resource next to your own, with explicit paths (a second checkout otherwise
moves yours to `s/<repo name>`), then include the template after `terraform show -json`:

```yaml
resources:
  repositories:
    - repository: reachdiff
      type: github
      endpoint: GITHUB_CONNECTION
      name: reachdiff/reachdiff
      ref: f80e06059ef6d8be015dc2ccbf7702e7fcb90aa4 # v0.9.0
steps:
  - checkout: self
    path: self
  - checkout: reachdiff
    path: reachdiff
  # ... terraform plan and show -json into $(Agent.TempDirectory)/plan.json
  - template: ci/azure-pipelines/reachdiff.yml@reachdiff
    parameters:
      planJson: $(Agent.TempDirectory)/plan.json
      reachdiffPath: $(Pipeline.Workspace)/reachdiff
      host: $(DATABRICKS_HOST)
      clientId: $(SCANNER_CLIENT_ID)
      comment: true
```

The parameters match the action's inputs (`planJson`, `mode`, `deep`, `config`, `failOn`, `comment`, `allowPublic`,
`commentKey`), plus `python` (default `python3`, 3.11 or newer) and the login: `host`, `clientId` and `authType`
(default `azure-devops-oidc`). They are set on the reachdiff step only, so they never change how your Terraform steps
log in. Use the template once per job. Outputs: `reachdiff.status`, `reachdiff.exitCode`, `reachdiff.reportPath`.

The project's build service needs **Contribute to pull requests** on the repository (Project settings →
Repositories → Security). Pull requests run the pipeline through a build validation branch policy. A full pipeline is
in [`examples/ci/azure-pipelines.yml`](examples/ci/azure-pipelines.yml).

## Validated scope

Live mode was exercised from 1 to 3 October 2026 against one Azure Databricks trial workspace (Premium, classic compute)
with Terraform 1.16.4, provider `databricks/databricks` 1.135.0, Databricks CLI 1.19.0, databricks-sdk 0.140.0 and
Python 3.14. The objects, groups and grants were synthetic. The scenarios and predictions are in
[`validation/azure/`](validation/azure/); real plans and results stay outside the repository. These runs used the code
before its rename to reachdiff on 3 October 2026 (see [CHANGELOG.md](CHANGELOG.md)). From 4 to 6 October 2026 the
renamed code ran against the same workspace again, as the GitHub Action, the Azure DevOps template and the CLI, and
produced the predicted WARN and BLOCK reports.

Covered:

- Plan reading for `databricks_grants`, `databricks_grant`, `databricks_group_member` and owners on catalogs, schemas
  and tables, including replaced resources, values known only after apply and a literal provider host.
- Runs as the workspace's admin user and as a service principal with `workspace-consume` at four privilege levels on
  the catalog: none, `BROWSE`, `READ METADATA`, and `READ METADATA` with `BROWSE`, `USE CATALOG` and `USE SCHEMA`.
  `READ METADATA` on the catalog alone gave complete grant, owner and tag reads. Below it, every grant list was
  discarded and no run passed.
- The visibility self-check against real SCIM `Me` and effective-permissions responses.
- Ownership: a service principal that owned a table without a `SELECT` grant could read it, and was refused `SELECT`
  on a table it did not own.
- A plan that only changes the case of a schema name reports no change.
- Group membership read without workspace admin: one `membership_incomplete` gap, "members not read".
- Paginated listings with `--deep`, tags on tables and columns, and the SDK errors `Unauthenticated`,
  `PermissionDenied` and `NotFound`.
- CI, on 2 and 3 October 2026: the GitHub Action on a GitHub-hosted Ubuntu runner (Python 3.11) and the Azure DevOps
  template on a self-hosted macOS agent (Python 3.14). reachdiff logged in as the scanning service principal by token
  federation (`github-oidc`, `azure-devops-oidc`) with the policy settings under [CI](#ci); no fallback login was
  needed. The pull request comment (a thread on Azure DevOps) was created once, then updated in place, and the job
  results matched WARN, BLOCK and ERROR. With a wrong client ID for reachdiff only, the run ended in ERROR without
  falling back to another login, also on the self-hosted agent, where a CLI profile and an Azure CLI login existed.
- Data classification, on 3 October 2026: with automatic tagging on for the class, it tagged an email column
  `class.email_address`, which the default `[sensitive].tags` pattern `class.*` matches. Without automatic tagging,
  classification only reports its detections and writes no tags.

Not covered:

- AWS and GCP, serverless workspaces, and more than one workspace or metastore.
- `READ METADATA` granted on the metastore rather than the catalog; visibility through `MANAGE`, ownership or
  metastore admin (unit tests only); a scanner that is workspace admin.
- Terraform's own token federation login in CI: the sample plan only created resources, so `terraform plan` made no
  Databricks request.
- Microsoft-hosted Azure DevOps agents, GitHub pull requests from forks, and public repositories or projects (the
  refusal is covered by unit tests only).
- Everything under [Not evaluated](#not-evaluated), including runtime behavior such as the gap between destroying and
  recreating a replaced `databricks_grants` resource.

## Rules

Built-in rules default to WARN: `broad_principal`, `broad_privilege`, `individual_owner`, `sensitive_access` and
`unverified`. `grant_resource_conflict` defaults to BLOCK: it fires when a plan changes access and more than one
resource sets the grants on one securable (`conflicting_grant_resources` below). The applied result then depends on
apply order, and grants can be lost without an error: in the live session, moving grants from `databricks_grants` to
`databricks_grant` removed every grant on a table. `unverified` reports what reachdiff couldn't see. It can be raised
to BLOCK but never turned off. Among the gaps it reports:

- `latent_grants` and `deactivated_grants`: a usage privilege (`USE_CATALOG`, `USE_SCHEMA`,
  `ALL_PRIVILEGES`) is granted or revoked on a catalog or schema, so grants below it may start or
  stop working. Without `--deep` they are not enumerated. With `--deep` they appear as gains and
  losses.
- `conflicting_grant_resources`: more than one resource sets the grants on one securable
  (`databricks_grants` with `databricks_grant`, two `databricks_grants`, or two `databricks_grant` for the same
  principal), so the applied result depends on apply order.
- `sensitivity_not_evaluated`: a schema- or catalog-level gain without `--deep`, or, with `--deep`,
  a gain over tables the plan doesn't change. Column tags are read only for changed tables, so child
  column tags are reported as a gap.

```toml
fail_on = "block"

[sensitive]
tags = ["pii*", "sensitive*", "class.*"]

[[rule]]
id = "pii-only-approved-groups"
severity = "BLOCK"
sensitive = true
unless_via = ["pii-readers"]
message = "New access to PII outside approved groups"
```

Configured rules fail closed. They match every row before child rows collapse into parent rows. An
`objects` glob also matches rows on a parent of the objects it names (`prod.*` matches a
catalog-level row on `prod`). `principal_kinds` also matches principals whose kind is unknown.

## Handle reports with care

Reports contain principal and object names. Don't post them as comments in public repositories.
reachdiff never posts anywhere itself; the CI publish script withholds reports outside private repositories (see
[CI](#ci)).

## Not evaluated

- ABAC policies, row filters and column masks
- volumes, functions and external locations
- workspace-level ACLs
- metastore and workspace admin powers
- identity-provider membership completeness
- runtime behavior

## Development

```bash
python3 -m unittest discover -v
```

`pre-commit install` adds hooks that run ruff (`ruff check`, `ruff format`) and gitleaks on every commit; gitleaks must
be on your PATH (for example `brew install gitleaks`). CI runs the tests on Python 3.11 and 3.14, the same ruff checks
and a gitleaks scan of the history. Fake values that look like secrets go into `.gitleaks.toml`, with their source.

Tests also run on sanitized plans and API responses from the live sessions (`tests/fixtures/real/`). To refresh them
from the ignored `local/validation/`, run `python3 -m validation.sanitize`; it copies only what reachdiff reads,
replaces identifiers with placeholders and refuses to write output that still looks like it holds one. Read each
fixture diff before committing.

## Licence and trademarks

Apache License 2.0, see [LICENSE](LICENSE).

reachdiff is an independent project, not affiliated with or endorsed by Databricks or HashiCorp. Databricks, Unity
Catalog and Terraform are trademarks of their owners.
