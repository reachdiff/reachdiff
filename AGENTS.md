# Working agreements

For anyone changing this repository, human or coding agent.

## Scope and approval

- Larger changes start with a short written design (scope, acceptance criteria), then an implementation plan. The
  maintainer reviews both before implementation starts.
- Don't implement features or change behavior without an approved plan. Ask before changing scope. Read-only
  investigation and requested planning are always fine.
- Keep implementations and tests lean. Test consequential domain behavior; avoid test matrices or infrastructure that
  don't serve the change.

## Design rules

- Only the live collector (`reachdiff/collect/live.py`) talks to Databricks, and only with read requests. Plan
  reading, state, resolution, diff, rules and reporting stay pure and testable with fixtures.
- Distinguish synthetic local checks, SDK, API and provider assumptions, and validation against a real workspace.
  Don't describe a behavior as validated until it has run against a real workspace; README "Validated scope" says
  what has.
- Anything reachdiff can't see is reported as a finding, never treated as "no change".

## Secrets and real data

- Terraform plan JSON can contain secrets. Never copy attributes of unrelated resources into reports, fixtures or
  logs. Keep real plans and reports under the ignored `local/`.
- Fixtures from real runs go through `validation/sanitize.py` and a manual read of the diff before they are committed.
- Never commit secrets, tokens, workspace hosts or identifiers. Stage files by name and let the pre-commit hooks
  (ruff, gitleaks) run.
- The validation kit (`validation/azure/`) writes to the workspace it points at. Run it only against a disposable
  workspace, in a session the maintainer leads.

## CI and releases

- Third-party actions are pinned by full commit SHA.
- `main` requires the CI checks. A release is a `vX.Y.Z` tag matching `pyproject.toml`'s version; the Release workflow
  publishes it to PyPI by trusted publishing.
