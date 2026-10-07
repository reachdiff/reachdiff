# Contributing

- For anything larger than a small fix, open an issue first.
- Set up: `python3 -m venv .venv && .venv/bin/pip install -e '.[databricks]'`, then
  `.venv/bin/python -m unittest discover -v`.
- Install the hooks with `pre-commit install`. They run ruff and gitleaks; gitleaks must be on your PATH.
- Never put real plans, reports, workspace hosts or identifiers into issues, fixtures or tests. Terraform plans can
  contain secrets.
- Contributions are accepted under the Apache License 2.0 (section 5).
