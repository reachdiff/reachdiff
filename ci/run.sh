#!/usr/bin/env bash
# Install reachdiff from this checkout into a virtual environment and run it on one plan, for action.yml and
# ci/azure-pipelines/reachdiff.yml. Writes $OUT/report.md and never prints the report. Exits with reachdiff's exit
# code, or 3 when the setup fails, so a broken install never reads as WARN (1) or BLOCK (2).
# Environment: PYTHON, REACHDIFF_PATH, OUT, PLAN_JSON, MODE (live|offline), DEEP, CONFIG, FAIL_ON.
mkdir -p "$OUT" && rm -f "$OUT/report.md" || exit 3
case "$MODE" in
  live) spec="$REACHDIFF_PATH[databricks]"; args=() ;;
  offline) spec="$REACHDIFF_PATH"; args=(--offline) ;;
  *) echo "reachdiff: error: mode must be live or offline" >&2; exit 3 ;;
esac
case "$DEEP" in true | True) args+=(--deep) ;; esac
if [ -n "$CONFIG" ]; then args+=(--config "$CONFIG"); fi
if [ -n "$FAIL_ON" ]; then args+=(--fail-on "$FAIL_ON"); fi
"$PYTHON" -m venv "$OUT/venv" || exit 3
"$OUT/venv/bin/pip" install --quiet --disable-pip-version-check "$spec" || exit 3
"$OUT/venv/bin/reachdiff" plan --tfplan "$PLAN_JSON" "${args[@]}" --format md --output "$OUT/report.md"
