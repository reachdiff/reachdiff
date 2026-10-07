#!/usr/bin/env bash
# Live-session helper. All output goes to the ignored local/validation/. README.md says when each command runs.
#   run.sh plan SCENARIO [NAME]          terraform plan and show -json into NAME.plan.json (reads, changes nothing)
#   run.sh report PLAN NAME [OPTIONS]    reachdiff text and JSON reports on PLAN.plan.json; exit codes in NAME.exits
#   run.sh apply SCENARIO                terraform apply (writes; read run.sh plan first)
#   run.sh readback NAME TYPE FULL_NAME  databricks grants get as gp-trial into NAME.readback.json
#   run.sh destroy                       terraform destroy (writes; the workspace itself stays)
set -euo pipefail
root=$(git rev-parse --show-toplevel)
out="$root/local/validation"
vars="$out/session.tfvars"
tf=(terraform -chdir="$root/validation/azure/terraform")
mkdir -p "$out"
command=${1:?usage: run.sh plan|report|apply|readback|destroy ...}
shift
case "$command" in
  plan)
    name=${2:-$1}
    "${tf[@]}" plan -input=false -var-file="$vars" -var "scenario=$1" -out="$out/$name.tfplan"
    "${tf[@]}" show -json "$out/$name.tfplan" > "$out/$name.plan.json" ;;
  report)
    plan=$1 name=$2
    shift 2
    for format in text json; do
      status=0
      "$root/.venv/bin/reachdiff" plan --tfplan "$out/$plan.plan.json" --format "$format" \
        --output "$out/$name.report.$format" "$@" 2>> "$out/$name.stderr" || status=$?
      echo "$format: exit $status" | tee -a "$out/$name.exits"
    done ;;
  apply)
    "${tf[@]}" apply -input=false -auto-approve -var-file="$vars" -var "scenario=$1" ;;
  readback)
    databricks grants get "$2" "$3" --profile gp-trial -o json > "$out/$1.readback.json" ;;
  destroy)
    "${tf[@]}" destroy -input=false -auto-approve -var-file="$vars" ;;
  *)
    echo "unknown command: $command" >&2
    exit 2 ;;
esac
