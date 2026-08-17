#!/usr/bin/env bash
# Bulk-apply per-instance IAM self-manage bindings for N VMs.
# Usage:
#   1. Fill instances.csv (same directory), format: instance_name,zone  (one per line, no header)
#   2. ./bulk-iam-setup.sh <PROJECT_ID> [SERVICE_ACCOUNT_NAME] [ROLE_NAME]
#
# Safe to re-run: gcloud IAM bindings are idempotent (adding the same
# member/role/condition twice is a no-op).

set -euo pipefail

PROJECT_ID="${1:?Usage: $0 <PROJECT_ID> [service_account_name] [role_name]}"
SA_NAME="${2:-acm-agent}"
ROLE_NAME="${3:-antiCryptoMinerdSelfManage}"
CSV_FILE="$(dirname "$0")/instances.csv"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if [[ ! -f "$CSV_FILE" ]]; then
  echo "Khong tim thay $CSV_FILE. Tao file voi noi dung dang:" >&2
  echo "vm-01,asia-southeast1-a" >&2
  echo "vm-02,asia-southeast1-b" >&2
  exit 1
fi

echo "== 1/3: Tao custom role (bo qua neu da ton tai) =="
if ! gcloud iam roles describe "$ROLE_NAME" --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam roles create "$ROLE_NAME" \
    --project="$PROJECT_ID" \
    --title="Anti-CryptoMinerd Self Manage" \
    --description="Cho phep 1 VM dung/xoa chinh no khi phat hien dao coin" \
    --permissions=compute.instances.get,compute.instances.stop,compute.instances.delete \
    --stage=GA
else
  echo "Role $ROLE_NAME da ton tai, bo qua."
fi

echo "== 2/3: Tao service account (bo qua neu da ton tai) =="
if ! gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$SA_NAME" \
    --project="$PROJECT_ID" \
    --display-name="AntiCryptoMinerd agent"
else
  echo "Service account $SA_EMAIL da ton tai, bo qua."
fi

echo "== 3/3: Gan IAM Condition cho tung instance trong $CSV_FILE =="
count=0
while IFS=',' read -r instance_name zone; do
  [[ -z "$instance_name" || "$instance_name" == \#* ]] && continue
  instance_name="$(echo "$instance_name" | xargs)"
  zone="$(echo "$zone" | xargs)"
  echo "  -> $instance_name ($zone)"

  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="projects/${PROJECT_ID}/roles/${ROLE_NAME}" \
    --condition="expression=resource.name.endsWith('/instances/${instance_name}'),title=self-only-${instance_name}" \
    --quiet >/dev/null

  # Gan service account vao VM. VM phai dang STOPPED de doi service account.
  status="$(gcloud compute instances describe "$instance_name" --zone="$zone" --project="$PROJECT_ID" --format='value(status)')"
  if [[ "$status" != "TERMINATED" ]]; then
    gcloud compute instances stop "$instance_name" --zone="$zone" --project="$PROJECT_ID" --quiet
  fi
  gcloud compute instances set-service-account "$instance_name" \
    --zone="$zone" --project="$PROJECT_ID" \
    --service-account="${SA_EMAIL}" \
    --scopes="https://www.googleapis.com/auth/cloud-platform" --quiet
  gcloud compute instances start "$instance_name" --zone="$zone" --project="$PROJECT_ID" --quiet

  count=$((count + 1))
done < "$CSV_FILE"

echo "Hoan tat: $count instance da duoc gan role + service account."
echo "Kiem tra lai bang:"
echo "  gcloud projects get-iam-policy $PROJECT_ID --flatten=\"bindings[].members\" --filter=\"bindings.members:${SA_EMAIL}\" --format=\"table(bindings.role,bindings.condition.title)\""
