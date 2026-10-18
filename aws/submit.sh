#!/usr/bin/env bash
# Build+push the training image, register the job definition, and submit a Batch
# job. Fire-and-forget by default; pass --wait to poll and then pull results.
#
#   export AWS_REGION=us-east-1 ACCOUNT=123456789012 BUCKET=my-pgym-bucket
#   export QUEUE=pgym-gpu-queue        # your Batch job queue (GPU compute env)
#   bash aws/submit.sh            # build, push, register, submit (returns a job id)
#   bash aws/submit.sh --wait     # also poll to completion and sync results down
#
# Prereqs (one-time, see aws/README.md): an ECR repo `pgym-train`, an S3 bucket,
# the two IAM roles, and a GPU compute environment + job queue. CRITICAL: your
# account must have EC2 G/P On-Demand quota, or the job stays RUNNABLE forever.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${AWS_REGION:?set AWS_REGION}"; : "${ACCOUNT:?set ACCOUNT}"
: "${BUCKET:?set BUCKET}"; : "${QUEUE:?set QUEUE (Batch job queue name)}"
ECR="${ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com"
IMAGE="${ECR}/pgym-train:latest"
JOBDEF="${JOBDEF:-pgym-train}"

echo "== 0. pre-flight: GPU quota check =="
# L-DB2E81BA = Running On-Demand G and VT instances. 0 here means Batch can
# never place the job. (P-family has its own code; check both if you use P.)
GQ=$(aws service-quotas get-service-quota --service-code ec2 \
      --quota-code L-DB2E81BA --region "$AWS_REGION" \
      --query 'Quota.Value' --output text 2>/dev/null || echo "unknown")
echo "   G/VT On-Demand vCPU quota: ${GQ}  (needs >= the instance's vCPUs, e.g. 4 for g4dn.xlarge)"
[ "$GQ" = "0.0" ] && echo "   WARNING: quota is 0 — request an increase before submitting."

echo "== 1. ECR login + build + push =="
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ECR"
aws ecr describe-repositories --repository-names pgym-train --region "$AWS_REGION" >/dev/null 2>&1 \
  || aws ecr create-repository --repository-name pgym-train --region "$AWS_REGION" >/dev/null
docker build -f aws/Dockerfile.train -t "$IMAGE" .
docker push "$IMAGE"

echo "== 2. register job definition =="
TMP=$(mktemp)
sed -e "s|<ACCOUNT>|${ACCOUNT}|g" -e "s|<REGION>|${AWS_REGION}|g" \
    -e "s|<BUCKET>|${BUCKET}|g" aws/job-definition.json > "$TMP"
REV=$(aws batch register-job-definition --cli-input-json "file://$TMP" \
      --region "$AWS_REGION" --query 'revision' --output text)
echo "   registered ${JOBDEF}:${REV}"

echo "== 3. submit =="
JOB_ID=$(aws batch submit-job --job-name "pgym-$(date +%s)" --job-queue "$QUEUE" \
         --job-definition "${JOBDEF}:${REV}" --region "$AWS_REGION" \
         --query 'jobId' --output text)
echo "   jobId: ${JOB_ID}"
echo "   results will appear under s3://${BUCKET}/pgym/ when it finishes."

if [ "${1:-}" = "--wait" ]; then
  echo "== 4. polling (Ctrl-C is safe; the job keeps running) =="
  while true; do
    ST=$(aws batch describe-jobs --jobs "$JOB_ID" --region "$AWS_REGION" \
         --query 'jobs[0].status' --output text)
    echo "   $(date +%T) status=${ST}"
    case "$ST" in
      SUCCEEDED) aws s3 sync "s3://${BUCKET}/pgym" "./runs_from_s3" --only-show-errors; echo "pulled to ./runs_from_s3"; break;;
      FAILED) echo "job FAILED — check CloudWatch logs"; exit 1;;
    esac
    sleep 30
  done
fi
