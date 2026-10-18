#!/usr/bin/env bash
# Container entrypoint for a GPU training job (AWS Batch or any GPU host).
#
# Fire-and-forget: it trains, then uploads everything to S3, so no one has to
# stay connected. Resumable: if a checkpoint already exists in S3 (e.g. after a
# spot interruption) it is pulled back first and training continues.
#
# Driven entirely by environment variables (set in the Batch job definition):
#   S3_OUTPUT      s3://bucket/prefix   (required) where results are written
#   CONFIG         config path          (default configs/final_coder15_mixed.yaml)
#   MAX_STEPS      override max_steps    (optional)
#   REPO_GIT       git URL to clone instead of using the baked-in code (optional)
#   REPO_REF       branch/tag/sha for REPO_GIT (optional, default main)
#   HF_TOKEN       Hugging Face token    (optional; only if a gated model is used)
set -euo pipefail

: "${S3_OUTPUT:?set S3_OUTPUT to s3://bucket/prefix}"
CONFIG="${CONFIG:-configs/final_coder15_mixed.yaml}"
RUN_DIR="runs/$(basename "${CONFIG%.*}")"

echo "== GPU =="; nvidia-smi -L || echo "WARNING: no GPU visible to the container"

if [ -n "${REPO_GIT:-}" ]; then
  echo "== cloning ${REPO_GIT}@${REPO_REF:-main} =="
  rm -rf /workspace/src && git clone --depth 1 -b "${REPO_REF:-main}" "$REPO_GIT" /workspace/src
  cd /workspace/src && export PYTHONPATH=/workspace/src
else
  cd /workspace
fi

echo "== grader isolation =="; python -c "from cybersec_env import sandbox; print(sandbox.isolation_level())" || true

# Resume: pull any prior checkpoint for this run from S3.
echo "== syncing prior checkpoints (if any) from ${S3_OUTPUT}/${RUN_DIR} =="
aws s3 sync "${S3_OUTPUT}/${RUN_DIR}" "${RUN_DIR}" --only-show-errors || true
RESUME=""
if [ -d "${RUN_DIR}" ] && ls "${RUN_DIR}"/checkpoint-* >/dev/null 2>&1; then
  RESUME="--resume"
  echo "   found a checkpoint -> will resume"
fi

STEP_ARG=""
[ -n "${MAX_STEPS:-}" ] && STEP_ARG="--max-steps ${MAX_STEPS}"

echo "== training: ${CONFIG} ${RESUME} ${STEP_ARG} =="
set +e
python scripts/train_grpo.py --config "${CONFIG}" --no-eval ${RESUME} ${STEP_ARG}
TRAIN_RC=$?
set -e

echo "== uploading results to ${S3_OUTPUT}/${RUN_DIR} (train rc=${TRAIN_RC}) =="
aws s3 sync "${RUN_DIR}" "${S3_OUTPUT}/${RUN_DIR}" --only-show-errors || true
# also save a small marker with the exit status for easy checking
echo "{\"train_rc\": ${TRAIN_RC}, \"config\": \"${CONFIG}\", \"finished\": \"$(date -u +%FT%TZ)\"}" \
  | aws s3 cp - "${S3_OUTPUT}/${RUN_DIR}/_status.json" || true

echo "== done; results at ${S3_OUTPUT}/${RUN_DIR} =="
exit ${TRAIN_RC}
