# Train on a GPU via AWS Batch (fire-and-forget)

Run a GPU training job without owning a GPU instance: Batch spins up a GPU EC2
host, runs the container, saves results to S3, and tears the host down. You pay
only for the minutes it runs.

> **Read this first — the one thing that blocks everything.** A Batch GPU job
> launches a **G/P-family EC2 instance**, which needs **On-Demand GPU vCPU
> quota**. New and student/free-tier accounts often have this at **0**, and then
> the job sits in `RUNNABLE` forever and never starts. Check and, if needed,
> request an increase *before* building anything:
>
> ```
> aws service-quotas get-service-quota --service-code ec2 \
>   --quota-code L-DB2E81BA --region $AWS_REGION   # "Running On-Demand G and VT instances"
> ```
> You need at least the instance's vCPU count (g4dn.xlarge = 4). If it is 0,
> open Service Quotas → EC2 → that quota → request increase (can take 1–2 days).
> AWS Batch does **not** bypass this; it is the same quota that blocks launching
> a GPU instance directly.

## What's here
- `Dockerfile.train` — CUDA + PyTorch image with the training stack, the grader
  deps, and the repo baked in.
- `entrypoint.sh` — trains, then uploads results to S3; resumes from an S3
  checkpoint if one exists (spot-friendly).
- `job-definition.json` — the Batch job definition (1 GPU, 4 vCPU, 15 GB).
- `submit.sh` — build + push to ECR, register, submit (`--wait` to poll + pull).

## GPU instance choice
- `g4dn.xlarge` — 1× **T4 16 GB**, cheapest GPU; fine for Qwen2.5-Coder-1.5B
  LoRA (the proven config) and 3B with 4-bit QLoRA.
- `g5.xlarge` — 1× **A10G 24 GB**; headroom for 7B QLoRA.
Pick this when you create the compute environment (below).

## One-time setup
```bash
export AWS_REGION=us-east-1 ACCOUNT=<your-account-id> BUCKET=<new-bucket-name> QUEUE=pgym-gpu-queue

# 1. S3 bucket for outputs
aws s3 mb "s3://$BUCKET" --region $AWS_REGION

# 2. IAM roles (two): a job role the container uses to write S3, and the Batch
#    execution role to pull from ECR + write logs. Give the job role
#    s3:PutObject/GetObject/ListBucket on your bucket. (Console or CLI; see AWS
#    "Batch IAM roles" docs. Names must match job-definition.json:
#    pgym-batch-job-role, pgym-batch-execution-role.)

# 3. A GPU compute environment + job queue (console is easiest):
#    Batch → Compute environments → create (managed, EC2, instance type g4dn.xlarge,
#    min vCPUs 0, max vCPUs 4–8) → create a Job queue named $QUEUE on it.
```

## Run it
```bash
# builds the image, pushes to ECR, registers the job def, submits:
bash aws/submit.sh            # returns a jobId; results land in s3://$BUCKET/pgym/
# or, to also watch it and pull results down when done:
bash aws/submit.sh --wait
```
Results (LoRA adapter, logs, `_status.json`) appear under
`s3://$BUCKET/pgym/runs/final_coder15/`. Pull anytime:
```bash
aws s3 sync s3://$BUCKET/pgym ./runs_from_s3
```

## Notes
- **Fire-and-forget beats babysitting.** The job self-uploads to S3, so you need
  not stay connected (important if you drive this from a session that can end).
- **Cost control:** set the compute environment's max vCPUs low (4–8) and use
  **Spot** instances to cut cost ~70%; `entrypoint.sh` resumes from the last S3
  checkpoint if Spot reclaims the host.
- **The grader inside the container** auto-detects that bubblewrap can't create
  user namespaces (unprivileged container) and falls back to process-only
  isolation — correct and safe for our *own* training (the OS jail matters for
  grading *hostile* code, not for the reward during training).
- **Overrides** via the job definition's `environment` (or `submit-job
  --container-overrides`): `CONFIG`, `MAX_STEPS`, `REPO_GIT`+`REPO_REF` (clone a
  branch instead of the baked-in code), `HF_TOKEN` (only if you switch to a
  gated base model).
