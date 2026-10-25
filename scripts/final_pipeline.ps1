# Final run, end to end: baseline evals -> GRPO training (auto-resume) -> trained evals.
# Runs in its own PowerShell window so it survives the Claude Code session.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\final_pipeline.ps1
#   powershell ... -File scripts\final_pipeline.ps1 -Config configs/hardened_coder15_mixed.yaml `
#       -Run runs\hardened_coder15 -Tag hardened
#
# Progress: runs\<Tag>_pipeline.log ; per-step output: runs\<Tag>_<step>.out/.err
# Results: results\eval_<Tag>_{base,trained}_*.json and results\compare_<Tag>_*.md

param(
    [string]$Config = "configs/final_coder15_mixed.yaml",
    [string]$Run = "runs\final_coder15",
    [string]$Tag = "final",
    [string]$Base = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
)

Set-Location (Split-Path -Parent $PSScriptRoot)
$env:HF_HUB_OFFLINE = "1"
$env:PYTHONIOENCODING = "utf-8"
$py = (Resolve-Path ".\.venv\Scripts\python.exe").Path
$log = "runs\${Tag}_pipeline.log"
$base = $Base
$run = $Run
New-Item -ItemType Directory -Force runs | Out-Null

function Step([string]$name, [string[]]$arguments) {
    # Re-runs skip evals whose results already exist (resume after a stop).
    $tagIdx = [array]::IndexOf($arguments, "--tag")
    if ($tagIdx -ge 0 -and (Test-Path "results\eval_$($arguments[$tagIdx + 1]).json")) {
        Add-Content $log "=== $name skipped (results exist)"
        return 0
    }
    Add-Content $log "=== $name start $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    $p = Start-Process -FilePath $py -ArgumentList $arguments -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput "runs\${Tag}_$name.out" -RedirectStandardError "runs\${Tag}_$name.err"
    Add-Content $log "=== $name exit $($p.ExitCode) $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    Write-Host "$name finished (exit $($p.ExitCode))"
    return $p.ExitCode
}

function Evals([string]$model, [string]$who) {
    Step "${who}_proc" @("scripts/evaluate.py", "--model", $model, "--k", "4", "--test-per-family", "25",
        "--difficulties", "2", "--max-new-tokens", "512", "--tag", "${Tag}_${who}_proc") | Out-Null
    Step "${who}_spl" @("scripts/evaluate.py", "--model", $model, "--families", "none", "--sources", "seccodeplt",
        "--k", "4", "--max-new-tokens", "512", "--tag", "${Tag}_${who}_spl") | Out-Null
    Step "${who}_cweval" @("scripts/evaluate.py", "--model", $model, "--families", "none", "--sources", "cweval",
        "--k", "8", "--max-new-tokens", "512", "--tag", "${Tag}_${who}_cweval") | Out-Null
    Step "${who}_ci_hint" @("scripts/probe_report.py", "--model", $model, "--families", "code_injection",
        "--difficulty", "1", "--k", "8", "--tag", "${Tag}_${who}_ci_hint") | Out-Null
}

Add-Content $log "=== PIPELINE START $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
if (-not (Test-Path "results\eval_${Tag}_base_cweval.json")) { Evals $base "base" }

for ($attempt = 1; $attempt -le 3; $attempt++) {
    if (Test-Path "$run\adapter_model.safetensors") { break }
    $trainArgs = @("scripts/train_grpo.py", "--config", $Config, "--no-eval")
    if (Get-ChildItem "$run\checkpoint-*" -ErrorAction SilentlyContinue) { $trainArgs += "--resume" }
    Step "train_attempt$attempt" $trainArgs | Out-Null
}

$model = $run
if (-not (Test-Path "$run\adapter_model.safetensors")) {
    $last = Get-ChildItem "$run\checkpoint-*" -ErrorAction SilentlyContinue |
        Sort-Object { [int]($_.Name -replace '\D', '') } | Select-Object -Last 1
    if ($last) { $model = $last.FullName; Add-Content $log "=== training incomplete; evaluating $($last.Name)" }
    else { Add-Content $log "=== PIPELINE FAILED: no trained model"; exit 1 }
}
Evals $model "trained"
foreach ($s in @("proc", "spl", "cweval")) {
    Step "compare_$s" @("scripts/compare_evals.py", "results/eval_${Tag}_base_$s.json",
        "results/eval_${Tag}_trained_$s.json", "--out", "results/compare_${Tag}_$s.md") | Out-Null
}
Add-Content $log "=== PIPELINE DONE $(Get-Date -Format 'yyyy-MM-dd HH:mm') model=$model"
Write-Host "Pipeline done. You can close this window."
