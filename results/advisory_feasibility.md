# Advisory feasibility — codebase security track

Source: OSV PyPI database (/tmp/claude-1000/-mnt-batch-tasks-shared-LS-root-mounts-clusters-rl-env-training-code/fe45aa7d-7408-4b5f-826f-371129a95a88/scratchpad/osv/all.zip), analysed 2026-10-17.

| stage | advisories |
|---|---|
| 0. all PyPI advisories | 26379 |
| 1. published >= 2024-06-01 | 13600 |
| 2. with a GitHub **fix commit** | 4627 |
| 2b. and GitHub-reviewed (curated) | 1980 |

## Stage-2 advisories (recent + fix commit) by CWE — top 20

| CWE | count |
|---|---|
| unknown | 2663 |
| CWE-22 | 240 |
| CWE-918 | 122 |
| CWE-79 | 114 |
| CWE-400 | 108 |
| CWE-94 | 100 |
| CWE-502 | 100 |
| CWE-770 | 88 |
| CWE-200 | 74 |
| CWE-862 | 60 |
| CWE-20 | 55 |
| CWE-1333 | 46 |
| CWE-89 | 44 |
| CWE-306 | 41 |
| CWE-78 | 40 |
| CWE-639 | 40 |
| CWE-863 | 39 |
| CWE-73 | 35 |
| CWE-287 | 35 |
| CWE-787 | 29 |

## Stage 3 — fix-commit-touches-test, sampled

GitHub auth: anonymous (~60/hr); sampling up to 40 of 4627 fix commits.

- fix commits checked: **39**
- of those, touched a test file: **27** (69%)
- → projected usable tasks (stage 2 x rate): **~3203** of 4627

### Reading this

Stage 2 is the ceiling for a quick Docker track; stage 3's rate is the fraction of those that already ship a fail-to-pass test, i.e. buildable with little manual test-writing. The rest would need a hand-written proof-of-vulnerability test, which is slower but higher-value.
