# PR Auto Merge Implementation Plan

<!-- markdownlint-disable MD001 MD013 -->

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a low-risk PR eligibility checker and an owner-approved merge workflow that works in the current GitHub Free private repository.

**Architecture:** A deterministic Python module classifies PRs from git refs and task contracts. A read-only pull-request workflow reports eligibility, while a separate comment-triggered workflow runs only the trusted `main` version of the checker and merges the exact approved SHA.

**Tech Stack:** Python 3.11 standard library, `unittest`, GitHub Actions, GitHub CLI, Markdown.

---

### Task 1: Task contract and execution state

**Files:**

- Modify: `docs/研发中心/任务/任务-000013.md`
- Modify: `docs/研发中心/看板.md`
- Create: `docs/plans/2026-07-23-pr-auto-merge-design.md`

- [ ] **Step 1: Record the approved architecture decision**

Set task-000013 to `执行中`, record branch and start time, replace the paid-plan blocker
with the user's decision to use a maintainable current-plan implementation, and define inputs,
outputs, scope, safety boundaries, validation and completion.

- [ ] **Step 2: Synchronize the board**

Move task-000013 from `阻塞` to `执行中` and record
`agent/000013-pr-auto-merge-v1`.

- [ ] **Step 3: Validate the governance-only change**

Run:

```bash
npx --yes markdownlint-cli2 \
  docs/plans/2026-07-23-pr-auto-merge-design.md \
  docs/研发中心/任务/任务-000013.md \
  docs/研发中心/看板.md
git diff --check
```

Expected: `0 error(s)` and no whitespace errors.

- [ ] **Step 4: Commit the execution contract**

```bash
git add \
  docs/plans/2026-07-23-pr-auto-merge-design.md \
  docs/研发中心/任务/任务-000013.md \
  docs/研发中心/看板.md
git commit -m "chore: 启动任务-000013自动合并治理"
```

### Task 2: Eligibility checker through TDD

**Files:**

- Create: `tests/研发中心/test_验证自动合并资格.py`
- Create: `scripts/研发中心/验证自动合并资格.py`

- [ ] **Step 1: Write failing policy tests**

Create tests using `unittest` for:

```python
def test_低风险治理文档且任务待评审时允许()
def test_缺少任务编号时拒绝()
def test_基线任务类型缺失时拒绝()
def test_pr不能通过修改任务类型获得资格()
def test_修改工作流时拒绝()
def test_关联任务未进入待评审时拒绝()
def test_外部仓库pr时拒绝()
def test_修改未引用任务文件时拒绝()
```

Each test must call the public `evaluate_eligibility(...)` function with explicit changed
paths, PR body, base task contents and head task contents.

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
python3 -m unittest tests/研发中心/test_验证自动合并资格.py -v
```

Expected: fail because `scripts/研发中心/验证自动合并资格.py` does not exist.

- [ ] **Step 3: Implement the minimal policy engine**

Implement:

```python
@dataclass(frozen=True)
class EligibilityResult:
    eligible: bool
    reasons: tuple[str, ...]


def evaluate_eligibility(
    *,
    changed_paths: Sequence[str],
    pr_body: str,
    base_tasks: Mapping[str, str],
    head_tasks: Mapping[str, str],
    base_branch: str,
    repository: str,
    head_repository: str,
) -> EligibilityResult:
    ...
```

Allowed base task types are exactly `文档`, `治理`, and `研究规范`. Allowed paths are
`AGENTS.md`, `README.md`, `《知势宣言》.md`, and Markdown files under `docs/`.
The task type must be read from `base_tasks`; the head task must be `待评审`.

- [ ] **Step 4: Add the git-backed CLI**

The CLI must accept:

```text
--repo-root
--base-ref
--head-ref
--metadata
```

The metadata JSON contains `body`, `base_ref`, `repository`, and `head_repository`.
The CLI must obtain changed paths with `git diff --name-only`, read task files at both refs
with `git show`, print a JSON result, and exit `0` only when eligible.

- [ ] **Step 5: Run tests and verify GREEN**

Run:

```bash
python3 -m unittest tests/研发中心/test_验证自动合并资格.py -v
python3 scripts/研发中心/验证自动合并资格.py --help
```

Expected: all tests pass and CLI help exits `0`.

- [ ] **Step 6: Commit the tested checker**

```bash
git add scripts/研发中心/验证自动合并资格.py tests/研发中心/test_验证自动合并资格.py
git commit -m "feat: 增加PR自动合并资格检查"
```

### Task 3: GitHub Actions workflows

**Files:**

- Create: `.github/workflows/pr-auto-merge-eligibility.yml`
- Create: `.github/workflows/pr-auto-merge.yml`

- [ ] **Step 1: Create the read-only eligibility workflow**

Use `pull_request` events, set:

```yaml
permissions:
  contents: read
  pull-requests: read
```

Pin checkout to `actions/checkout@11d5960a326750d5838078e36cf38b85af677262`.
Build metadata from `GITHUB_EVENT_PATH`, fetch the exact base and head SHA, and run the
eligibility CLI. The job name must be `验证自动合并资格`.

- [ ] **Step 2: Create the owner-comment merge workflow**

Use only `issue_comment.created`. Require:

```text
github.event.issue.pull_request
github.actor == 'xk320'
github.event.comment.author_association == 'OWNER'
```

Accept only `/架构评审通过 <40位SHA>`. Fetch PR metadata through `gh api`, reject drafts,
external repositories, non-`main` bases, changed SHAs, failed eligibility checks or conflicts.
Checkout only `main`, rerun the trusted `main` eligibility script, then call the merge REST
endpoint with the expected SHA and `merge_method=merge`.

- [ ] **Step 3: Validate workflow syntax and security invariants**

Run:

```bash
ruby -e "require 'yaml'; YAML.load_file('.github/workflows/pr-auto-merge-eligibility.yml'); YAML.load_file('.github/workflows/pr-auto-merge.yml')"
rg -n 'pull_request_target|github\\.event\\..*\\}\\}.*run:|uses:.*@(v[0-9]+|main|master)' .github/workflows
```

Expected: YAML parses; the security scan returns no match.

- [ ] **Step 4: Commit workflows**

```bash
git add .github/workflows/pr-auto-merge-eligibility.yml .github/workflows/pr-auto-merge.yml
git commit -m "feat: 建立架构批准后的自动合并流程"
```

### Task 4: Governance documentation

**Files:**

- Create: `docs/治理/PR自动合并策略.md`
- Modify: `AGENTS.md`
- Modify: `docs/研发中心/任务规范.md`
- Modify: `docs/研发中心/Codex自动执行提示词.md`
- Modify: `docs/研发中心/总体计划.md`

- [ ] **Step 1: Publish the merge policy**

Document the exact approval command, trusted actor, SHA binding, eligible task types,
allowed paths, high-risk exclusions, failure behavior, audit evidence, rollback and the
manual bootstrap requirement for task-000013.

- [ ] **Step 2: Synchronize agent and task-center rules**

Replace the unconditional “不得自动合并自己的PR” wording with:

```text
Codex不得自行给出架构批准。低风险PR只有在仓库所有者针对当前提交SHA明确批准、
资格检查通过且可信main工作流复验通过后，才可由自动化合并；其他PR必须人工合并。
```

Require new task files to declare `类型`. Missing or unknown types always require manual merge.

- [ ] **Step 3: Register Phase 2 platform hardening**

Add GitHub Pro evaluation, branch protection/rulesets, required reviews and checks,
CODEOWNERS, native auto-merge and end-to-end status sync to the Phase 2 plan without making
them current acceptance conditions.

- [ ] **Step 4: Validate Markdown**

Run the task's complete `markdownlint-cli2` command.

Expected: `0 error(s)`.

- [ ] **Step 5: Commit governance documentation**

```bash
git add \
  AGENTS.md \
  docs/治理/PR自动合并策略.md \
  docs/研发中心/任务规范.md \
  docs/研发中心/Codex自动执行提示词.md \
  docs/研发中心/总体计划.md
git commit -m "docs: 明确PR自动合并策略与审批边界"
```

### Task 5: Final verification and PR delivery

**Files:**

- Modify: `docs/研发中心/任务/任务-000013.md`
- Modify: `docs/研发中心/看板.md`

- [ ] **Step 1: Run all verification commands**

Run unit tests, CLI help, YAML parse, workflow security scans, Markdown lint, task-board
consistency and `git diff --check`. Record exact outputs.

- [ ] **Step 2: Review the branch against `origin/main`**

Confirm the diff contains only task-authorized governance, workflow, script and test files.
Confirm no credentials, production code, data or real-money behavior changed.

- [ ] **Step 3: Commit implementation delivery state**

Update task-000013 and the board to `待评审`, recording branch, commit SHA, PR placeholder,
deliverables, verification results, limitations, data/security impact and manual decisions.

- [ ] **Step 4: Push and create the pull request**

Push `agent/000013-pr-auto-merge-v1` and create a PR to `main` with the task number,
deliverables, acceptance results, commands, limitations, data/security impact and rollback.

- [ ] **Step 5: Add PR number and final state commit**

Write the real PR URL and number to task-000013, synchronize the board, commit and push the
state update to the same PR. Do not merge task-000013 automatically.
