# Fan-Out/Fan-In Code Analysis Architecture

**Goal:** Replace the current single-stage `gather_code` + `code_analysis` pattern with a
per-file fan-out/fan-in pipeline that removes all file count and line caps, scaling to
repositories of arbitrary size.

---

## Why This Is Needed

The current architecture has two hard limits:

1. **File cap** — `gather_code` collects at most 12 files per language (recently raised from 8).
2. **Line cap** — each file is truncated to 150 lines (recently raised from 80).

Even with those caps raised, the fundamental ceiling is the LLM context window. All gathered
source is concatenated into one prompt sent to a single `code_analysis` call. At ~200K tokens
(≈ 600 KB of text), that's a hard wall that no prompt-level fix can move. Real repositories
commonly exceed this by an order of magnitude.

**Fan-out/fan-in** solves this by assigning one LLM call per source file. Each call analyzes
only that file, returns a structured finding list, and a fan-in aggregator merges everything
before the findings enter the existing `synthesize_findings` stage unchanged.

---

## High-Level Flow (New)

```
list_source_files   ← direct tool call, returns [{path, language, size_lines}]
       │
       ▼
triage_files        ← optional LLM stage: rank/filter to top-N if repo is huge
       │
       ▼
analyze_file        ← fan-out: one LLM call per file, returns {vulnerabilities: [...]}
       │  (parallel)
       ▼
aggregate_code_findings  ← fan-in: merges + deduplicates all per-file findings
       │
       ▼
synthesize_findings  ← unchanged: treats aggregate output as the new "code_analysis"
```

### High-Level Flow (Old, for comparison)

```
gather_code (adapter, capped)  →  code_analysis (single LLM call)  →  synthesize_findings
```

---

## Step 1 — New Tool: `list_source_files`

**File:** `argus/tools/files.py`

```python
async def _handle_list_source_files(args: dict) -> dict:
    repo_dir = args.get("repo_dir", "")
    if not repo_dir or not Path(repo_dir).exists():
        return {"error": f"repo_dir not found: {repo_dir}"}

    EXTENSIONS = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript",
        ".java": "java", ".go": "go",
        ".rs": "rust",
        ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
        ".h": "c", ".hpp": "cpp",
        ".rb": "ruby", ".php": "php",
    }

    SKIP_DIRS = {"node_modules", ".git", "target", "build", "dist",
                 "vendor", ".venv", "venv", "__pycache__"}

    files = []
    for path in sorted(Path(repo_dir).rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        lang = EXTENSIONS.get(path.suffix.lower())
        if not lang:
            continue
        try:
            size_lines = sum(1 for _ in path.open("rb"))
        except OSError:
            continue
        files.append({
            "path": str(path),
            "relative_path": str(path.relative_to(repo_dir)),
            "language": lang,
            "size_lines": size_lines,
        })

    return {"files": files, "total_count": len(files)}
```

Also add a `read_file` tool in the same module:

```python
async def _handle_read_file(args: dict) -> dict:
    path = args.get("path", "")
    try:
        content = Path(path).read_text(errors="replace")
        return {"path": path, "content": content, "size_chars": len(content)}
    except Exception as exc:
        return {"error": str(exc)}
```

Register both descriptors in the module's `register()` function.

---

## Step 2 — New Workflow Stage: `list_source_files`

In `repo-scan.yaml`, replace the `gather_code` adapter stage with a direct tool call:

```yaml
- id: list_source_files
  type: tool_call
  tool: list_source_files
  inputs:
    repo_dir: "{{ clone_repo.repo_dir }}"
  depends_on: [clone_repo]
```

Output: `list_source_files.files` — array of `{path, relative_path, language, size_lines}`.

---

## Step 3 — Optional Triage Stage

For repositories with > 100 source files, a triage pass ranks files by security relevance
before the expensive fan-out. This caps cost without capping correctness on the highest-risk
paths.

```yaml
- id: triage_files
  type: llm
  role: triage_analyst
  model_tier: small
  output_mode: guided_json
  output_schema:
    selected_files:
      type: array
      items: {type: string}   # relative_path values
    rationale: {type: string}
  depends_on: [list_source_files]
```

System prompt for `triage_analyst`:

> You are a security triage specialist. Given the file manifest below, select up to 60 files
> most likely to contain security vulnerabilities. Prioritize: authentication, authorization,
> input parsing, network handlers, file I/O, crypto, database queries, config loaders, and
> anything named *auth*, *login*, *token*, *api*, *router*, *handler*, *upload*, *exec*.
> Deprioritize: tests, migrations, auto-generated code, locale files, and static assets.
>
> Return `selected_files` as a list of `relative_path` strings.

**When to activate:** Gate on `list_source_files.total_count > 60` (configurable threshold).

---

## Step 4 — Fan-Out Stage: `analyze_file`

This is the core architectural change. Armature needs a `fan_out` stage type (see Step 7).

```yaml
- id: analyze_file
  type: llm
  fan_out: true
  partition_source: "{{ triage_files.selected_files | default(list_source_files.files | map(attribute='path')) }}"
  partition_key: file_path
  role: file_analyst
  model_tier: small
  output_mode: guided_json
  output_schema:
    file_path: {type: string}
    language: {type: string}
    vulnerabilities:
      type: array
      items:
        type: object
        properties:
          type: {type: string}
          severity: {type: string, enum: [critical, high, medium, low]}
          line: {type: integer}
          title: {type: string}
          description: {type: string}
          recommendation: {type: string}
          code_snippet: {type: string}
  depends_on: [triage_files]
```

System prompt for `file_analyst`:

> You are a security code reviewer. Analyze the source file at `{{ file_path }}` for
> vulnerabilities. Read the entire file and report every security issue you find.
> For each finding include: type, severity, line number, title, one-sentence description,
> concrete recommendation, and the relevant code snippet (3–5 lines).
> If there are no findings, return an empty `vulnerabilities` array.

The file content is injected into the user turn via the `read_file` tool (called automatically
by the fan-out executor before each LLM call).

---

## Step 5 — Fan-In Stage: `aggregate_code_findings`

```yaml
- id: aggregate_code_findings
  type: tool_call
  tool: aggregate_findings
  inputs:
    per_file_results: "{{ analyze_file }}"   # array of all fan-out outputs
  depends_on: [analyze_file]
```

New tool in `argus/tools/files.py`:

```python
async def _handle_aggregate_findings(args: dict) -> dict:
    per_file = args.get("per_file_results", [])
    seen = set()
    merged = []
    for file_result in per_file:
        for v in file_result.get("vulnerabilities", []):
            key = (file_result.get("file_path", ""), v.get("type", ""), v.get("line", 0))
            if key not in seen:
                seen.add(key)
                merged.append({**v, "file": file_result.get("file_path", "")})
    return {
        "vulnerabilities": merged,
        "files_analyzed": len(per_file),
        "total_findings": len(merged),
    }
```

Output shape is compatible with the existing `synthesize_findings` stage's `code_analysis`
input expectation — just rename the dependency reference from `code_analysis` to
`aggregate_code_findings`.

---

## Step 6 — Wire Into `synthesize_findings`

In `synthesize_findings`, update the dependency and template reference:

```yaml
depends_on:
  - aggregate_code_findings    # was: code_analysis
  - compress_scanners

# In the system prompt template, replace:
#   {{ code_analysis.vulnerabilities }}
# with:
#   {{ aggregate_code_findings.vulnerabilities }}
```

All downstream stages (`validate_findings`, `generate_report`) are unaffected because
they consume `synthesize_findings` output.

---

## Step 7 — Armature Fan-Out Support

This is the one Armature framework change required. The fan-out executor needs to:

1. Expand `partition_source` into N individual items.
2. For each item, set `{{ file_path }}` in the stage context and call `read_file` to inject
   content into the prompt.
3. Run all N LLM calls concurrently (bounded by a semaphore, default max=20).
4. Return results as an array keyed by stage ID — `analyze_file` becomes a list, not a dict.

**Proposed Armature API:**

```python
# In DAGExecutor._run_stage():
if stage.fan_out:
    items = self._resolve(stage.partition_source)
    results = await asyncio.gather(*[
        self._run_single_llm(stage, {stage.partition_key: item})
        for item in items
    ])
    self.context[stage.id] = results   # list, not dict
    return
```

The `aggregate_code_findings` tool call receives the full list via `{{ analyze_file }}`.

**Concurrency guard:** Add `max_parallelism: 20` to the fan-out stage spec to avoid
hammering the API with 500 simultaneous calls on large repos.

---

## Step 8 — Backward Compatibility / Migration

Keep the current `code_analysis` stage in the workflow under a feature flag until the
fan-out path is stable:

```yaml
# Temporary: disable old path when fan-out is active
- id: code_analysis
  enabled: false       # add 'enabled' flag support to Armature spec loader
```

Or more pragmatically: run both in parallel during the transition period and diff outputs
on a known fixture repo to validate parity.

---

## Cost and Latency Profile

| Repo size       | Files analyzed | API calls | Approx cost (haiku) | Approx latency |
|-----------------|---------------|-----------|---------------------|----------------|
| Small (< 20)    | all           | 20        | ~$0.01              | 15–30s         |
| Medium (20–100) | all or triage | 60        | ~$0.03              | 30–60s         |
| Large (100–500) | triage 60     | 60        | ~$0.03              | 30–60s         |
| Monorepo (500+) | triage 60     | 60        | ~$0.03              | 30–60s         |

Cost is bounded by the triage cap (60 files), not by repo size. Latency is dominated by
the slowest single file call, not the total number (they run in parallel).

---

## Implementation Order (recommended)

1. **`argus/tools/files.py`** — `list_source_files`, `read_file`, `aggregate_findings` tools
2. **Armature fan-out executor** — `fan_out: true`, partition expansion, bounded gather
3. **`repo-scan.yaml`** — add `list_source_files` and `triage_files` stages; stub out
   `analyze_file` and `aggregate_code_findings`; gate old `code_analysis` with `enabled: false`
4. **Integration test** on `tests/fixtures/vulnerable-app/` — confirm `vuln.c` findings
   survive the full fan-out/fan-in path
5. **e2e test update** — `test_code_analysis_found` → `test_aggregate_code_findings_found`

---

## Open Questions

- **Armature fan-out syntax**: The `fan_out` / `partition_source` / `partition_key` spec
  fields are proposed above but don't exist yet — needs design agreement with Armature.
- **`read_file` injection**: How does file content reach the `analyze_file` LLM prompt?
  Options: (a) fan-out executor reads the file and injects content into the user turn
  template; (b) `analyze_file` calls the `read_file` tool itself as a tool-use stage.
  Option (a) is simpler; option (b) requires tool-use support in the LLM stage.
- **Triage threshold**: 60 files is a guess. Tune based on observed token cost vs.
  missed-finding rate on benchmark repos.
- **Binary/generated files**: The `list_source_files` extension filter handles most cases,
  but minified JS (`.js` but 1 line of 500KB) needs a size guard (e.g., skip files > 2000
  lines even in fan-out mode, or add a `size_lines` column to the triage prompt so the
  triage LLM can downrank them).
