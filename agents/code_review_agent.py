import os
import base64
import requests
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage

# ── Configuration ────────────────────────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GH_PAT")
REPO         = os.environ.get("GITHUB_REPOSITORY")
PR_NUMBER    = os.environ.get("PR_NUMBER")
HEAD_SHA     = os.environ.get("HEAD_SHA")

# ── Tuneable constants ────────────────────────────────────────────────────────
MAX_DIFF_CHARS      = 12_000
MAX_ANALYSIS_CHARS  = 4_000
MAX_FIX_CHARS       = 3_000
MAX_RETRIES         = 3

# ── LLM setup ────────────────────────────────────────────────────────────────
llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0.2,
    api_key=os.environ.get("GROQ_API_KEY"),
)

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
}


# ── GitHub helpers ────────────────────────────────────────────────────────────

def gh_request(method: str, url: str, **kwargs) -> requests.Response:
    """Thin wrapper with retry logic for transient GitHub API errors."""
    for attempt in range(1, MAX_RETRIES + 1):
        resp = requests.request(method, url, headers=HEADERS, **kwargs)
        if resp.status_code in (429, 500, 502, 503):
            print(f"⚠️  GitHub API {resp.status_code} — retry {attempt}/{MAX_RETRIES}")
            continue
        return resp
    return resp  # return last response after exhausting retries


def get_pr_diff() -> tuple[list | None, str]:
    """Fetch changed files and build a unified diff string."""
    url  = f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}/files"
    resp = gh_request("GET", url)

    if resp.status_code != 200:
        return None, f"Could not fetch PR files: {resp.status_code}"

    files        = resp.json()
    diff_parts   = []
    total_chars  = 0

    for f in files:
        patch = f.get("patch", "")
        if not patch:
            continue
        block = f"## File: {f['filename']} ({f.get('status','')})\n```diff\n{patch}\n```"

        # Budget-aware truncation with clear warning
        if total_chars + len(block) > MAX_DIFF_CHARS:
            remaining = MAX_DIFF_CHARS - total_chars
            if remaining > 200:
                diff_parts.append(block[:remaining] + "\n⚠️  [truncated — diff too large]")
            diff_parts.append("⚠️  Remaining files omitted — diff exceeded budget.")
            break

        diff_parts.append(block)
        total_chars += len(block)

    return files, "\n\n".join(diff_parts)


# ── LLM analysis passes ───────────────────────────────────────────────────────

REVIEW_SYSTEM = """\
You are an expert code reviewer. Evaluate the diff for:
- Security vulnerabilities (OWASP Top 10, secret leakage, injection)
- Correctness and edge-case bugs
- Error handling gaps
- FastAPI / Docker / DevOps best practices
- Missing or inadequate tests
- PEP 8 and clean-code compliance

Return STRICT structured markdown with exactly these sections:
## Verdict
One of: APPROVE | REQUEST_CHANGES | COMMENT
## Critical Issues
## Code Quality Issues
## Positive Points
## Suggested Fixes
"""

OPTIMIZATION_SYSTEM = """\
You are an algorithm and performance optimization expert. Analyze the diff for:

1. **Time Complexity** — identify O(n²) or worse patterns; suggest O(n log n) or better alternatives
2. **Space Complexity** — unnecessary data copies, large in-memory structures; suggest generators/streaming
3. **Pythonic Patterns** — replace manual loops with list comprehensions, map/filter, itertools, collections
4. **Async / Concurrency** — blocking I/O that could be async; ThreadPoolExecutor / asyncio opportunities
5. **Database & I/O** — N+1 query patterns, missing batching, redundant API calls
6. **Caching** — repeated computations that could be memoized (functools.lru_cache, cachetools)
7. **Memory Layout** — use of __slots__, dataclasses, namedtuples for hot objects

For every suggestion provide:
- The original code snippet (from the diff)
- The complexity BEFORE (e.g. O(n²) time, O(n) space)
- The optimized version with concrete code
- The complexity AFTER

Return structured markdown. Be specific; reference file names.
"""


def analyze_review(diff: str) -> str:
    """Pass 1 — security, correctness, style."""
    messages = [
        SystemMessage(content=REVIEW_SYSTEM),
        HumanMessage(content=f"PR Diff:\n{diff}"),
    ]
    try:
        return llm.invoke(messages).content
    except Exception as e:
        return f"⚠️ Review error: {e}"


def analyze_optimizations(diff: str) -> str:
    """Pass 2 — algorithmic & performance optimization (your new idea)."""
    messages = [
        SystemMessage(content=OPTIMIZATION_SYSTEM),
        HumanMessage(content=f"PR Diff to optimize:\n{diff}"),
    ]
    try:
        return llm.invoke(messages).content
    except Exception as e:
        return f"⚠️ Optimization analysis error: {e}"


def generate_fixed_code(files: list, review: str, optimizations: str) -> str:
    """Pass 3 — produce concrete fixed + optimized file contents."""
    python_files = [f["filename"] for f in files if f["filename"].endswith(".py")]
    messages = [
        SystemMessage(content="You are an expert Python developer. Output ONLY fixed code blocks, no prose."),
        HumanMessage(content=f"""\
Based on this review:
{review[:MAX_ANALYSIS_CHARS]}

And these optimization suggestions:
{optimizations[:MAX_ANALYSIS_CHARS]}

For each file in {python_files} that needs changes, output:

FILE: path/to/file.py
```python
# complete corrected + optimized file
```

Only include files with actual changes needed."""),
    ]
    try:
        return llm.invoke(messages).content
    except Exception as e:
        return f"⚠️ Fix generation error: {e}"


# ── Verdict parsing ───────────────────────────────────────────────────────────

def parse_verdict(review: str) -> str:
    """Extract the structured verdict from the LLM review."""
    for line in review.splitlines():
        upper = line.strip().upper()
        if "REQUEST_CHANGES" in upper:
            return "REQUEST_CHANGES"
        if "APPROVE" in upper:
            return "APPROVE"
    return "COMMENT"


# ── GitHub posting ────────────────────────────────────────────────────────────

def post_pr_review(review: str, optimizations: str) -> bool:
    """Post the combined review + optimization report as a PR review."""
    verdict = parse_verdict(review)
    body = f"""## 🤖 AI Code Review

{review}

---

## ⚡ Algorithmic Optimization Report

{optimizations}

---
*Powered by LangChain + Groq (Llama 3.3) • Two-pass AI Review Agent*
*Automated review — apply human judgment before merging.*
"""
    url  = f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}/reviews"
    resp = gh_request("POST", url, json={
        "commit_id": HEAD_SHA,
        "body": body,
        "event": verdict,
        "comments": [],
    })

    if resp.status_code in (200, 201):
        print(f"✅ Review posted — verdict: {verdict}")
        return True

    print(f"❌ Failed to post review: {resp.status_code} {resp.text}")
    return False


def create_fix_pr(files: list, review: str, optimizations: str) -> None:
    """Open a dedicated PR that contains AI-suggested fixes and optimisations."""
    print("🔧 Generating fixes...")
    fixes = generate_fixed_code(files, review, optimizations)

    # Resolve base SHA from the original PR
    pr_resp = gh_request("GET", f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}")
    if pr_resp.status_code != 200:
        print("❌ Could not fetch PR metadata")
        return

    base_sha   = pr_resp.json()["head"]["sha"]
    fix_branch = f"ai-fixes/pr-{PR_NUMBER}"

    # Idempotent branch creation
    ref_url = f"https://api.github.com/repos/{REPO}/git/refs/heads/{fix_branch}"
    if gh_request("GET", ref_url).status_code == 200:
        gh_request("DELETE", ref_url)
        print(f"🗑️  Removed stale branch: {fix_branch}")

    br_resp = gh_request("POST", f"https://api.github.com/repos/{REPO}/git/refs", json={
        "ref": f"refs/heads/{fix_branch}",
        "sha": base_sha,
    })
    if br_resp.status_code not in (200, 201):
        print(f"❌ Could not create branch: {br_resp.status_code}")
        return
    print(f"✅ Branch created: {fix_branch}")

    # Commit the summary document
    summary = f"""# AI Review & Optimization Report — PR #{PR_NUMBER}

## 🔒 Code Review
{review[:MAX_ANALYSIS_CHARS]}

## ⚡ Optimization Suggestions
{optimizations[:MAX_ANALYSIS_CHARS]}

## 🛠 Suggested Fixed Files
{fixes[:MAX_FIX_CHARS]}

---
*Generated by AI Code Review Agent • LangChain + Groq*
"""
    file_resp = gh_request(
        "PUT",
        f"https://api.github.com/repos/{REPO}/contents/ai-review/pr-{PR_NUMBER}-fixes.md",
        json={
            "message": f"🤖 AI review + optimization fixes for PR #{PR_NUMBER}",
            "content": base64.b64encode(summary.encode()).decode(),
            "branch": fix_branch,
        },
    )
    if file_resp.status_code not in (200, 201):
        print(f"❌ Could not commit fix file: {file_resp.status_code}")
        return

    # Open the fix PR
    fix_pr_resp = gh_request(
        "POST",
        f"https://api.github.com/repos/{REPO}/pulls",
        json={
            "title": f"🤖 AI Fixes + Optimizations for PR #{PR_NUMBER}",
            "body": f"""## 🤖 AI-Generated Fixes & Optimizations

> ⚠️ Human review required before merging.

### What changed
- Fixed critical issues from the review
- Applied algorithmic optimizations (complexity improvements, Pythonic rewrites, async suggestions)

### Review Summary
{review[:1_000]}

### Optimization Report
{optimizations[:1_000]}

### Suggested File Changes
{fixes[:1_500]}

---
*Powered by LangChain + Groq (Llama 3.3)*
""",
            "head": fix_branch,
            "base": "main",
        },
    )

    if fix_pr_resp.status_code in (200, 201):
        fix_url = fix_pr_resp.json().get("html_url")
        print(f"✅ Fix PR opened: {fix_url}")

        # Back-link on the original PR
        gh_request(
            "POST",
            f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments",
            json={"body": f"## 🤖 AI Fix PR Ready\n\n👉 {fix_url}\n\n*AI Code Review Agent*"},
        )
    else:
        print(f"❌ Fix PR failed: {fix_pr_resp.status_code} {fix_pr_resp.text}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    print("🔍 AI Code Review Agent — two-pass mode")
    print(f"   Repo : {REPO}")
    print(f"   PR   : #{PR_NUMBER}")
    print(f"   SHA  : {HEAD_SHA}")

    # Step 1 — fetch diff
    print("\n📥 Fetching PR diff...")
    files, diff = get_pr_diff()
    if files is None:
        print(f"❌ {diff}")
        return
    print(f"✅ {len(files)} file(s) changed")

    # Step 2 — review pass
    print("\n🔒 Running security & quality review...")
    review = analyze_review(diff)
    print("✅ Review complete")

    # Step 3 — optimization pass  ← your new idea
    print("\n⚡ Running algorithmic optimization analysis...")
    optimizations = analyze_optimizations(diff)
    print("✅ Optimization analysis complete")

    # Step 4 — post combined review
    print("\n💬 Posting review to PR...")
    post_pr_review(review, optimizations)

    # Step 5 — fix PR if needed
    needs_fixes = any(kw in review.lower() for kw in ("critical", "request_changes", "request changes"))
    if needs_fixes:
        print("\n🔧 Issues found — creating fix PR...")
        create_fix_pr(files, review, optimizations)
    else:
        print("\n✅ No critical issues — skipping fix PR")


if __name__ == "__main__":
    main()