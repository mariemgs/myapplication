import os
import json
import base64
import subprocess
import requests
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage

# ── Configuration ─────────────────────────────────────────────────────────────
GITHUB_TOKEN = os.environ.get("GH_PAT")
REPO         = os.environ.get("GITHUB_REPOSITORY")
PR_NUMBER    = os.environ.get("PR_NUMBER")
HEAD_SHA     = os.environ.get("HEAD_SHA")

MAX_DIFF_CHARS     = 12000
MAX_ANALYSIS_CHARS = 4000
MAX_RETRIES        = 3

llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0.1,
    api_key=os.environ.get("GROQ_API_KEY"),
)

HEADERS = {
    "Authorization": "token {}".format(GITHUB_TOKEN),
    "Accept": "application/vnd.github.v3+json",
}

SKIP_PATTERNS = [
    ".lock", ".json", ".yml", ".yaml", "migration",
    "alembic", "__pycache__", ".min.js", ".map",
    "node_modules", "dist/", "build/"
]


# ── GitHub helpers ─────────────────────────────────────────────────────────────
def gh_request(method, url, **kwargs):
    for attempt in range(1, MAX_RETRIES + 1):
        resp = requests.request(method, url, headers=HEADERS, **kwargs)
        if resp.status_code in (429, 500, 502, 503):
            print("GitHub API {} — retry {}/{}".format(resp.status_code, attempt, MAX_RETRIES))
            continue
        return resp
    return resp


def get_pr_diff():
    url  = "https://api.github.com/repos/{}/pulls/{}/files".format(REPO, PR_NUMBER)
    resp = gh_request("GET", url)
    if resp.status_code != 200:
        return None, "Could not fetch PR files: {}".format(resp.status_code)

    files      = resp.json()
    diff_parts = []
    total      = 0

    for f in files:
        filename = f.get("filename", "")
        # Skip non-relevant files
        if any(p in filename for p in SKIP_PATTERNS):
            continue

        patch = f.get("patch", "")
        if not patch:
            continue

        block = "## File: {} ({})\n```diff\n{}\n```".format(
            filename, f.get("status", ""), patch)

        if total + len(block) > MAX_DIFF_CHARS:
            remaining = MAX_DIFF_CHARS - total
            if remaining > 200:
                diff_parts.append(block[:remaining] + "\n[truncated]")
            break

        diff_parts.append(block)
        total += len(block)

    return files, "\n\n".join(diff_parts)


def get_python_files(files):
    return [f["filename"] for f in files if f["filename"].endswith(".py")
            and not any(p in f["filename"] for p in SKIP_PATTERNS)]


# ── Pass 1: Security & Quality Review ─────────────────────────────────────────
def pass_security_review(diff):
    print("Pass 1: Security and quality review...")
    messages = [
        SystemMessage(content="""You are a security-focused code reviewer.
CRITICAL RULES:
- Only report issues you can PROVE exist in the diff with exact file name and line number
- Do NOT invent issues. If you cannot cite exact evidence from the diff, do not report it
- Reference the actual code from the diff when describing issues
- Format each issue as: FILE:LINE_NUMBER - SEVERITY - description

Check for:
- Security vulnerabilities (OWASP Top 10, injection, secrets in code)
- Error handling gaps
- FastAPI best practices
- Missing input validation"""),
        HumanMessage(content="Review this diff:\n\n{}".format(diff))
    ]
    try:
        return llm.invoke(messages).content
    except Exception as e:
        return "Review error: {}".format(e)


# ── Pass 2: SOLID & Best Practices ────────────────────────────────────────────
def pass_solid_review(diff):
    print("Pass 2: SOLID principles review...")
    messages = [
        SystemMessage(content="""You are a software architecture expert reviewing for SOLID principles.
CRITICAL RULES:
- Only flag violations you can point to with exact file name and line number from the diff
- Do NOT invent violations. Cite exact code snippets from the diff as evidence
- If the diff is too small to evaluate a principle, say so explicitly

Check for:
- S: Single Responsibility — does each class/function do one thing?
- O: Open/Closed — is code open for extension but closed for modification?
- L: Liskov Substitution — are subtypes substitutable?
- I: Interface Segregation — are interfaces too large?
- D: Dependency Inversion — does code depend on abstractions?

Also check: DRY, KISS, clean code naming conventions"""),
        HumanMessage(content="Review this diff for SOLID violations:\n\n{}".format(diff))
    ]
    try:
        return llm.invoke(messages).content
    except Exception as e:
        return "SOLID review error: {}".format(e)


# ── Pass 3: Performance & Optimization ────────────────────────────────────────
def pass_optimization(diff, python_files):
    if not python_files:
        return "No Python files to optimize."
    print("Pass 3: Performance optimization review...")
    messages = [
        SystemMessage(content="""You are a Python performance expert.
CRITICAL RULES:
- Only suggest optimizations for code that actually exists in the diff
- Cite exact file name and line number for every suggestion
- Show the original code snippet and the optimized version

Check for:
- Time complexity issues (O(n²) or worse)
- Unnecessary loops that could use list comprehensions
- Missing async/await for I/O operations
- N+1 query patterns
- Opportunities for caching with functools.lru_cache"""),
        HumanMessage(content="Optimize this diff:\n\n{}".format(diff))
    ]
    try:
        return llm.invoke(messages).content
    except Exception as e:
        return "Optimization error: {}".format(e)


# ── Pass 4: Validation (Anti-Hallucination) ───────────────────────────────────
def pass_validation(diff, security_review, solid_review, optimization):
    print("Pass 4: Validating findings (anti-hallucination)...")
    messages = [
        SystemMessage(content="""You are a strict fact-checker for code reviews.
Your job is to validate that every issue mentioned in the reviews actually exists in the diff.

For each issue found in the reviews:
1. Search for it in the diff
2. If you can find the exact code being referenced: mark as VALID
3. If you cannot find it in the diff: mark as HALLUCINATED and remove it

Return a clean validated report with only VALID findings.
Format:
## Validated Security Issues
## Validated SOLID Violations  
## Validated Optimizations
## Removed (Hallucinated) Issues
"""),
        HumanMessage(content="""DIFF:
{}

SECURITY REVIEW:
{}

SOLID REVIEW:
{}

OPTIMIZATION:
{}

Validate all findings against the diff.""".format(
            diff,
            security_review[:2000],
            solid_review[:2000],
            optimization[:2000]
        ))
    ]
    try:
        return llm.invoke(messages).content
    except Exception as e:
        return "Validation error: {}".format(e)


# ── Post inline comments ───────────────────────────────────────────────────────
def post_inline_comments(files, validated_report):
    print("Posting inline comments...")
    messages = [
        SystemMessage(content="""Extract inline comments from this validated review report.
Return a JSON array only, no other text:
[
  {
    "path": "exact/file/path.py",
    "line": 42,
    "body": "comment text"
  }
]
Only include items where you have an exact file path and line number.
If you cannot extract structured comments, return an empty array: []"""),
        HumanMessage(content=validated_report[:3000])
    ]

    try:
        response = llm.invoke(messages).content
        # Clean JSON
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        comments = json.loads(response.strip())
    except Exception as e:
        print("Could not parse inline comments: {}".format(e))
        return

    # Get valid file paths from PR
    valid_paths = {f["filename"] for f in files}
    posted = 0

    for comment in comments[:10]:  # limit to 10 inline comments
        path = comment.get("path", "")
        line = comment.get("line")
        body = comment.get("body", "")

        if path not in valid_paths or not line or not body:
            continue

        url  = "https://api.github.com/repos/{}/pulls/{}/comments".format(REPO, PR_NUMBER)
        resp = gh_request("POST", url, json={
            "commit_id": HEAD_SHA,
            "path": path,
            "line": line,
            "body": "**AI Review:** {}".format(body),
            "side": "RIGHT"
        })

        if resp.status_code in (200, 201):
            posted += 1
        else:
            print("Inline comment failed: {} - {}".format(resp.status_code, resp.text[:100]))

    print("Posted {} inline comments".format(posted))


# ── Post PR review summary ─────────────────────────────────────────────────────
def post_pr_review(validated_report, security_review, solid_review, optimization):
    verdict = "COMMENT"
    lower = validated_report.lower()
    if "critical" in lower or "high" in lower:
        verdict = "REQUEST_CHANGES"
    elif "no issues" in lower or "no violations" in lower:
        verdict = "APPROVE"

    body = """## AI Code Review Report

> This review was validated to remove hallucinated findings. Only issues found in the actual diff are reported.

---

{}

---

### Raw Analysis Details

<details>
<summary>Security & Quality Review</summary>

{}

</details>

<details>
<summary>SOLID Principles Review</summary>

{}

</details>

<details>
<summary>Performance Optimization</summary>

{}

</details>

---
*4-Pass AI Code Review: Security -> SOLID -> Optimization -> Validation*
*Powered by Groq (Llama-3.3-70b) | Hallucination filter applied*""".format(
        validated_report,
        security_review[:1500],
        solid_review[:1500],
        optimization[:1500]
    )

    url  = "https://api.github.com/repos/{}/pulls/{}/reviews".format(REPO, PR_NUMBER)
    resp = gh_request("POST", url, json={
        "commit_id": HEAD_SHA,
        "body": body,
        "event": verdict,
        "comments": [],
    })

    if resp.status_code in (200, 201):
        print("Review posted — verdict: {}".format(verdict))
        return True
    print("Failed to post review: {} {}".format(resp.status_code, resp.text[:200]))
    return False


# ── Create fix PR ──────────────────────────────────────────────────────────────
def create_fix_pr(files, validated_report, security_review, solid_review, optimization):
    print("Generating fix suggestions...")

    python_files = get_python_files(files)
    if not python_files:
        print("No Python files to fix")
        return

    messages = [
        SystemMessage(content="You are an expert Python developer. Provide concrete fix suggestions based only on validated issues."),
        HumanMessage(content="""Based on these VALIDATED issues (hallucinations already removed):
{}

For each file that needs changes: {}

Provide specific fix suggestions with:
- The exact problematic code
- The fixed version
- Why this fix addresses the issue

Only suggest fixes for issues that appear in the validated report.""".format(
            validated_report[:2000],
            python_files
        ))
    ]

    try:
        fixes = llm.invoke(messages).content
    except Exception as e:
        fixes = "Could not generate fixes: {}".format(e)

    # Get base SHA
    pr_resp = gh_request("GET", "https://api.github.com/repos/{}/pulls/{}".format(REPO, PR_NUMBER))
    if pr_resp.status_code != 200:
        print("Could not fetch PR metadata")
        return

    base_sha   = pr_resp.json()["head"]["sha"]
    fix_branch = "ai-fixes/pr-{}".format(PR_NUMBER)

    # Clean up old branch if exists
    ref_url = "https://api.github.com/repos/{}/git/refs/heads/{}".format(REPO, fix_branch)
    if gh_request("GET", ref_url).status_code == 200:
        gh_request("DELETE", ref_url)

    # Create branch
    br_resp = gh_request("POST", "https://api.github.com/repos/{}/git/refs".format(REPO), json={
        "ref": "refs/heads/{}".format(fix_branch),
        "sha": base_sha,
    })
    if br_resp.status_code not in (200, 201):
        print("Could not create branch: {}".format(br_resp.status_code))
        return

    # Commit fix document
    summary = "# AI Fix Suggestions for PR #{}\n\n".format(PR_NUMBER)
    summary += "## Validated Issues Found\n{}\n\n".format(validated_report[:2000])
    summary += "## Suggested Fixes\n{}\n\n".format(fixes[:2000])
    summary += "---\n*Generated by 4-Pass AI Code Review Agent*\n"
    summary += "*All issues validated against actual diff — hallucinations removed*\n"

    file_resp = gh_request(
        "PUT",
        "https://api.github.com/repos/{}/contents/ai-review/pr-{}-fixes.md".format(REPO, PR_NUMBER),
        json={
            "message": "AI fix suggestions for PR #{}".format(PR_NUMBER),
            "content": base64.b64encode(summary.encode()).decode(),
            "branch": fix_branch,
        },
    )

    if file_resp.status_code not in (200, 201):
        print("Could not commit fix file: {}".format(file_resp.status_code))
        return

    # Open fix PR
    fix_pr_resp = gh_request(
        "POST",
        "https://api.github.com/repos/{}/pulls".format(REPO),
        json={
            "title": "AI Fix Suggestions for PR #{}".format(PR_NUMBER),
            "body": """## AI-Generated Fix Suggestions

> Human review required before merging.
> All suggestions were validated — hallucinated issues removed.

### Validated Issues
{}

### Suggested Fixes
{}

---
*4-Pass AI Code Review | Groq Llama-3.3-70b*""".format(
                validated_report[:1000],
                fixes[:1000]
            ),
            "head": fix_branch,
            "base": "main",
        },
    )

    if fix_pr_resp.status_code in (200, 201):
        fix_url = fix_pr_resp.json().get("html_url")
        print("Fix PR opened: {}".format(fix_url))
        gh_request(
            "POST",
            "https://api.github.com/repos/{}/issues/{}/comments".format(REPO, PR_NUMBER),
            json={"body": "## AI Fix PR Ready\n\n{}\n\n*AI Code Review Agent*".format(fix_url)},
        )
    else:
        print("Fix PR failed: {} {}".format(fix_pr_resp.status_code, fix_pr_resp.text[:200]))


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print("AI Code Review Agent - 4-Pass Mode")
    print("Repo: {}".format(REPO))
    print("PR: #{}".format(PR_NUMBER))
    print("SHA: {}".format(HEAD_SHA))

    print("\nFetching PR diff...")
    files, diff = get_pr_diff()
    if files is None:
        print("Error: {}".format(diff))
        return
    print("{} relevant file(s) found".format(len(files)))

    if not diff.strip():
        print("No reviewable changes found (all files skipped)")
        return

    python_files = get_python_files(files)
    print("Python files: {}".format(python_files))

    # 4 passes
    security_review  = pass_security_review(diff)
    solid_review     = pass_solid_review(diff)
    optimization     = pass_optimization(diff, python_files)
    validated_report = pass_validation(diff, security_review, solid_review, optimization)

    print("\nPosting results...")
    post_inline_comments(files, validated_report)
    post_pr_review(validated_report, security_review, solid_review, optimization)

    needs_fixes = any(kw in validated_report.lower() for kw in ["critical", "high", "request_changes"])
    if needs_fixes:
        print("\nIssues found - creating fix PR...")
        create_fix_pr(files, validated_report, security_review, solid_review, optimization)
    else:
        print("\nNo critical issues - skipping fix PR")

    print("\nAI Code Review complete!")


if __name__ == "__main__":
    main()
