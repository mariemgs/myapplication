import os
import json
import base64
import subprocess
import requests
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage

GITHUB_TOKEN = os.environ.get("GH_PAT")
REPO = os.environ.get("GITHUB_REPOSITORY")
PR_NUMBER = os.environ.get("PR_NUMBER")
HEAD_SHA = os.environ.get("HEAD_SHA")

MAX_DIFF_CHARS = 12000
MAX_ANALYSIS_CHARS = 4000
MAX_RETRIES = 3

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


def gh_request(method, url, **kwargs):
    for attempt in range(1, MAX_RETRIES + 1):
        resp = requests.request(method, url, headers=HEADERS, **kwargs)
        if resp.status_code in (429, 500, 502, 503):
            print("GitHub API {} - retry {}/{}".format(resp.status_code, attempt, MAX_RETRIES))
            continue
        return resp
    return resp


def get_pr_diff():
    url = "https://api.github.com/repos/{}/pulls/{}/files".format(REPO, PR_NUMBER)
    resp = gh_request("GET", url)
    if resp.status_code != 200:
        return None, "Could not fetch PR files: {}".format(resp.status_code)

    files = resp.json()
    diff_parts = []
    total = 0

    for f in files:
        filename = f.get("filename", "")
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


def pass_security_review(diff):
    print("Pass 1: Security and quality review...")
    messages = [
        SystemMessage(content=(
            "You are a security-focused code reviewer.\n"
            "CRITICAL RULES:\n"
            "- Only report issues you can PROVE exist in the diff with exact file name and line number\n"
            "- Do NOT invent issues. If you cannot cite exact evidence from the diff, do not report it\n"
            "- Reference the actual code from the diff when describing issues\n"
            "- Format each issue as: FILE:LINE_NUMBER - SEVERITY - description\n\n"
            "Check for:\n"
            "- Security vulnerabilities (OWASP Top 10, injection, secrets in code)\n"
            "- Error handling gaps\n"
            "- FastAPI best practices\n"
            "- Missing input validation"
        )),
        HumanMessage(content="Review this diff:\n\n{}".format(diff))
    ]
    try:
        return llm.invoke(messages).content
    except Exception as e:
        return "Review error: {}".format(e)


def pass_solid_review(diff):
    print("Pass 2: SOLID principles review...")
    messages = [
        SystemMessage(content=(
            "You are a software architecture expert reviewing for SOLID principles.\n"
            "CRITICAL RULES:\n"
            "- Only flag violations you can point to with exact file name and line number from the diff\n"
            "- Do NOT invent violations. Cite exact code snippets from the diff as evidence\n"
            "- If the diff is too small to evaluate a principle, say so explicitly\n\n"
            "Check for:\n"
            "- S: Single Responsibility - does each class/function do one thing?\n"
            "- O: Open/Closed - is code open for extension but closed for modification?\n"
            "- L: Liskov Substitution - are subtypes substitutable?\n"
            "- I: Interface Segregation - are interfaces too large?\n"
            "- D: Dependency Inversion - does code depend on abstractions?\n\n"
            "Also check: DRY, KISS, clean code naming conventions"
        )),
        HumanMessage(content="Review this diff for SOLID violations:\n\n{}".format(diff))
    ]
    try:
        return llm.invoke(messages).content
    except Exception as e:
        return "SOLID review error: {}".format(e)


def pass_optimization(diff, python_files):
    if not python_files:
        return "No Python files to optimize."
    print("Pass 3: Performance optimization review...")
    messages = [
        SystemMessage(content=(
            "You are a Python performance expert.\n"
            "CRITICAL RULES:\n"
            "- Only suggest optimizations for code that actually exists in the diff\n"
            "- Cite exact file name and line number for every suggestion\n"
            "- Show the original code snippet and the optimized version\n\n"
            "Check for:\n"
            "- Time complexity issues (O(n^2) or worse)\n"
            "- Unnecessary loops that could use list comprehensions\n"
            "- Missing async/await for I/O operations\n"
            "- N+1 query patterns\n"
            "- Opportunities for caching with functools.lru_cache"
        )),
        HumanMessage(content="Optimize this diff:\n\n{}".format(diff))
    ]
    try:
        return llm.invoke(messages).content
    except Exception as e:
        return "Optimization error: {}".format(e)


def pass_validation(diff, security_review, solid_review, optimization):
    print("Pass 4: Validating findings (anti-hallucination)...")
    messages = [
        SystemMessage(content=(
            "You are a strict fact-checker for code reviews.\n"
            "Your job is to validate that every issue mentioned in the reviews actually exists in the diff.\n\n"
            "For each issue found in the reviews:\n"
            "1. Search for it in the diff\n"
            "2. If you can find the exact code being referenced: mark as VALID\n"
            "3. If you cannot find it in the diff: mark as HALLUCINATED and remove it\n\n"
            "Return a clean validated report with only VALID findings.\n"
            "Format:\n"
            "## Validated Security Issues\n"
            "## Validated SOLID Violations\n"
            "## Validated Optimizations\n"
            "## Removed (Hallucinated) Issues"
        )),
        HumanMessage(content=(
            "DIFF:\n{}\n\n"
            "SECURITY REVIEW:\n{}\n\n"
            "SOLID REVIEW:\n{}\n\n"
            "OPTIMIZATION:\n{}\n\n"
            "Validate all findings against the diff."
        ).format(diff, security_review[:2000], solid_review[:2000], optimization[:2000]))
    ]
    try:
        return llm.invoke(messages).content
    except Exception as e:
        return "Validation error: {}".format(e)


def post_inline_comments(files, validated_report):
    print("Posting inline comments...")
    messages = [
        SystemMessage(content=(
            "Extract inline comments from this validated review report.\n"
            "Return a JSON array only, no other text:\n"
            "[\n"
            "  {\n"
            "    \"path\": \"exact/file/path.py\",\n"
            "    \"line\": 42,\n"
            "    \"body\": \"comment text\"\n"
            "  }\n"
            "]\n"
            "Only include items where you have an exact file path and line number.\n"
            "If you cannot extract structured comments, return an empty array: []"
        )),
        HumanMessage(content=validated_report[:3000])
    ]

    try:
        response = llm.invoke(messages).content
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        comments = json.loads(response.strip())
    except Exception as e:
        print("Could not parse inline comments: {}".format(e))
        return

    valid_paths = {f["filename"] for f in files}
    posted = 0

    for comment in comments[:10]:
        path = comment.get("path", "")
        line = comment.get("line")
        body = comment.get("body", "")

        if path not in valid_paths or not line or not body:
            continue

        url = "https://api.github.com/repos/{}/pulls/{}/comments".format(REPO, PR_NUMBER)
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


def post_pr_review(validated_report, security_review, solid_review, optimization):
    verdict = "COMMENT"
    lower = validated_report.lower()
    if "critical" in lower or "high" in lower:
        verdict = "REQUEST_CHANGES"
    elif "no issues" in lower or "no violations" in lower:
        verdict = "APPROVE"

    body = (
        "## AI Code Review Report\n\n"
        "> This review was validated to remove hallucinated findings. "
        "Only issues found in the actual diff are reported.\n\n"
        "---\n\n"
        "{}\n\n"
        "---\n\n"
        "### Raw Analysis Details\n\n"
        "<details>\n"
        "<summary>Security & Quality Review</summary>\n\n"
        "{}\n\n"
        "</details>\n\n"
        "<details>\n"
        "<summary>SOLID Principles Review</summary>\n\n"
        "{}\n\n"
        "</details>\n\n"
        "<details>\n"
        "<summary>Performance Optimization</summary>\n\n"
        "{}\n\n"
        "</details>\n\n"
        "---\n"
        "*4-Pass AI Code Review: Security -> SOLID -> Optimization -> Validation*\n"
        "*Powered by Groq (Llama-3.3-70b) | Hallucination filter applied*"
    ).format(validated_report, security_review[:1500], solid_review[:1500], optimization[:1500])

    url = "https://api.github.com/repos/{}/pulls/{}/reviews".format(REPO, PR_NUMBER)
    resp = gh_request("POST", url, json={
        "commit_id": HEAD_SHA,
        "body": body,
        "event": verdict,
        "comments": [],
    })

    if resp.status_code in (200, 201):
        print("Review posted - verdict: {}".format(verdict))
        return True
    print("Failed to post review: {} {}".format(resp.status_code, resp.text[:200]))
    return False


def create_fix_pr_with_gh(validated_report, security_review, solid_review, optimization):
    print("Creating fix PR autonomously using gh CLI...")

    fixes_content = (
        "# AI Fix Suggestions for PR #{}\n\n"
        "## Validated Issues\n{}\n\n"
        "## Security Review\n{}\n\n"
        "## SOLID Review\n{}\n\n"
        "## Optimization\n{}\n\n"
        "---\n"
        "*Generated by 4-Pass AI Code Review Agent*\n"
    ).format(PR_NUMBER, validated_report[:2000], security_review[:1000],
             solid_review[:1000], optimization[:1000])

    branch_name = "ai-fixes/pr-{}".format(PR_NUMBER)
    env = os.environ.copy()
    env["GH_TOKEN"] = GITHUB_TOKEN

    os.makedirs("ai-review", exist_ok=True)
    with open("ai-review/pr-{}-fixes.md".format(PR_NUMBER), "w") as f:
        f.write(fixes_content)

    cmds = [
        ["git", "config", "user.email", "ai-agent@github.com"],
        ["git", "config", "user.name", "AI Code Review Agent"],
        ["git", "checkout", "-b", branch_name],
        ["git", "add", "ai-review/"],
        ["git", "commit", "-m", "AI fix suggestions for PR #{}".format(PR_NUMBER)],
        ["git", "push", "-u", "origin", branch_name, "--force"],
    ]

    for cmd in cmds:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            print("Git command failed: {} - {}".format(" ".join(cmd), result.stderr[:100]))
            return

    pr_body = (
        "## AI-Generated Fix Suggestions\n\n"
        "> All issues validated - hallucinations removed.\n\n"
        "### Validated Issues\n{}\n\n"
        "---\n"
        "*4-Pass AI Code Review | Groq Llama-3.3-70b*"
    ).format(validated_report[:1000])

    pr_cmd = [
        "gh", "pr", "create",
        "--title", "AI Fix Suggestions for PR #{}".format(PR_NUMBER),
        "--body", pr_body,
        "--base", "main",
        "--head", branch_name,
    ]

    result = subprocess.run(pr_cmd, capture_output=True, text=True, env=env)
    if result.returncode == 0:
        pr_url = result.stdout.strip()
        print("Fix PR created autonomously: {}".format(pr_url))
        gh_request(
            "POST",
            "https://api.github.com/repos/{}/issues/{}/comments".format(REPO, PR_NUMBER),
            json={"body": "## AI Fix PR Ready\n\n{}\n\n*AI Code Review Agent*".format(pr_url)}
        )
    else:
        print("gh pr create failed: {}".format(result.stderr[:200]))


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

    security_review = pass_security_review(diff)
    solid_review = pass_solid_review(diff)
    optimization = pass_optimization(diff, python_files)
    validated_report = pass_validation(diff, security_review, solid_review, optimization)

    print("\nPosting results...")
    post_inline_comments(files, validated_report)
    post_pr_review(validated_report, security_review, solid_review, optimization)

    needs_fixes = any(kw in validated_report.lower() for kw in ["critical", "high", "request_changes"])
    if needs_fixes:
        print("\nIssues found - creating fix PR autonomously...")
        create_fix_pr_with_gh(validated_report, security_review, solid_review, optimization)
    else:
        print("\nNo critical issues - skipping fix PR")

    print("\nAI Code Review complete!")


if __name__ == "__main__":
    main()