import os
import requests
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage

# Configuration
GITHUB_TOKEN = os.environ.get("GH_PAT")
REPO = os.environ.get("GITHUB_REPOSITORY")
PR_NUMBER = os.environ.get("PR_NUMBER")
HEAD_SHA = os.environ.get("HEAD_SHA")

# LangChain LLM
llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0.2,
    api_key=os.environ.get("GROQ_API_KEY")
)

headers = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}


def get_pr_diff():
    """Fetch the PR diff"""
    url = f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}/files"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return None, f"Could not fetch PR files: {response.status_code}"

    files = response.json()
    diff_content = []

    for file in files:
        filename = file["filename"]
        patch = file.get("patch", "")
        status = file.get("status", "")
        diff_content.append(f"## File: {filename} ({status})\n```diff\n{patch}\n```")

    return files, "\n\n".join(diff_content)


def analyze_code_with_langchain(diff, files):
    """Analyze the PR diff using LangChain + Groq"""
    messages = [
        SystemMessage(content="""You are an expert code reviewer specializing in:
- Python best practices (PEP8, clean code)
- Security vulnerabilities (OWASP Top 10)
- Performance issues
- FastAPI best practices
- Docker and DevOps practices
- Missing error handling
- Missing tests

Be specific, constructive, and actionable."""),
        HumanMessage(content=f"""Review this Pull Request diff and provide:

1. **Summary** - Overall assessment (Approve/Request Changes/Comment)
2. **Critical Issues** - Security or breaking bugs (must fix)
3. **Code Quality Issues** - Bad practices, performance problems
4. **Suggestions** - Improvements and best practices
5. **Positive Points** - What was done well
6. **Suggested Fixes** - For each critical issue, provide the corrected code

Format your response as structured markdown.
Be specific about file names and line numbers when possible.

PR Diff:
{diff[:10000]}
""")
    ]

    try:
        response = llm.invoke(messages)
        return response.content
    except Exception as e:
        return f"⚠️ Analysis error: {str(e)}"


def post_pr_review(analysis, files):
    """Post review comment on the PR"""
    # Determine review action based on analysis
    action = "COMMENT"
    if "critical" in analysis.lower() or "security" in analysis.lower():
        action = "REQUEST_CHANGES"
    elif "approve" in analysis.lower()[:200]:
        action = "APPROVE"

    url = f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}/reviews"
    payload = {
        "commit_id": HEAD_SHA,
        "body": f"""## 🤖 AI Code Review

{analysis}

---
*Powered by LangChain + Groq (Llama3) • AI Code Review Agent*
*This is an automated review. Please use your judgment before merging.*
""",
        "event": action,
        "comments": []
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code in [200, 201]:
        print(f"✅ Review posted with action: {action}")
        return True
    else:
        print(f"❌ Failed to post review: {response.status_code} {response.text}")
        return False


def generate_fix_branch(files, analysis):
    """Level 2: Create a fix branch with suggested improvements"""

    # Get the fix suggestions from the LLM
    messages = [
        SystemMessage(content="You are an expert Python developer. Provide ONLY the fixed code, no explanations."),
        HumanMessage(content=f"""Based on this code review:

{analysis[:3000]}

And these changed files:
{[f['filename'] for f in files if f['filename'].endswith('.py')]}

For each Python file that has critical issues, provide the complete fixed version.
Format your response as:

FILE: path/to/file.py
```python
# complete fixed file content here
```

Only include files that need critical fixes.""")
    ]

    try:
        response = llm.invoke(messages)
        return response.content
    except Exception as e:
        return f"⚠️ Fix generation error: {str(e)}"


def create_fix_pr(files, analysis):
    """Level 2: Create a new branch and PR with fixes"""
    print("🔧 Creating fix branch...")

    # Get fix suggestions
    fix_suggestions = generate_fix_branch(files, analysis)
    print(f"📝 Fix suggestions generated ({len(fix_suggestions)} chars)")

    # Get base branch info
    pr_url = f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}"
    pr_response = requests.get(pr_url, headers=headers)
    if pr_response.status_code != 200:
        print("❌ Could not fetch PR info")
        return

    pr_data = pr_response.json()
    base_branch = pr_data["head"]["ref"]
    base_sha = pr_data["head"]["sha"]

    # Create fix branch
    fix_branch = f"ai-fixes/pr-{PR_NUMBER}"

    # Check if branch exists and delete if so
    check_url = f"https://api.github.com/repos/{REPO}/git/refs/heads/{fix_branch}"
    check_response = requests.get(check_url, headers=headers)
    if check_response.status_code == 200:
        requests.delete(check_url, headers=headers)
        print(f"🗑️ Deleted existing branch: {fix_branch}")

    # Create new branch
    branch_url = f"https://api.github.com/repos/{REPO}/git/refs"
    branch_payload = {
        "ref": f"refs/heads/{fix_branch}",
        "sha": base_sha
    }
    branch_response = requests.post(branch_url, json=branch_payload, headers=headers)

    if branch_response.status_code not in [200, 201]:
        print(f"❌ Could not create branch: {branch_response.status_code} {branch_response.text}")
        return

    print(f"✅ Created branch: {fix_branch}")

    # Create a summary file with all fix suggestions
    summary_content = f"""# AI Code Review Fixes for PR #{PR_NUMBER}

## Review Summary
{analysis[:2000]}

## Suggested Fixes
{fix_suggestions}

---
*Generated by AI Code Review Agent • LangChain + Groq*
*Review and apply these fixes manually or use them as reference.*
"""

    # Add the fix summary file to the branch
    import base64
    file_url = f"https://api.github.com/repos/{REPO}/contents/ai-review/pr-{PR_NUMBER}-fixes.md"
    file_payload = {
        "message": f"🤖 AI suggested fixes for PR #{PR_NUMBER}",
        "content": base64.b64encode(summary_content.encode()).decode(),
        "branch": fix_branch
    }

    file_response = requests.put(file_url, json=file_payload, headers=headers)
    if file_response.status_code not in [200, 201]:
        print(f"❌ Could not create fix file: {file_response.status_code}")
        return

    print("✅ Fix file created on branch")

    # Open a PR with the fixes
    fix_pr_url = f"https://api.github.com/repos/{REPO}/pulls"
    fix_pr_payload = {
        "title": f"🤖 AI Suggested Fixes for PR #{PR_NUMBER}",
        "body": f"""## 🤖 AI Code Review — Suggested Fixes

This PR was automatically created by the AI Code Review Agent with suggested improvements for PR #{PR_NUMBER}.

## What was reviewed
{analysis[:1500]}

## Suggested Fixes
{fix_suggestions[:2000]}

---
> ⚠️ **Human review required** — These are AI suggestions. Please review carefully before merging.
> 
> *Powered by LangChain + Groq (Llama3) • AI Code Review Agent*
""",
        "head": fix_branch,
        "base": "main"
    }

    fix_pr_response = requests.post(fix_pr_url, json=fix_pr_payload, headers=headers)
    if fix_pr_response.status_code in [200, 201]:
        fix_pr_data = fix_pr_response.json()
        print(f"✅ Fix PR created: {fix_pr_data.get('html_url')}")

        # Comment on original PR linking to fix PR
        comment_url = f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments"
        comment_payload = {
            "body": f"""## 🤖 AI Fix PR Created

I've analyzed your code and created a PR with suggested fixes:
👉 {fix_pr_data.get('html_url')}

Please review the suggestions and apply what makes sense.

*AI Code Review Agent • LangChain + Groq*"""
        }
        requests.post(comment_url, json=comment_payload, headers=headers)
    else:
        print(f"❌ Could not create fix PR: {fix_pr_response.status_code} {fix_pr_response.text}")


def main():
    print("🔍 AI Code Review Agent starting...")
    print(f"Repository: {REPO}")
    print(f"PR Number: {PR_NUMBER}")
    print(f"HEAD SHA: {HEAD_SHA}")

    # Fetch PR diff
    print("\n📥 Fetching PR diff...")
    files, diff = get_pr_diff()

    if files is None:
        print(f"❌ Error: {diff}")
        return

    print(f"✅ Found {len(files)} changed files")

    # Level 1: Analyze and review
    print("\n🧠 Analyzing code with LangChain + Groq...")
    analysis = analyze_code_with_langchain(diff, files)
    print("✅ Analysis complete!")
    print("\n--- Review ---")
    print(analysis[:500])
    print("--- End Review ---\n")

    # Post review on PR
    print("💬 Posting review on PR...")
    post_pr_review(analysis, files)

    # Level 2: Create fix PR if issues found
    if "critical" in analysis.lower() or "request changes" in analysis.lower():
        print("\n🔧 Critical issues found — creating fix PR...")
        create_fix_pr(files, analysis)
    else:
        print("\n✅ No critical issues — skipping fix PR creation")


if __name__ == "__main__":
    main()
