import os
import requests
import json
# Configuration
GITHUB_TOKEN = os.environ.get("GH_PAT")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
REPO = os.environ.get("GITHUB_REPOSITORY")
RUN_ID = os.environ.get("GITHUB_RUN_ID")
PR_NUMBER = os.environ.get("PR_NUMBER")


def get_failed_logs():
    """Fetch logs from failed GitHub Actions run"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    jobs_url = f"https://api.github.com/repos/{REPO}/actions/runs/{RUN_ID}/jobs"
    response = requests.get(jobs_url, headers=headers)

    if response.status_code != 200:
        return f"❌ Could not fetch jobs: {response.status_code} {response.text}"

    jobs = response.json()
    failed_logs = []

    for job in jobs.get("jobs", []):
        if job["conclusion"] == "failure":
            job_id = job["id"]
            job_name = job["name"]
            print(f"❌ Found failed job: {job_name} (id: {job_id})")

            logs_url = f"https://api.github.com/repos/{REPO}/actions/jobs/{job_id}/logs"
            logs_response = requests.get(
                logs_url,
                headers=headers,
                allow_redirects=True
            )

            if logs_response.status_code == 200:
                log_lines = logs_response.text.split("\n")[-150:]
                logs = "\n".join(log_lines)
                failed_logs.append(f"### Job: {job_name}\n```\n{logs}\n```")
            else:
                failed_logs.append(
                    f"### Job: {job_name}\nCould not fetch logs: {logs_response.status_code}"
                )

    if not failed_logs:
        all_jobs = [f"{j['name']}: {j['conclusion']}" for j in jobs.get("jobs", [])]
        return f"No failed jobs found. All jobs: {all_jobs}"

    return "\n\n".join(failed_logs)


def analyze_with_groq(logs):
    """Send logs to Groq for analysis"""

    if not GROQ_API_KEY:
        return "❌ Missing GROQ_API_KEY"

    url = "https://api.groq.com/openai/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    prompt = f"""You are a DevOps expert analyzing a CI/CD pipeline failure.

Analyze these GitHub Actions failure logs and provide:

1. What failed
2. Why it failed (root cause)
3. How to fix it (clear actionable steps)

Be concise, technical, and developer-friendly.

Logs:
{logs[:8000]}
"""

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": "You are a DevOps and DevSecOps expert."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3
    }

    try:
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            return f"❌ Groq API error: {response.status_code} {response.text}"

        data = response.json()

        # Safe parsing
        if "choices" in data and len(data["choices"]) > 0:
            return data["choices"][0]["message"]["content"]
        else:
            return f"⚠️ Unexpected Groq response format: {data}"

    except Exception as e:
        return f"⚠️ Exception during Groq call: {str(e)}"


def post_github_comment(analysis):
    """Post analysis as GitHub comment"""

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    comment = f"""## 🤖 AI Pipeline Failure Analysis

{analysis}

---
*Powered by Groq (Llama3) • Agentic DevSecOps System*
"""

    if PR_NUMBER and PR_NUMBER not in ["", "None"]:
        url = f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments"
    else:
        commit_sha = os.environ.get("GITHUB_SHA", "")
        url = f"https://api.github.com/repos/{REPO}/commits/{commit_sha}/comments"

    response = requests.post(url, json={"body": comment}, headers=headers)

    if response.status_code in [200, 201]:
        print("✅ Analysis posted successfully!")
    else:
        print(f"❌ Failed to post comment: {response.status_code}")
        print(response.text)


def main():
    print("🤖 AI Failure Analyzer starting...")
    print(f"Repository: {REPO}")
    print(f"Run ID: {RUN_ID}")

    print("📋 Fetching failed job logs...")
    logs = get_failed_logs()

    print(f"📝 Got {len(logs)} characters of logs")
    print(f"Preview: {logs[:200]}")

    print("🧠 Analyzing with Groq AI...")
    analysis = analyze_with_groq(logs)

    print("✅ Analysis complete!")
    print("\n--- Analysis ---")
    print(analysis)
    print("--- End Analysis ---\n")

    print("💬 Posting comment to GitHub...")
    post_github_comment(analysis)


if __name__ == "__main__":
    main()