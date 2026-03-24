import os
import sys
import requests
import json

# Configuration
GITHUB_TOKEN = os.environ.get("GH_PAT")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
REPO = os.environ.get("GITHUB_REPOSITORY")
RUN_ID = os.environ.get("GITHUB_RUN_ID")
PR_NUMBER = os.environ.get("PR_NUMBER")

def get_failed_logs():
    """Fetch logs from failed GitHub Actions run"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Get jobs for this run
    jobs_url = f"https://api.github.com/repos/{REPO}/actions/runs/{RUN_ID}/jobs"
    response = requests.get(jobs_url, headers=headers)
    jobs = response.json()
    
    failed_logs = []
    
    for job in jobs.get("jobs", []):
        if job["conclusion"] == "failure":
            job_id = job["id"]
            job_name = job["name"]
            
            # Get logs for failed job
            logs_url = f"https://api.github.com/repos/{REPO}/actions/jobs/{job_id}/logs"
            logs_response = requests.get(logs_url, headers=headers, allow_redirects=True)
            
            if logs_response.status_code == 200:
                # Get last 100 lines of logs
                log_lines = logs_response.text.split("\n")[-100:]
                logs = "\n".join(log_lines)
                failed_logs.append(f"Job: {job_name}\n{logs}")
    
    return "\n\n".join(failed_logs) if failed_logs else "No failed job logs found"

def analyze_with_gemini(logs):
    """Send logs to Gemini for analysis"""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    
    prompt = f"""You are a DevOps expert analyzing a CI/CD pipeline failure.

Analyze these GitHub Actions failure logs and provide:
1. **What failed** - clearly identify the failing step
2. **Why it failed** - explain the root cause
3. **How to fix it** - provide specific actionable steps

Keep your response concise and developer-friendly.
Use markdown formatting.

Failed logs:
{logs[:8000]}
"""
    
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }
    
    response = requests.post(url, json=payload)
    data = response.json()
    
    if "candidates" in data:
        return data["candidates"][0]["content"]["parts"][0]["text"]
    else:
        return f"Error analyzing logs: {data}"

def post_github_comment(analysis):
    """Post analysis as GitHub comment"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    comment = f"""## 🤖 AI Pipeline Failure Analysis

{analysis}

---
*Powered by Gemini AI • Automated DevSecOps Agent*
"""
    
    if PR_NUMBER and PR_NUMBER != "":
        # Post on PR
        url = f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments"
    else:
        # Post on commit
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
    
    print("📋 Fetching failed job logs...")
    logs = get_failed_logs()
    print(f"📝 Got {len(logs)} characters of logs")
    
    print("🧠 Analyzing with Gemini AI...")
    analysis = analyze_with_gemini(logs)
    print("✅ Analysis complete!")
    print("\n--- Analysis ---")
    print(analysis)
    print("--- End Analysis ---\n")
    
    print("💬 Posting comment to GitHub...")
    post_github_comment(analysis)

if __name__ == "__main__":
    main()
