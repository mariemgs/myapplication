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
    
    jobs_url = f"https://api.github.com/repos/{REPO}/actions/runs/{RUN_ID}/jobs"
    response = requests.get(jobs_url, headers=headers)
    
    if response.status_code != 200:
        return f"Could not fetch jobs: {response.status_code} {response.text}"
    
    jobs = response.json()
    failed_logs = []
    
    for job in jobs.get("jobs", []):
        if job["conclusion"] == "failure":
            job_id = job["id"]
            job_name = job["name"]
            print(f"Found failed job: {job_name} (id: {job_id})")
            
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
                failed_logs.append(f"### Job: {job_name}\nCould not fetch logs: {logs_response.status_code}")
    
    if not failed_logs:
        # Try to get all jobs for debugging
        all_jobs = [f"{j['name']}: {j['conclusion']}" for j in jobs.get("jobs", [])]
        return f"No failed jobs found. All jobs: {all_jobs}"
    
    return "\n\n".join(failed_logs)

def analyze_with_gemini(logs):
    """Send logs to Gemini for analysis"""
    
    models = [
        "gemini-1.5-flash-8b",
        "gemini-1.5-flash",
        "gemini-1.0-pro"
    ]
    
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
    
    for model in models:
        print(f"Trying model: {model}")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }
        response = requests.post(url, json=payload)
        data = response.json()
        
        if "candidates" in data:
            print(f"✅ Got response from {model}")
            return data["candidates"][0]["content"]["parts"][0]["text"]
        elif data.get("error", {}).get("code") == 429:
            print(f"⚠️ Model {model} rate limited, trying next...")
            continue
        else:
            print(f"❌ Error from {model}: {data}")
            continue
    
    return "⚠️ All models are currently rate limited. Please try again in a few minutes."

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
    
    if PR_NUMBER and PR_NUMBER != "" and PR_NUMBER != "None":
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