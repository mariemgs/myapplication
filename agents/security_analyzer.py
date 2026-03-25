import os
import requests
import json

# Configuration
GITHUB_TOKEN = os.environ.get("GH_PAT")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
REPO = os.environ.get("GITHUB_REPOSITORY")
GITHUB_SHA = os.environ.get("GITHUB_SHA")
PR_NUMBER = os.environ.get("PR_NUMBER")

# Security scan results passed as env vars
BANDIT_RESULTS = os.environ.get("BANDIT_RESULTS", "Not available")
TRIVY_RESULTS = os.environ.get("TRIVY_RESULTS", "Not available")
ZAP_RESULTS = os.environ.get("ZAP_RESULTS", "Not available")
SONAR_RESULTS = os.environ.get("SONAR_RESULTS", "Not available")


def analyze_with_groq(report):
    """Send security report to Groq for analysis"""

    if not GROQ_API_KEY:
        return "❌ Missing GROQ_API_KEY"

    url = "https://api.groq.com/openai/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    prompt = f"""You are a DevSecOps security expert. Analyze these security scan results from multiple tools and provide a unified security report.

Security Scan Results:

## Bandit (Python SAST):
{BANDIT_RESULTS[:2000]}

## Trivy (Container/Dependency Scan):
{TRIVY_RESULTS[:2000]}

## OWASP ZAP (DAST):
{ZAP_RESULTS[:2000]}

## SonarQube:
{SONAR_RESULTS[:2000]}

Please provide:
1. **Executive Summary** - Overall security posture (Critical/High/Medium/Low)
2. **Critical Issues** - Issues that must be fixed immediately
3. **High Priority Issues** - Important issues to address soon
4. **Medium/Low Issues** - Issues to address in next sprint
5. **Recommendations** - Top 3 actionable fixes

Format your response in clean markdown.
Be concise and developer-friendly.
"""

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": "You are a DevSecOps and security expert."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3
    }

    try:
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            return f"❌ Groq API error: {response.status_code} {response.text}"

        data = response.json()

        if "choices" in data and len(data["choices"]) > 0:
            return data["choices"][0]["message"]["content"]
        else:
            return f"⚠️ Unexpected response: {data}"

    except Exception as e:
        return f"⚠️ Exception: {str(e)}"


def post_github_comment(analysis):
    """Post security report as GitHub comment"""

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    comment = f"""## 🔒 AI Security Analysis Report

{analysis}

---
*Powered by Groq (Llama3) • Agentic DevSecOps Security Agent*
"""

    if PR_NUMBER and PR_NUMBER not in ["", "None"]:
        url = f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments"
    else:
        url = f"https://api.github.com/repos/{REPO}/commits/{GITHUB_SHA}/comments"

    response = requests.post(url, json={"body": comment}, headers=headers)

    if response.status_code in [200, 201]:
        print("✅ Security report posted successfully!")
    else:
        print(f"❌ Failed to post: {response.status_code} {response.text}")


def main():
    print("🔒 AI Security Analyzer starting...")
    print(f"Repository: {REPO}")
    print(f"SHA: {GITHUB_SHA}")

    print("🧠 Analyzing security results with Groq...")
    analysis = analyze_with_groq("")

    print("✅ Analysis complete!")
    print("\n--- Security Report ---")
    print(analysis)
    print("--- End Report ---\n")

    print("💬 Posting security report to GitHub...")
    post_github_comment(analysis)


if __name__ == "__main__":
    main()
