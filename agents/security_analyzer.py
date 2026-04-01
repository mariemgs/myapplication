import os
import requests
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage

# Configuration
GITHUB_TOKEN = os.environ.get("GH_PAT")
REPO = os.environ.get("GITHUB_REPOSITORY")
GITHUB_SHA = os.environ.get("GITHUB_SHA")
PR_NUMBER = os.environ.get("PR_NUMBER")
BANDIT_RESULTS = os.environ.get("BANDIT_RESULTS", "Not available")
TRIVY_RESULTS = os.environ.get("TRIVY_RESULTS", "Not available")
ZAP_RESULTS = os.environ.get("ZAP_RESULTS", "Not available")
SONAR_RESULTS = os.environ.get("SONAR_RESULTS", "Not available")

# LangChain LLM
llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0.3,
    api_key=os.environ.get("GROQ_API_KEY")
)


def analyze_with_langchain():
    """Send security results to Groq via LangChain"""
    messages = [
        SystemMessage(content="You are a DevSecOps security expert."),
        HumanMessage(content=f"""Analyze these security scan results and provide a unified report:

## Bandit (Python SAST):
{BANDIT_RESULTS[:2000]}

## Trivy (Container/Dependency):
{TRIVY_RESULTS[:2000]}

## OWASP ZAP (DAST):
{ZAP_RESULTS[:2000]}

## SonarQube:
{SONAR_RESULTS[:1000]}

Provide:
1. **Executive Summary** - Overall security posture
2. **Critical Issues** - Fix immediately
3. **High Priority Issues** - Fix soon
4. **Medium/Low Issues** - Next sprint
5. **Recommendations** - Top 3 actionable fixes

Format in clean markdown.""")
    ]

    try:
        response = llm.invoke(messages)
        return response.content
    except Exception as e:
        return f"⚠️ LangChain/Groq error: {str(e)}"


def post_github_comment(analysis):
    """Post security report as GitHub comment"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    comment = f"""## 🔒 AI Security Analysis Report

{analysis}

---
*Powered by LangChain + Groq (Llama3) • Agentic DevSecOps Security Agent*
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

    print("🧠 Analyzing security results with LangChain + Groq...")
    analysis = analyze_with_langchain()
    print("✅ Analysis complete!")
    print("\n--- Security Report ---")
    print(analysis)
    print("--- End Report ---\n")

    print("💬 Posting security report to GitHub...")
    post_github_comment(analysis)


if __name__ == "__main__":
    main()
