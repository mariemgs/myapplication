import os
import requests
from langchain_core.tools import tool

# Configuration
GITHUB_TOKEN = os.environ.get("GH_PAT")
REPO = os.environ.get("GITHUB_REPOSITORY")
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://192.168.29.131:9090")

@tool
def fetch_pipeline_logs(run_id: str) -> str:
    """Fetch logs from a failed GitHub Actions run by run ID"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    jobs_url = f"https://api.github.com/repos/{REPO}/actions/runs/{run_id}/jobs"
    response = requests.get(jobs_url, headers=headers)

    if response.status_code != 200:
        return f"Could not fetch jobs: {response.status_code}"

    jobs = response.json()
    failed_logs = []

    for job in jobs.get("jobs", []):
        if job["conclusion"] in ["failure", "cancelled"]:
            job_id = job["id"]
            job_name = job["name"]
            logs_url = f"https://api.github.com/repos/{REPO}/actions/jobs/{job_id}/logs"
            logs_response = requests.get(logs_url, headers=headers, allow_redirects=True)
            if logs_response.status_code == 200:
                log_lines = logs_response.text.split("\n")[-100:]
                failed_logs.append(f"Job: {job_name}\n{''.join(log_lines)}")

    return "\n\n".join(failed_logs) if failed_logs else "No failed jobs found"


@tool
def query_prometheus(metric: str) -> str:
    """Query Prometheus API for a specific PromQL metric expression"""
    try:
        url = f"{PROMETHEUS_URL}/api/v1/query"
        response = requests.get(url, params={"query": metric}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            results = data.get("data", {}).get("result", [])
            if results:
                return f"Metric '{metric}': {results[0]['value'][1]}"
            return f"No data for metric: {metric}"
        return f"Prometheus error: {response.status_code}"
    except Exception as e:
        return f"Could not query Prometheus: {e}"


@tool
def post_github_comment(comment: str) -> str:
    """Post a comment on the current GitHub commit"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    commit_sha = os.environ.get("GITHUB_SHA", "")
    url = f"https://api.github.com/repos/{REPO}/commits/{commit_sha}/comments"
    response = requests.post(url, json={"body": comment}, headers=headers)
    if response.status_code in [200, 201]:
        return "Comment posted successfully"
    return f"Failed to post comment: {response.status_code}"


@tool
def create_github_issue(title: str, body: str) -> str:
    """Create a GitHub issue with the given title and body"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"https://api.github.com/repos/{REPO}/issues"
    payload = {
        "title": title,
        "body": body,
        "labels": ["monitoring", "alert", "automated"]
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 201:
        return f"Issue created: {response.json().get('html_url')}"
    return f"Failed to create issue: {response.status_code}"


@tool
def read_security_report(report_type: str) -> str:
    """Read a security report file. report_type can be: bandit, trivy, pipaudit, zap"""
    files = {
        "bandit": "security-reports/bandit-report.json",
        "trivy": "security-reports/trivy-image-report.json",
        "pipaudit": "security-reports/pip-audit-report.json",
        "zap": "zap-report/report_html.html"
    }
    
    filepath = files.get(report_type)
    if not filepath:
        return f"Unknown report type: {report_type}"
    
    if not os.path.exists(filepath):
        return f"{report_type} report not available"
    
    try:
        import json
        with open(filepath) as f:
            if filepath.endswith('.json'):
                data = json.load(f)
                return json.dumps(data, indent=2)[:3000]
            else:
                return f.read()[:3000]
    except Exception as e:
        return f"Could not read {report_type} report: {e}"
