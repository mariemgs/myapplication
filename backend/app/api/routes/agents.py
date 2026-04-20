from typing import Any
import httpx
import os
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.api.deps import CurrentUser

router = APIRouter(prefix="/agents", tags=["agents"])

GITHUB_TOKEN = os.environ.get("GH_PAT", "")
REPO = os.environ.get("GITHUB_REPOSITORY", "mariemgs/myapplication")
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
}

AGENT_WORKFLOWS = [
    {
        "id": "ai-failure-analyzer",
        "name": "Failure Analyzer",
        "icon": "🔴",
        "description": "Analyzes CI/CD pipeline failures and suggests fixes",
        "file": "ai-failure-analyzer.yml",
    },
    {
        "id": "ai-security-analyzer",
        "name": "Security Analyzer",
        "icon": "🔒",
        "description": "Generates unified security reports from Bandit, Trivy, ZAP & SonarQube",
        "file": "ai-security-analyzer.yml",
    },
    {
        "id": "ai-monitoring-agent",
        "name": "Monitoring Agent",
        "icon": "📊",
        "description": "Queries Prometheus metrics and opens GitHub Issues on anomalies",
        "file": "ai-monitoring-agent.yml",
    },
    {
        "id": "ai-code-review",
        "name": "Code Review Agent",
        "icon": "🔍",
        "description": "Reviews Pull Requests and creates fix PRs automatically",
        "file": "ai-code-review.yml",
    },
    {
        "id": "ai-orchestrator",
        "name": "Orchestrator",
        "icon": "🤖",
        "description": "LangGraph multi-agent system coordinating all agents",
        "file": "ai-orchestrator.yml",
    },
]


def time_ago(date_str: str | None) -> str:
    if not date_str:
        return "Never"
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        diff = datetime.now(timezone.utc) - dt
        mins = int(diff.total_seconds() / 60)
        if mins < 1:
            return "Just now"
        if mins < 60:
            return f"{mins}m ago"
        hours = mins // 60
        if hours < 24:
            return f"{hours}h ago"
        return f"{hours // 24}d ago"
    except Exception:
        return date_str


class TriggerRequest(BaseModel):
    workflow_id: str


@router.get("/status")
def get_agents_status(current_user: CurrentUser) -> Any:
    """Get status of all AI agents from GitHub Actions"""
    agents = []
    with httpx.Client() as client:
        for agent in AGENT_WORKFLOWS:
            try:
                url = f"https://api.github.com/repos/{REPO}/actions/workflows/{agent['file']}/runs?per_page=1"
                response = client.get(url, headers=HEADERS, timeout=10)
                if response.status_code == 200:
                    runs = response.json().get("workflow_runs", [])
                    if runs:
                        last_run = runs[0]
                        created_at = last_run.get("created_at")
                        agents.append({
                            "name": agent["name"],
                            "icon": agent["icon"],
                            "description": agent["description"],
                            "workflow_file": agent["file"],
                            "status": last_run.get("status", "unknown"),
                            "conclusion": last_run.get("conclusion") or "in_progress",
                            "last_run": time_ago(created_at),
                            "last_run_url": last_run.get("html_url"),
                            "run_number": last_run.get("run_number"),
                        })
                    else:
                        agents.append({
                            "name": agent["name"],
                            "icon": agent["icon"],
                            "description": agent["description"],
                            "workflow_file": agent["file"],
                            "status": "never_run",
                            "conclusion": None,
                            "last_run": "Never",
                            "last_run_url": None,
                            "run_number": None,
                        })
                else:
                    agents.append({
                        "name": agent["name"],
                        "icon": agent["icon"],
                        "description": agent["description"],
                        "workflow_file": agent["file"],
                        "status": "unknown",
                        "conclusion": None,
                        "last_run": "Unknown",
                        "last_run_url": None,
                        "run_number": None,
                    })
            except Exception:
                agents.append({
                    "name": agent["name"],
                    "icon": agent["icon"],
                    "description": agent["description"],
                    "workflow_file": agent["file"],
                    "status": "error",
                    "conclusion": None,
                    "last_run": "Error",
                    "last_run_url": None,
                    "run_number": None,
                })
    return agents


@router.get("/reports")
def get_agent_reports(current_user: CurrentUser) -> Any:
    """Get recent AI agent reports from GitHub commit comments"""
    with httpx.Client() as client:
        try:
            url = f"https://api.github.com/repos/{REPO}/comments?per_page=20"
            response = client.get(url, headers=HEADERS, timeout=10)
            if response.status_code != 200:
                return {"reports": []}
            comments = response.json()
            reports = []
            for comment in comments:
                body = comment.get("body", "")
                if any(keyword in body for keyword in ["🤖", "🔒", "📊", "AI Pipeline", "AI Security", "Orchestrator"]):
                    report_type = "unknown"
                    if "Failure Analysis" in body or "Pipeline Failure" in body:
                        report_type = "failure"
                    elif "Security" in body:
                        report_type = "security"
                    elif "Monitoring" in body or "Orchestrator" in body:
                        report_type = "orchestrator"
                    elif "Code Review" in body:
                        report_type = "review"
                    reports.append({
                        "id": comment.get("id"),
                        "type": report_type,
                        "body": body[:500],
                        "created_at": time_ago(comment.get("created_at")),
                        "url": comment.get("html_url"),
                        "commit_id": comment.get("commit_id", "")[:7],
                    })
            return {"reports": reports[:10]}
        except Exception:
            return {"reports": []}


@router.get("/issues")
def get_monitoring_issues(current_user: CurrentUser) -> Any:
    """Get open monitoring issues from GitHub"""
    with httpx.Client() as client:
        try:
            url = f"https://api.github.com/repos/{REPO}/issues?state=open&labels=monitoring&per_page=10"
            response = client.get(url, headers=HEADERS, timeout=10)
            if response.status_code != 200:
                return {"issues": []}
            issues = response.json()
            return {
                "issues": [
                    {
                        "id": issue.get("number"),
                        "title": issue.get("title"),
                        "created_at": time_ago(issue.get("created_at")),
                        "url": issue.get("html_url"),
                        "labels": [l.get("name") for l in issue.get("labels", [])],
                    }
                    for issue in issues
                ]
            }
        except Exception:
            return {"issues": []}


@router.get("/pipeline")
def get_pipeline_status(current_user: CurrentUser) -> Any:
    """Get recent pipeline workflow runs"""
    pipeline_workflows = [
        "test-backend.yml",
        "test-docker-compose.yml",
        "owasp-zap.yml",
        "sonarqube.yml",
        "deploy-staging.yml",
    ]
    pipeline = []
    with httpx.Client() as client:
        for workflow in pipeline_workflows:
            try:
                url = f"https://api.github.com/repos/{REPO}/actions/workflows/{workflow}/runs?per_page=1"
                response = client.get(url, headers=HEADERS, timeout=10)
                if response.status_code == 200:
                    runs = response.json().get("workflow_runs", [])
                    if runs:
                        run = runs[0]
                        name = workflow.replace(".yml", "").replace("-", " ").title()
                        pipeline.append({
                            "name": name,
                            "status": run.get("status", "unknown"),
                            "conclusion": run.get("conclusion") or "in_progress",
                            "last_run": time_ago(run.get("created_at")),
                            "url": run.get("html_url"),
                        })
            except Exception:
                pass
    return {"pipeline": pipeline}


@router.post("/trigger")
def trigger_agent(request: TriggerRequest, current_user: CurrentUser) -> Any:
    """Manually trigger an AI agent workflow"""
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Only superusers can trigger agents")
    workflow_map = {agent["id"]: agent["file"] for agent in AGENT_WORKFLOWS}
    workflow_file = workflow_map.get(request.workflow_id)
    if not workflow_file:
        raise HTTPException(status_code=404, detail="Agent not found")
    with httpx.Client() as client:
        url = f"https://api.github.com/repos/{REPO}/actions/workflows/{workflow_file}/dispatches"
        response = client.post(
            url,
            headers=HEADERS,
            json={"ref": "main"},
            timeout=10
        )
        if response.status_code == 204:
            return {"message": f"Agent {request.workflow_id} triggered successfully"}
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Failed to trigger agent: {response.text}"
            )
