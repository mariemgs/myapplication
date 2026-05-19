import os
import json
from typing import TypedDict
import requests
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agents.tools import (
    query_prometheus,
    post_github_comment,
    create_github_issue,
)

# ─── Shared State ───────────────────────────────────────────────
class AgentState(TypedDict):
    run_id: str
    commit_sha: str
    pipeline_logs: str
    bandit_results: str
    trivy_results: str
    pipaudit_results: str
    zap_results: str
    prometheus_metrics: str
    failure_analysis: str
    security_analysis: str
    monitoring_analysis: str
    critic_feedback: str
    final_report: str
    has_failure: bool
    has_security_issues: bool
    has_monitoring_issues: bool
    errors: list


def get_llm():
    return ChatGroq(
        model="llama-3.3-70b-versatile",
        temperature=0.3,
        api_key=os.environ.get("GROQ_API_KEY")
    )


# ─── Helper: fetch all recent failed runs ────────────────────────
def fetch_all_pipeline_logs() -> tuple[str, bool]:
    """Fetch logs from ALL recent workflow runs to find failures"""
    token = os.environ.get("GH_PAT")
    repo = os.environ.get("GITHUB_REPOSITORY")
    sha = os.environ.get("GITHUB_SHA", "")
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}

    # Get all runs for this commit
    url = f"https://api.github.com/repos/{repo}/actions/runs?head_sha={sha}&per_page=20"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return "Could not fetch runs", False

    runs = response.json().get("workflow_runs", [])
    failed_logs = []
    has_failure = False

    for run in runs:
        if run.get("conclusion") in ["failure", "cancelled"]:
            run_id = run["id"]
            run_name = run.get("name", "Unknown")
            has_failure = True

            # Get jobs for this run
            jobs_url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs"
            jobs_resp = requests.get(jobs_url, headers=headers)
            if jobs_resp.status_code != 200:
                continue

            for job in jobs_resp.json().get("jobs", []):
                if job["conclusion"] in ["failure", "cancelled"]:
                    job_id = job["id"]
                    job_name = job["name"]
                    logs_url = f"https://api.github.com/repos/{repo}/actions/jobs/{job_id}/logs"
                    logs_resp = requests.get(logs_url, headers=headers, allow_redirects=True)
                    if logs_resp.status_code == 200:
                        log_lines = logs_resp.text.split("\n")[-80:]
                        failed_logs.append(f"### ❌ {run_name} → {job_name}\n```\n{''.join(log_lines)}\n```")

    if not failed_logs:
        return f"✅ All workflows passed for commit {sha[:7]}", False

    return "\n\n".join(failed_logs), True


# ─── Helper: read security report files ─────────────────────────
def read_report(filepath: str, max_chars: int = 3000) -> str:
    """Read a security report file"""
    if not os.path.exists(filepath):
        # Try alternative paths
        alternatives = [
            filepath,
            os.path.basename(filepath),
            f"security-reports/{os.path.basename(filepath)}",
        ]
        for alt in alternatives:
            if os.path.exists(alt):
                filepath = alt
                break
        else:
            return f"Report not found: {filepath}"

    try:
        with open(filepath) as f:
            if filepath.endswith('.json'):
                data = json.load(f)
                # Parse bandit format
                if "results" in data:
                    results = data["results"]
                    if not results:
                        return "✅ No issues found by Bandit"
                    summary = f"Found {len(results)} issues:\n"
                    for r in results[:10]:
                        summary += f"- [{r.get('issue_severity')}] {r.get('issue_text')} in {r.get('filename')}:{r.get('line_number')}\n"
                    return summary
                # Parse trivy format
                if "Results" in data:
                    vulns = []
                    for result in data["Results"]:
                        for v in result.get("Vulnerabilities", []):
                            vulns.append(f"- [{v.get('Severity')}] {v.get('VulnerabilityID')} in {v.get('PkgName')} {v.get('InstalledVersion')}")
                    if not vulns:
                        return "✅ No vulnerabilities found by Trivy"
                    return f"Found {len(vulns)} vulnerabilities:\n" + "\n".join(vulns[:15])
                return json.dumps(data, indent=2)[:max_chars]
            else:
                return f.read()[:max_chars]
    except Exception as e:
        return f"Could not read report: {e}"


# ─── Node 1: Data Fetcher ────────────────────────────────────────
def data_fetcher_node(state: AgentState) -> AgentState:
    print("📥 Node 1: Fetching all data...")
    updates = {}

    # Fetch pipeline logs from ALL recent runs
    logs, has_failure = fetch_all_pipeline_logs()
    updates["pipeline_logs"] = logs
    updates["has_failure"] = has_failure

    # Read security reports
    updates["bandit_results"] = read_report("security-reports/bandit-report.json")
    updates["trivy_results"] = read_report("security-reports/trivy-image-report.json")
    updates["pipaudit_results"] = read_report("security-reports/pip-audit-report.json")
    updates["zap_results"] = read_report("zap-report/report_html.html")

    # Query Prometheus
    error_rate = query_prometheus.invoke({"metric": 'sum(rate(http_requests_total{status=~"4..|5.."}[5m])) / sum(rate(http_requests_total[5m]))'})
    response_time = query_prometheus.invoke({"metric": 'sum(rate(http_request_duration_seconds_sum[5m])) / sum(rate(http_request_duration_seconds_count[5m]))'})
    updates["prometheus_metrics"] = f"Error Rate: {error_rate}\nResponse Time: {response_time}"

    print(f"  ✅ Has failure: {has_failure}")
    print(f"  ✅ Bandit: {updates['bandit_results'][:80]}")
    print(f"  ✅ Trivy: {updates['trivy_results'][:80]}")
    print(f"  ✅ Prometheus: {updates['prometheus_metrics'][:100]}")

    return updates


# ─── Node 2: Failure Analyzer ────────────────────────────────────
def failure_analyzer_node(state: AgentState) -> AgentState:
    print("🔍 Node 2: Analyzing pipeline failures...")

    logs = state.get("pipeline_logs", "")
    has_failure = state.get("has_failure", False)

    if not has_failure:
        return {"failure_analysis": "✅ All pipeline jobs passed successfully. No failures detected."}

    llm = get_llm()
    messages = [
        SystemMessage(content="You are a DevOps expert. Be concise and technical."),
        HumanMessage(content=f"""Analyze these CI/CD pipeline failure logs:

{logs[:5000]}

Provide:
1. **What failed** - specific job/step names
2. **Root cause** - why it failed
3. **Fix** - exact steps to resolve

Format in markdown. Be specific and actionable.""")
    ]

    response = llm.invoke(messages)
    print(f"  ✅ Failure analysis complete")
    return {"failure_analysis": response.content}


# ─── Node 3: Security Analyzer ───────────────────────────────────
def security_analyzer_node(state: AgentState) -> AgentState:
    print("🔒 Node 3: Analyzing security scan results...")

    llm = get_llm()
    messages = [
        SystemMessage(content="You are a DevSecOps security expert. Be specific and actionable."),
        HumanMessage(content=f"""Analyze these security scan results and provide a detailed report:

## Bandit (Python SAST):
{state.get('bandit_results', 'Not available')}

## Trivy (Container vulnerabilities):
{state.get('trivy_results', 'Not available')}

## pip-audit (Dependency vulnerabilities):
{state.get('pipaudit_results', 'Not available')}

## OWASP ZAP (Dynamic scan):
{state.get('zap_results', 'Not available')[:500]}

Provide:
1. **Executive Summary** - Overall security posture with counts (Critical/High/Medium/Low)
2. **Critical Issues** - List each with CVE if available and exact fix
3. **High Priority Issues** - List each with recommended fix
4. **Top 3 Actionable Recommendations**

Be specific about actual findings, not generic advice.""")
    ]

    response = llm.invoke(messages)
    has_security_issues = any(k in response.content.lower() for k in ["critical", "high", "vulnerability", "cve"])

    print(f"  ✅ Security analysis complete")
    return {
        "security_analysis": response.content,
        "has_security_issues": has_security_issues
    }


# ─── Node 4: Monitoring Agent ─────────────────────────────────────
def monitoring_agent_node(state: AgentState) -> AgentState:
    print("📊 Node 4: Monitoring analysis...")

    from agents.monitoring_agent import collect_metrics, detect_anomalies, analyze_with_langchain

    metrics = collect_metrics()
    anomalies = detect_anomalies(metrics)

    error_rate = metrics.get('error_rate')
    response_time = metrics.get('response_time')
    request_rate = metrics.get('request_rate')
    total_requests = metrics.get('total_requests')

    metrics_table = f"""## 📊 Current Metrics

| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Error Rate | {f"{error_rate*100:.2f}%" if error_rate is not None else "N/A"} | 5% | {"🔴" if error_rate and error_rate > 0.05 else "✅"} |
| Response Time | {f"{response_time:.3f}s" if response_time is not None else "N/A"} | 2s | {"🔴" if response_time and response_time > 2.0 else "✅"} |
| Request Rate | {f"{request_rate:.2f} req/min" if request_rate is not None else "N/A"} | - | ℹ️ |
| Total Requests | {int(total_requests) if total_requests is not None else "N/A"} | - | ℹ️ |

> 📡 Prometheus: http://192.168.29.131:9090 | Grafana: http://192.168.29.131:3000"""

    if anomalies:
        ai_analysis = analyze_with_langchain(metrics, anomalies)
        analysis = f"{metrics_table}\n\n## 🤖 AI Analysis\n{ai_analysis}"
        has_monitoring_issues = True
    else:
        analysis = f"✅ **App is healthy** — No anomalies detected.\n\n{metrics_table}"
        has_monitoring_issues = False

    print(f"  ✅ Monitoring analysis complete")
    return {
        "monitoring_analysis": analysis,
        "has_monitoring_issues": has_monitoring_issues
    }


# ─── Node 5: Critic ──────────────────────────────────────────────
def critic_node(state: AgentState) -> AgentState:
    print("🧐 Node 5: Critic review...")

    llm = get_llm()
    messages = [
        SystemMessage(content="You are a senior DevSecOps reviewer."),
        HumanMessage(content=f"""Review these analyses briefly:

## Failure Analysis:
{state.get('failure_analysis', 'None')[:800]}

## Security Analysis:
{state.get('security_analysis', 'None')[:800]}

## Monitoring:
{state.get('monitoring_analysis', 'None')[:400]}

In 3-4 sentences: Are these accurate? What's missing? Overall assessment.""")
    ]

    response = llm.invoke(messages)
    print(f"  ✅ Critic complete")
    return {"critic_feedback": response.content}


# ─── Node 6: Reporter ────────────────────────────────────────────
def reporter_node(state: AgentState) -> AgentState:
    print("📝 Node 6: Generating final report...")

    report = f"""## 🤖 AI Orchestrator — Unified DevSecOps Report

---

## {'🔴' if state.get('has_failure') else '✅'} Pipeline Status
{state.get('failure_analysis', 'No analysis available')}

---

## 🔒 Security Analysis
{state.get('security_analysis', 'No security analysis available')}

---

## 📊 Monitoring
{state.get('monitoring_analysis', 'Metrics not available')}

---

## 🧐 Critic Review
{state.get('critic_feedback', 'No review available')}

---
*Generated by LangGraph Multi-Agent Orchestrator • Powered by Groq (Llama3)*
*Nodes: Data Fetcher → Failure Analyzer → Security Analyzer → Monitoring Agent → Critic → Reporter*
"""

    result = post_github_comment.invoke({"comment": report})
    print(f"  ✅ Report posted: {result}")

    if state.get("has_monitoring_issues"):
        create_github_issue.invoke({
            "title": "🚨 Orchestrator Alert: Performance Issues Detected",
            "body": f"## Monitoring Alert\n\n{state.get('monitoring_analysis', '')}\n\n---\n*Created by AI Orchestrator*"
        })

    return {"final_report": report}


# ─── Build Graph ─────────────────────────────────────────────────
def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("data_fetcher", data_fetcher_node)
    graph.add_node("failure_analyzer", failure_analyzer_node)
    graph.add_node("security_analyzer", security_analyzer_node)
    graph.add_node("monitoring_agent", monitoring_agent_node)
    graph.add_node("critic", critic_node)
    graph.add_node("reporter", reporter_node)
    graph.set_entry_point("data_fetcher")
    graph.add_edge("data_fetcher", "failure_analyzer")
    graph.add_edge("failure_analyzer", "security_analyzer")
    graph.add_edge("security_analyzer", "monitoring_agent")
    graph.add_edge("monitoring_agent", "critic")
    graph.add_edge("critic", "reporter")
    graph.add_edge("reporter", END)
    return graph.compile()


# ─── Main ────────────────────────────────────────────────────────
def main():
    print("🚀 AI Orchestrator starting...")
    print(f"Repository: {os.environ.get('GITHUB_REPOSITORY')}")
    print(f"SHA: {os.environ.get('GITHUB_SHA')}")

    initial_state = {
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "commit_sha": os.environ.get("GITHUB_SHA", ""),
        "pipeline_logs": "",
        "bandit_results": "",
        "trivy_results": "",
        "pipaudit_results": "",
        "zap_results": "",
        "prometheus_metrics": "",
        "failure_analysis": "",
        "security_analysis": "",
        "monitoring_analysis": "",
        "critic_feedback": "",
        "final_report": "",
        "has_failure": False,
        "has_security_issues": False,
        "has_monitoring_issues": False,
        "errors": []
    }

    app = build_graph()
    print("🔄 Running LangGraph pipeline...\n")
    final_state = app.invoke(initial_state)

    print("\n✅ Orchestrator complete!")
    print(f"  - Failure detected: {final_state.get('has_failure')}")
    print(f"  - Security issues: {final_state.get('has_security_issues')}")
    print(f"  - Monitoring issues: {final_state.get('has_monitoring_issues')}")


if __name__ == "__main__":
    main()
