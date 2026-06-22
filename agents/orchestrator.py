import os
import json
from typing import TypedDict
import requests
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agents.tools import query_prometheus, post_github_comment, create_github_issue

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")


class AgentState(TypedDict):
    commit_sha: str
    bandit_results: str
    trivy_results: str
    pipaudit_results: str
    zap_results: str
    checkov_results: str
    security_analysis: str
    monitoring_analysis: str
    final_report: str
    has_security_issues: bool
    has_monitoring_issues: bool


def get_llm():
    return ChatGroq(
        model="llama-3.3-70b-versatile",
        temperature=0.3,
        api_key=os.environ.get("GROQ_API_KEY")
    )


def read_report(filepath: str) -> str:
    alternatives = [filepath, os.path.basename(filepath), f"security-reports/{os.path.basename(filepath)}"]
    for alt in alternatives:
        if os.path.exists(alt):
            filepath = alt
            break
    else:
        return f"Report not found: {os.path.basename(filepath)}"

    try:
        with open(filepath) as f:
            if not filepath.endswith('.json') and not filepath.endswith('.sarif'):
                return f.read()[:2000]
            data = json.load(f)

            # Bandit
            if "results" in data:
                results = data["results"]
                if not results:
                    return "No issues found"
                high = [r for r in results if r.get('issue_severity') == 'HIGH']
                medium = [r for r in results if r.get('issue_severity') == 'MEDIUM']
                low = [r for r in results if r.get('issue_severity') == 'LOW']
                summary = "Total: {} issues (High: {}, Medium: {}, Low: {})\n\n".format(len(results), len(high), len(medium), len(low))
                for r in (high + medium)[:10]:
                    summary += "- [{}] {} in {}:{}\n".format(
                        r.get('issue_severity'), r.get('issue_text'),
                        os.path.basename(r.get('filename', '')), r.get('line_number')
                    )
                return summary

            # Trivy
            if "Results" in data:
                all_vulns = []
                for result in data["Results"]:
                    for v in result.get("Vulnerabilities", []):
                        all_vulns.append(v)
                if not all_vulns:
                    return "No vulnerabilities found"
                critical = [v for v in all_vulns if v.get('Severity') == 'CRITICAL']
                high = [v for v in all_vulns if v.get('Severity') == 'HIGH']
                medium = [v for v in all_vulns if v.get('Severity') == 'MEDIUM']
                summary = "Total: {} vulnerabilities (Critical: {}, High: {}, Medium: {})\n\n".format(
                    len(all_vulns), len(critical), len(high), len(medium))
                for v in (critical + high)[:10]:
                    fix = " -> fix: upgrade to {}".format(v.get('FixedVersion')) if v.get('FixedVersion') else ""
                    summary += "- [{}] {} in {} {}{}.\n".format(
                        v.get('Severity'), v.get('VulnerabilityID'),
                        v.get('PkgName'), v.get('InstalledVersion'), fix)
                return summary

            # SARIF (Checkov)
            if "runs" in data:
                runs = data.get("runs", [])
                results = []
                for run in runs:
                    for result in run.get("results", []):
                        level = result.get("level", "warning")
                        msg = result.get("message", {}).get("text", "")[:100]
                        rule_id = result.get("ruleId", "")
                        results.append("- [{}] {}: {}".format(level.upper(), rule_id, msg))
                if not results:
                    return "No IaC issues found by Checkov"
                return "{} IaC issues found:\n".format(len(results)) + "\n".join(results[:15])

            # pip-audit
            if "dependencies" in data:
                vulns = []
                for dep in data["dependencies"]:
                    for v in dep.get("vulns", []):
                        vulns.append("- [{}] in {} {}: {}".format(
                            v.get('id'), dep.get('name'), dep.get('version'),
                            v.get('description', '')[:100]))
                if not vulns:
                    return "No vulnerable dependencies found"
                return "{} vulnerable dependencies:\n".format(len(vulns)) + "\n".join(vulns[:10])

            return json.dumps(data, indent=2)[:2000]

    except Exception as e:
        return "Could not read report: {}".format(e)


def get_prometheus_metrics() -> dict:
    def query(q):
        try:
            url = "{}/api/v1/query".format(PROMETHEUS_URL)
            r = requests.get(url, params={"query": q}, timeout=10)
            if r.status_code == 200:
                results = r.json().get("data", {}).get("result", [])
                if results:
                    return float(results[0]["value"][1])
        except:
            pass
        return None

    return {
        "error_rate": query('sum(rate(http_requests_total{status=~"4..|5.."}[5m])) / sum(rate(http_requests_total[5m]))'),
        "response_time": query('sum(rate(http_request_duration_seconds_sum[5m])) / sum(rate(http_request_duration_seconds_count[5m]))'),
        "request_rate": query('sum(rate(http_requests_total[5m])) * 60'),
        "total_requests": query('sum(http_requests_total)'),
    }


def data_fetcher_node(state: AgentState) -> AgentState:
    print("Node 1: Fetching security reports and metrics...")

    bandit = read_report("security-reports/bandit-report.json")
    trivy = read_report("security-reports/trivy-report.json")
    pipaudit = read_report("security-reports/pip-audit-report.json")
    zap = read_report("zap-report/zap-report.json")
    checkov = read_report("security-reports/checkov-report.json/results_json.json")

    print("  Bandit: {}...".format(bandit[:60]))
    print("  Trivy: {}...".format(trivy[:60]))
    print("  pip-audit: {}...".format(pipaudit[:60]))
    print("  Checkov: {}...".format(checkov[:60]))

    return {
        "bandit_results": bandit,
        "trivy_results": trivy,
        "pipaudit_results": pipaudit,
        "zap_results": zap,
        "checkov_results": checkov,
    }


def security_analyzer_node(state: AgentState) -> AgentState:
    print("Node 2: Analyzing security scan results...")

    llm = get_llm()
    messages = [
        SystemMessage(content="""You are a DevSecOps security expert analyzing real security scan results.
Be specific about actual findings. Reference exact CVEs, file names, and line numbers from the data provided.
Do NOT give generic advice if there are no real findings."""),
        HumanMessage(content="""Analyze these security scan results:

## Bandit (Python SAST):
{}

## Trivy (Container vulnerabilities):
{}

## pip-audit (Dependency vulnerabilities):
{}

## OWASP ZAP (Dynamic scan):
{}

## Checkov (IaC Security):
{}

Provide:
### Executive Summary
- Total issues found across all tools with severity breakdown
- Overall security posture: Secure / Needs Attention / Critical

### Critical and High Issues
List each real finding with:
- Tool that found it
- Exact CVE or rule ID
- Affected component and version
- Specific fix

### Key Recommendations
Top 3 specific actions based on actual findings only.
If a tool found no issues, state that clearly.""".format(
            state.get('bandit_results'),
            state.get('trivy_results'),
            state.get('pipaudit_results'),
            state.get('zap_results', '')[:300],
            state.get('checkov_results', '')[:500]
        ))
    ]

    response = llm.invoke(messages)
    has_security_issues = any(k in response.content.lower() for k in ["critical", "high", "cve-"])

    print("  Security analysis complete")
    return {
        "security_analysis": response.content,
        "has_security_issues": has_security_issues
    }


def monitoring_agent_node(state: AgentState) -> AgentState:
    print("Node 3: Analyzing monitoring metrics...")

    metrics = get_prometheus_metrics()
    error_rate = metrics.get('error_rate')
    response_time = metrics.get('response_time')
    request_rate = metrics.get('request_rate')
    total_requests = metrics.get('total_requests')

    anomalies = []
    if error_rate is not None and error_rate > 0.05:
        anomalies.append("High error rate: {:.2f}% (threshold: 5%)".format(error_rate * 100))
    if response_time is not None and response_time > 2.0:
        anomalies.append("Slow response time: {:.3f}s (threshold: 2s)".format(response_time))

    grafana_url = PROMETHEUS_URL.replace("9090", "3000")

    er_val = "{:.2f}%".format(error_rate * 100) if error_rate is not None else "N/A"
    rt_val = "{:.3f}s".format(response_time) if response_time is not None else "N/A"
    rr_val = "{:.2f} req/min".format(request_rate) if request_rate is not None else "N/A"
    tr_val = str(int(total_requests)) if total_requests is not None else "N/A"

    er_status = "HIGH" if error_rate and error_rate > 0.05 else "OK"
    rt_status = "HIGH" if response_time and response_time > 2.0 else "OK"

    metrics_table = "| Metric | Value | Threshold | Status |\n"
    metrics_table += "|--------|-------|-----------|--------|\n"
    metrics_table += "| Error Rate | {} | 5% | {} |\n".format(er_val, er_status)
    metrics_table += "| Response Time | {} | 2s | {} |\n".format(rt_val, rt_status)
    metrics_table += "| Request Rate | {} | - | - |\n".format(rr_val)
    metrics_table += "| Total Requests | {} | - | - |\n".format(tr_val)
    metrics_table += "\n> Prometheus: {} | Grafana: {}".format(PROMETHEUS_URL, grafana_url)

    if anomalies:
        llm = get_llm()
        messages = [
            SystemMessage(content="You are a DevOps monitoring expert."),
            HumanMessage(content="Anomalies detected:\n{}\n\nProvide root cause, immediate actions, and prevention. Be concise.".format("\n".join(anomalies)))
        ]
        ai_analysis = llm.invoke(messages).content
        analysis = "Anomalies detected:\n{}\n\n{}\n\nAI Analysis:\n{}".format(
            "\n".join(anomalies), metrics_table, ai_analysis)
        has_monitoring_issues = True
    else:
        analysis = "Application is healthy - all metrics within normal thresholds.\n\n{}".format(metrics_table)
        has_monitoring_issues = False

    print("  Monitoring complete - anomalies: {}".format(len(anomalies)))
    return {
        "monitoring_analysis": analysis,
        "has_monitoring_issues": has_monitoring_issues
    }


def reporter_node(state: AgentState) -> AgentState:
    print("Node 4: Generating and posting final report...")

    sha = state.get("commit_sha", "")[:7]
    security_status = "Issues Found" if state.get("has_security_issues") else "No Critical Issues"
    monitoring_status = "Anomalies Detected" if state.get("has_monitoring_issues") else "Healthy"

    report = "## AI Orchestrator Report - Commit {}\n\n".format(sha)
    report += "| Component | Status |\n|-----------|--------|\n"
    report += "| Security | {} |\n".format(security_status)
    report += "| Monitoring | {} |\n\n".format(monitoring_status)
    report += "---\n\n## Security Analysis\n{}\n\n".format(state.get('security_analysis', 'Not available'))
    report += "---\n\n## Monitoring\n{}\n\n".format(state.get('monitoring_analysis', 'Not available'))
    report += "---\n*Generated by LangGraph Orchestrator - Nodes: Data Fetcher -> Security Analyzer -> Monitoring Agent -> Reporter*\n"
    report += "*Powered by Groq (Llama-3.3-70b)*"

    result = post_github_comment.invoke({"comment": report})
    print("  Report posted: {}".format(result))

    if state.get("has_monitoring_issues"):
        create_github_issue.invoke({
            "title": "Monitoring Alert - Commit {}".format(sha),
            "body": "## Monitoring Alert\n\n{}\n\n---\n*Created by AI Orchestrator*".format(
                state.get('monitoring_analysis', ''))
        })
        print("  GitHub issue created for monitoring alert")

    return {"final_report": report}


def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("data_fetcher", data_fetcher_node)
    graph.add_node("security_analyzer", security_analyzer_node)
    graph.add_node("monitoring_agent", monitoring_agent_node)
    graph.add_node("reporter", reporter_node)
    graph.set_entry_point("data_fetcher")
    graph.add_edge("data_fetcher", "security_analyzer")
    graph.add_edge("security_analyzer", "monitoring_agent")
    graph.add_edge("monitoring_agent", "reporter")
    graph.add_edge("reporter", END)
    return graph.compile()


def main():
    print("AI Orchestrator starting...")
    print("Repository: {}".format(os.environ.get('GITHUB_REPOSITORY')))
    print("SHA: {}".format(os.environ.get('GITHUB_SHA')))
    print("Prometheus: {}".format(PROMETHEUS_URL))
    print()

    initial_state = {
        "commit_sha": os.environ.get("GITHUB_SHA", ""),
        "bandit_results": "",
        "trivy_results": "",
        "pipaudit_results": "",
        "zap_results": "",
        "checkov_results": "",
        "security_analysis": "",
        "monitoring_analysis": "",
        "final_report": "",
        "has_security_issues": False,
        "has_monitoring_issues": False,
    }

    app = build_graph()
    print("Running LangGraph pipeline...\n")
    final_state = app.invoke(initial_state)

    print("\nOrchestrator complete!")
    print("  - Security issues: {}".format(final_state.get('has_security_issues')))
    print("  - Monitoring issues: {}".format(final_state.get('has_monitoring_issues')))


if __name__ == "__main__":
    main()
