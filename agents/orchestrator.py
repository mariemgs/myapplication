import os
import json
from typing import TypedDict
import requests
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agents.tools import query_prometheus, post_github_comment, create_github_issue

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")


# ─── Shared State ───────────────────────────────────────────────
class AgentState(TypedDict):
    commit_sha: str
    # Security data
    bandit_results: str
    trivy_results: str
    pipaudit_results: str
    zap_results: str
    # Agent outputs
    security_analysis: str
    monitoring_analysis: str
    final_report: str
    # Control flags
    has_security_issues: bool
    has_monitoring_issues: bool


def get_llm():
    return ChatGroq(
        model="llama-3.3-70b-versatile",
        temperature=0.3,
        api_key=os.environ.get("GROQ_API_KEY")
    )


# ─── Helper: parse security reports ─────────────────────────────
def read_report(filepath: str) -> str:
    """Read and parse a security report file into readable text"""
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
        return f"⚠️ Report not found: {os.path.basename(filepath)}"

    try:
        with open(filepath) as f:
            if not filepath.endswith('.json'):
                return f.read()[:2000]
            
            data = json.load(f)

            # Bandit format
            if "results" in data:
                results = data["results"]
                if not results:
                    return "✅ No issues found"
                
                # Group by severity
                high = [r for r in results if r.get('issue_severity') == 'HIGH']
                medium = [r for r in results if r.get('issue_severity') == 'MEDIUM']
                low = [r for r in results if r.get('issue_severity') == 'LOW']
                
                summary = f"**Total: {len(results)} issues** (High: {len(high)}, Medium: {len(medium)}, Low: {len(low)})\n\n"
                
                for r in (high + medium)[:10]:
                    summary += f"- **[{r.get('issue_severity')}]** {r.get('issue_text')} "
                    summary += f"in `{os.path.basename(r.get('filename', ''))}:{r.get('line_number')}`\n"
                    summary += f"  - Test ID: {r.get('test_id')} | Confidence: {r.get('issue_confidence')}\n"
                
                return summary

            # Trivy format
            if "Results" in data:
                all_vulns = []
                for result in data["Results"]:
                    for v in result.get("Vulnerabilities", []):
                        all_vulns.append(v)
                
                if not all_vulns:
                    return "✅ No vulnerabilities found"
                
                critical = [v for v in all_vulns if v.get('Severity') == 'CRITICAL']
                high = [v for v in all_vulns if v.get('Severity') == 'HIGH']
                medium = [v for v in all_vulns if v.get('Severity') == 'MEDIUM']
                
                summary = f"**Total: {len(all_vulns)} vulnerabilities** "
                summary += f"(Critical: {len(critical)}, High: {len(high)}, Medium: {len(medium)})\n\n"
                
                for v in (critical + high)[:10]:
                    summary += f"- **[{v.get('Severity')}]** {v.get('VulnerabilityID')} "
                    summary += f"in `{v.get('PkgName')}` {v.get('InstalledVersion')}"
                    if v.get('FixedVersion'):
                        summary += f" → fix: upgrade to {v.get('FixedVersion')}"
                    summary += "\n"
                
                return summary

            # pip-audit format
            if "dependencies" in data:
                vulns = []
                for dep in data["dependencies"]:
                    for v in dep.get("vulns", []):
                        vulns.append(f"- **[{v.get('id')}]** in `{dep.get('name')}` {dep.get('version')}: {v.get('description', '')[:100]}")
                
                if not vulns:
                    return "✅ No vulnerable dependencies found"
                return f"**{len(vulns)} vulnerable dependencies:**\n" + "\n".join(vulns[:10])

            return json.dumps(data, indent=2)[:2000]

    except Exception as e:
        return f"⚠️ Could not read report: {e}"


# ─── Helper: get Prometheus metrics ─────────────────────────────
def get_prometheus_metrics() -> dict:
    """Query Prometheus for current metrics"""
    def query(q):
        try:
            url = f"{PROMETHEUS_URL}/api/v1/query"
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


# ─── Node 1: Data Fetcher ────────────────────────────────────────
def data_fetcher_node(state: AgentState) -> AgentState:
    print("📥 Node 1: Fetching security reports and metrics...")

    bandit = read_report("security-reports/bandit-report.json")
    trivy = read_report("security-reports/trivy-report.json")
    pipaudit = read_report("security-reports/pip-audit-report.json")
    zap = read_report("zap-report/report_html.html")

    print(f"  ✅ Bandit: {bandit[:60]}...")
    print(f"  ✅ Trivy: {trivy[:60]}...")
    print(f"  ✅ pip-audit: {pipaudit[:60]}...")

    return {
        "bandit_results": bandit,
        "trivy_results": trivy,
        "pipaudit_results": pipaudit,
        "zap_results": zap,
    }


# ─── Node 2: Security Analyzer ───────────────────────────────────
def security_analyzer_node(state: AgentState) -> AgentState:
    print("🔒 Node 2: Analyzing security scan results...")

    llm = get_llm()
    messages = [
        SystemMessage(content="""You are a DevSecOps security expert analyzing real security scan results.
Be specific about actual findings. Reference exact CVEs, file names, and line numbers from the data provided.
Do NOT give generic advice if there are no real findings."""),
        HumanMessage(content=f"""Analyze these security scan results:

## 🔍 Bandit (Python SAST):
{state.get('bandit_results')}

## 🐳 Trivy (Container vulnerabilities):
{state.get('trivy_results')}

## 📦 pip-audit (Dependency vulnerabilities):
{state.get('pipaudit_results')}

## 🌐 OWASP ZAP (Dynamic scan):
{state.get('zap_results')[:300] if state.get('zap_results') else 'Not available'}

Provide:
### Executive Summary
- Total issues found across all tools with severity breakdown
- Overall security posture: Secure / Needs Attention / Critical

### Critical & High Issues
List each real finding with:
- Tool that found it
- Exact CVE or rule ID
- Affected component and version
- Specific fix with version to upgrade to

### Key Recommendations
Top 3 specific actions based on actual findings only.

If a tool found no issues, state that clearly. Do not invent findings.""")
    ]

    response = llm.invoke(messages)
    has_security_issues = any(k in response.content.lower() for k in ["critical", "high", "cve-"])

    print(f"  ✅ Security analysis complete")
    return {
        "security_analysis": response.content,
        "has_security_issues": has_security_issues
    }


# ─── Node 3: Monitoring Agent ─────────────────────────────────────
def monitoring_agent_node(state: AgentState) -> AgentState:
    print("📊 Node 3: Analyzing monitoring metrics...")

    metrics = get_prometheus_metrics()
    error_rate = metrics.get('error_rate')
    response_time = metrics.get('response_time')
    request_rate = metrics.get('request_rate')
    total_requests = metrics.get('total_requests')

    # Detect anomalies
    anomalies = []
    if error_rate is not None and error_rate > 0.05:
        anomalies.append(f"🔴 High error rate: {error_rate*100:.2f}% (threshold: 5%)")
    if response_time is not None and response_time > 2.0:
        anomalies.append(f"🟠 Slow response time: {response_time:.3f}s (threshold: 2s)")

    prometheus_url = PROMETHEUS_URL
    grafana_url = prometheus_url.replace("9090", "3000")

    metrics_table = f"""| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Error Rate | {f"{error_rate*100:.2f}%" if error_rate is not None else "N/A"} | 5% | {"🔴 HIGH" if error_rate and error_rate > 0.05 else "✅ OK"} |
| Response Time | {f"{response_time:.3f}s" if response_time is not None else "N/A"} | 2s | {"🔴 HIGH" if response_time and response_time > 2.0 else "✅ OK"} |
| Request Rate | {f"{request_rate:.2f} req/min" if request_rate is not None else "N/A"} | - | ℹ️ |
| Total Requests | {int(total_requests) if total_requests is not None else "N/A"} | - | ℹ️ |

> 📡 [Prometheus]({prometheus_url}) | 📊 [Grafana]({grafana_url})"""

    if anomalies:
        llm = get_llm()
        messages = [
            SystemMessage(content="You are a DevOps monitoring expert."),
            HumanMessage(content=f"""These anomalies were detected:
{chr(10).join(anomalies)}

Metrics:
- Error Rate: {error_rate}
- Response Time: {response_time}s
- Request Rate: {request_rate} req/min

Provide:
1. **Root Cause** - likely causes
2. **Immediate Actions** - what to do right now
3. **Prevention** - how to avoid this

Be concise and specific.""")
        ]
        ai_analysis = llm.invoke(messages).content
        analysis = f"⚠️ **Anomalies detected:**\n" + "\n".join(anomalies) + f"\n\n{metrics_table}\n\n## 🤖 AI Analysis\n{ai_analysis}"
        has_monitoring_issues = True
    else:
        analysis = f"✅ **Application is healthy** — all metrics within normal thresholds.\n\n{metrics_table}"
        has_monitoring_issues = False

    print(f"  ✅ Monitoring complete — anomalies: {len(anomalies)}")
    return {
        "monitoring_analysis": analysis,
        "has_monitoring_issues": has_monitoring_issues
    }


# ─── Node 4: Reporter ────────────────────────────────────────────
def reporter_node(state: AgentState) -> AgentState:
    print("📝 Node 4: Generating and posting final report...")

    sha = state.get("commit_sha", "")[:7]
    security_status = "🔴 Issues Found" if state.get("has_security_issues") else "✅ No Critical Issues"
    monitoring_status = "⚠️ Anomalies Detected" if state.get("has_monitoring_issues") else "✅ Healthy"

    report = f"""## 🤖 AI Orchestrator Report — Commit `{sha}`

| Component | Status |
|-----------|--------|
| 🔒 Security | {security_status} |
| 📊 Monitoring | {monitoring_status} |

---

## 🔒 Security Analysis
{state.get('security_analysis', 'Not available')}

---

## 📊 Monitoring
{state.get('monitoring_analysis', 'Not available')}

---
*🤖 Generated by LangGraph Orchestrator • Nodes: Data Fetcher → Security Analyzer → Monitoring Agent → Reporter*
*Powered by Groq (Llama-3.3-70b)*"""

    result = post_github_comment.invoke({"comment": report})
    print(f"  ✅ Report posted: {result}")

    if state.get("has_monitoring_issues"):
        create_github_issue.invoke({
            "title": f"🚨 Monitoring Alert — Commit {sha}",
            "body": f"## Monitoring Alert\n\n{state.get('monitoring_analysis', '')}\n\n---\n*Created by AI Orchestrator*"
        })
        print("  ✅ GitHub issue created for monitoring alert")

    return {"final_report": report}


# ─── Build Graph ─────────────────────────────────────────────────
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


# ─── Main ────────────────────────────────────────────────────────
def main():
    print("🚀 AI Orchestrator starting...")
    print(f"Repository: {os.environ.get('GITHUB_REPOSITORY')}")
    print(f"SHA: {os.environ.get('GITHUB_SHA')}")
    print(f"Prometheus: {PROMETHEUS_URL}")
    print()

    initial_state = {
        "commit_sha": os.environ.get("GITHUB_SHA", ""),
        "bandit_results": "",
        "trivy_results": "",
        "pipaudit_results": "",
        "zap_results": "",
        "security_analysis": "",
        "monitoring_analysis": "",
        "final_report": "",
        "has_security_issues": False,
        "has_monitoring_issues": False,
    }

    app = build_graph()
    print("🔄 Running LangGraph pipeline...\n")
    final_state = app.invoke(initial_state)

    print("\n✅ Orchestrator complete!")
    print(f"  - Security issues: {final_state.get('has_security_issues')}")
    print(f"  - Monitoring issues: {final_state.get('has_monitoring_issues')}")


if __name__ == "__main__":
    main()
