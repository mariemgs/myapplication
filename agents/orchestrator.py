import os
import json
from typing import TypedDict, Annotated
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from agents.tools import (
    fetch_pipeline_logs,
    query_prometheus,
    post_github_comment,
    create_github_issue,
    read_security_report
)

# ─── Shared State ───────────────────────────────────────────────
class AgentState(TypedDict):
    # Inputs
    run_id: str
    commit_sha: str
    
    # Data collected
    pipeline_logs: str
    bandit_results: str
    trivy_results: str
    pipaudit_results: str
    zap_results: str
    prometheus_metrics: str
    
    # Agent outputs
    failure_analysis: str
    security_analysis: str
    monitoring_analysis: str
    critic_feedback: str
    final_report: str
    
    # Control
    has_failure: bool
    has_security_issues: bool
    has_monitoring_issues: bool
    errors: list


# ─── LLM Setup ──────────────────────────────────────────────────
def get_llm():
    return ChatGroq(
        model="llama-3.3-70b-versatile",
        temperature=0.3,
        api_key=os.environ.get("GROQ_API_KEY")
    )


# ─── Node 1: Data Fetcher ────────────────────────────────────────
def data_fetcher_node(state: AgentState) -> AgentState:
    print("📥 Node 1: Fetching all data...")
    updates = {}
    
    # Fetch pipeline logs
    run_id = state.get("run_id", "")
    if run_id:
        logs = fetch_pipeline_logs.invoke({"run_id": run_id})
        updates["pipeline_logs"] = logs
        updates["has_failure"] = "No failed jobs" not in logs
    else:
        updates["pipeline_logs"] = "No run ID provided"
        updates["has_failure"] = False
    
    # Read security reports
    updates["bandit_results"] = read_security_report.invoke({"report_type": "bandit"})
    updates["trivy_results"] = read_security_report.invoke({"report_type": "trivy"})
    updates["pipaudit_results"] = read_security_report.invoke({"report_type": "pipaudit"})
    updates["zap_results"] = read_security_report.invoke({"report_type": "zap"})
    
    # Query Prometheus metrics
    error_rate = query_prometheus.invoke({"metric": 'sum(rate(http_requests_total{status=~"4..|5.."}[5m])) / sum(rate(http_requests_total[5m]))'})
    response_time = query_prometheus.invoke({"metric": 'sum(rate(http_request_duration_seconds_sum[5m])) / sum(rate(http_request_duration_seconds_count[5m]))'})
    updates["prometheus_metrics"] = f"Error Rate: {error_rate}\nResponse Time: {response_time}"
    
    print(f"  ✅ Pipeline logs: {len(updates['pipeline_logs'])} chars")
    print(f"  ✅ Bandit: {updates['bandit_results'][:50]}...")
    print(f"  ✅ Trivy: {updates['trivy_results'][:50]}...")
    print(f"  ✅ Prometheus: {updates['prometheus_metrics'][:100]}...")
    
    return updates


# ─── Node 2: Failure Analyzer ────────────────────────────────────
def failure_analyzer_node(state: AgentState) -> AgentState:
    print("🔍 Node 2: Analyzing pipeline failures...")
    
    llm = get_llm()
    logs = state.get("pipeline_logs", "No logs available")
    
    messages = [
        SystemMessage(content="You are a DevOps expert. Be concise and technical."),
        HumanMessage(content=f"""Analyze these CI/CD pipeline logs:

{logs[:5000]}

Provide:
1. What failed
2. Root cause
3. How to fix it (specific steps)

Format in markdown. Be concise.""")
    ]
    
    response = llm.invoke(messages)
    analysis = response.content
    
    print(f"  ✅ Failure analysis complete ({len(analysis)} chars)")
    return {"failure_analysis": analysis}


# ─── Node 3: Security Analyzer ───────────────────────────────────
def security_analyzer_node(state: AgentState) -> AgentState:
    print("🔒 Node 3: Analyzing security scan results...")
    
    llm = get_llm()
    
    messages = [
        SystemMessage(content="You are a DevSecOps security expert. Be concise and actionable."),
        HumanMessage(content=f"""Analyze these security scan results:

## Bandit (SAST):
{state.get('bandit_results', 'Not available')[:2000]}

## Trivy (Container):
{state.get('trivy_results', 'Not available')[:2000]}

## pip-audit (Dependencies):
{state.get('pipaudit_results', 'Not available')[:1000]}

## OWASP ZAP (DAST):
{state.get('zap_results', 'Not available')[:500]}

## Pipeline failure context:
{state.get('failure_analysis', 'No failure')[:500]}

Provide unified security report:
1. Executive Summary (Critical/High/Medium/Low)
2. Critical Issues (fix immediately)
3. High Priority Issues
4. Recommendations (top 3)

Format in markdown.""")
    ]
    
    response = llm.invoke(messages)
    analysis = response.content
    
    has_security_issues = any(keyword in analysis.lower() 
                               for keyword in ["critical", "high", "vulnerability", "cve"])
    
    print(f"  ✅ Security analysis complete ({len(analysis)} chars)")
    return {
        "security_analysis": analysis,
        "has_security_issues": has_security_issues
    }


# ─── Node 4: Monitoring Agent ─────────────────────────────────────
def monitoring_agent_node(state: AgentState) -> AgentState:
    print("📊 Node 4: Monitoring analysis...")
    
    # Monitoring agent runs separately on self-hosted runner
    # with direct Prometheus access every 30 minutes
    analysis = """## 📊 Monitoring Status

> ℹ️ Real-time monitoring is handled by the dedicated AI Monitoring Agent 
> running on the self-hosted runner with direct Prometheus access.
> 
> Check the **Issues tab** for any active monitoring alerts.
> Prometheus dashboard: http://192.168.29.131:9090
> Grafana dashboard: http://192.168.29.131:3000"""

    return {
        "monitoring_analysis": analysis,
        "has_monitoring_issues": False
    }
    
# ─── Node 5: Critic Agent ─────────────────────────────────────────
def critic_node(state: AgentState) -> AgentState:
    print("🧐 Node 5: Critic validating all analyses...")
    
    llm = get_llm()
    
    messages = [
        SystemMessage(content="You are a senior DevSecOps reviewer. Validate and improve the analyses below."),
        HumanMessage(content=f"""Review these analyses and provide a brief validation:

## Failure Analysis:
{state.get('failure_analysis', 'None')[:1000]}

## Security Analysis:
{state.get('security_analysis', 'None')[:1000]}

## Monitoring Analysis:
{state.get('monitoring_analysis', 'None')[:500]}

Provide:
1. Are the analyses accurate and complete?
2. Any missing critical points?
3. Overall assessment (1-2 sentences)

Be brief and constructive.""")
    ]
    
    response = llm.invoke(messages)
    feedback = response.content
    
    print(f"  ✅ Critic feedback complete ({len(feedback)} chars)")
    return {"critic_feedback": feedback}


# ─── Node 6: Reporter ─────────────────────────────────────────────
def reporter_node(state: AgentState) -> AgentState:
    print("📝 Node 6: Generating and posting final report...")
    
    report = f"""## 🤖 AI Orchestrator — Unified DevSecOps Report

---

## 🔴 Pipeline Failure Analysis
{state.get('failure_analysis', 'No failures detected')}

---

## 🔒 Security Analysis
{state.get('security_analysis', 'No security issues detected')}

---

## 📊 Monitoring Analysis
{state.get('monitoring_analysis', 'Metrics not available')}

---

## 🧐 Critic Review
{state.get('critic_feedback', 'No review available')}

---
*Generated by LangGraph Multi-Agent Orchestrator • Powered by Groq (Llama3)*
*Agents: Failure Analyzer → Security Analyzer → Monitoring Agent → Critic → Reporter*
"""
    
    # Post as GitHub comment
    result = post_github_comment.invoke({"comment": report})
    print(f"  ✅ Report posted: {result}")
    
    # Create GitHub issue if monitoring issues detected
    if state.get("has_monitoring_issues"):
        issue_result = create_github_issue.invoke({
            "title": "🚨 Orchestrator Alert: Performance Issues Detected",
            "body": f"## Monitoring Alert\n\n{state.get('monitoring_analysis', '')}\n\n---\n*Created by AI Orchestrator*"
        })
        print(f"  ✅ Issue created: {issue_result}")
    
    return {"final_report": report}


# ─── Build the Graph ──────────────────────────────────────────────
def build_graph():
    graph = StateGraph(AgentState)
    
    # Add nodes
    graph.add_node("data_fetcher", data_fetcher_node)
    graph.add_node("failure_analyzer", failure_analyzer_node)
    graph.add_node("security_analyzer", security_analyzer_node)
    graph.add_node("monitoring_agent", monitoring_agent_node)
    graph.add_node("critic", critic_node)
    graph.add_node("reporter", reporter_node)
    
    # Define flow
    graph.set_entry_point("data_fetcher")
    graph.add_edge("data_fetcher", "failure_analyzer")
    graph.add_edge("failure_analyzer", "security_analyzer")
    graph.add_edge("security_analyzer", "monitoring_agent")
    graph.add_edge("monitoring_agent", "critic")
    graph.add_edge("critic", "reporter")
    graph.add_edge("reporter", END)
    
    return graph.compile()


# ─── Main ─────────────────────────────────────────────────────────
def main():
    print("🚀 AI Orchestrator starting...")
    print(f"Repository: {os.environ.get('GITHUB_REPOSITORY')}")
    print(f"Run ID: {os.environ.get('GITHUB_RUN_ID')}")
    print("")
    
    # Initial state
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
    
    # Run the graph
    app = build_graph()
    
    print("🔄 Running LangGraph pipeline...\n")
    final_state = app.invoke(initial_state)
    
    print("\n✅ Orchestrator complete!")
    print(f"  - Failure detected: {final_state.get('has_failure')}")
    print(f"  - Security issues: {final_state.get('has_security_issues')}")
    print(f"  - Monitoring issues: {final_state.get('has_monitoring_issues')}")
    print(f"  - Report length: {len(final_state.get('final_report', ''))} chars")


if __name__ == "__main__":
    main()
