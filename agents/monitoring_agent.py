import os
import requests
from datetime import datetime
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage

# Configuration
GITHUB_TOKEN = os.environ.get("GH_PAT")
REPO = os.environ.get("GITHUB_REPOSITORY")
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://192.168.29.131:9090")

# Thresholds
ERROR_RATE_THRESHOLD = 0.05
RESPONSE_TIME_THRESHOLD = 2.0

# LangChain LLM
llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0.3,
    api_key=os.environ.get("GROQ_API_KEY")
)


def query_prometheus(query):
    """Query Prometheus API"""
    try:
        url = f"{PROMETHEUS_URL}/api/v1/query"
        response = requests.get(url, params={"query": query}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            results = data.get("data", {}).get("result", [])
            if results:
                return float(results[0]["value"][1])
        return None
    except Exception as e:
        print(f"⚠️ Prometheus query failed: {e}")
        return None


def collect_metrics():
    """Collect all relevant metrics from Prometheus"""
    print("📊 Collecting metrics from Prometheus...")
    metrics = {}
    metrics["error_rate"] = query_prometheus(
        'sum(rate(http_requests_total{status=~"4..|5.."}[5m])) / sum(rate(http_requests_total[5m]))'
    )
    metrics["response_time"] = query_prometheus(
        'sum(rate(http_request_duration_seconds_sum[5m])) / sum(rate(http_request_duration_seconds_count[5m]))'
    )
    metrics["request_rate"] = query_prometheus(
        'sum(rate(http_requests_total[5m])) * 60'
    )
    metrics["total_requests"] = query_prometheus('sum(http_requests_total)')

    for key, value in metrics.items():
        print(f"  {key}: {value}")

    return metrics


def detect_anomalies(metrics):
    """Detect anomalies based on thresholds"""
    anomalies = []
    if metrics.get("error_rate") is not None:
        if metrics["error_rate"] > ERROR_RATE_THRESHOLD:
            anomalies.append({
                "type": "High Error Rate",
                "severity": "🔴 Critical",
                "value": f"{metrics['error_rate']*100:.2f}%",
                "threshold": f"{ERROR_RATE_THRESHOLD*100}%",
                "message": f"Error rate is {metrics['error_rate']*100:.2f}%, exceeding {ERROR_RATE_THRESHOLD*100}%"
            })
    if metrics.get("response_time") is not None:
        if metrics["response_time"] > RESPONSE_TIME_THRESHOLD:
            anomalies.append({
                "type": "Slow Response Time",
                "severity": "🟠 High",
                "value": f"{metrics['response_time']:.3f}s",
                "threshold": f"{RESPONSE_TIME_THRESHOLD}s",
                "message": f"Response time is {metrics['response_time']:.3f}s, exceeding {RESPONSE_TIME_THRESHOLD}s"
            })
    return anomalies


def analyze_with_langchain(metrics, anomalies):
    """Analyze metrics using LangChain + Groq"""
    anomaly_text = "\n".join([f"- {a['type']}: {a['message']}" for a in anomalies]) if anomalies else "No anomalies detected"

    messages = [
        SystemMessage(content="You are a DevOps monitoring expert."),
        HumanMessage(content=f"""Analyze these application metrics:

Metrics:
- Error Rate: {metrics.get('error_rate', 'N/A')}
- Response Time: {metrics.get('response_time', 'N/A')}s
- Request Rate: {metrics.get('request_rate', 'N/A')} req/min
- Total Requests: {metrics.get('total_requests', 'N/A')}

Detected Anomalies:
{anomaly_text}

Provide:
1. **Health Status** - Healthy/Degraded/Critical
2. **Root Cause Analysis** - What might be causing anomalies
3. **Immediate Actions** - What to do right now
4. **Prevention** - How to prevent this

Be concise and actionable. Use markdown.""")
    ]

    try:
        response = llm.invoke(messages)
        return response.content
    except Exception as e:
        return f"⚠️ LangChain/Groq error: {str(e)}"


def create_github_issue(metrics, anomalies, analysis):
    """Create a GitHub issue for anomalies"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity = anomalies[0]["severity"] if anomalies else "⚠️ Warning"
    title = f"🚨 Monitoring Alert: {anomalies[0]['type']} detected - {timestamp}"

    body = f"""## 🚨 Monitoring Alert

**Detected at:** {timestamp}
**Severity:** {severity}

## 📊 Current Metrics

| Metric | Value | Threshold | Status |
|--------|-------|-----------|--------|
| Error Rate | {metrics.get('error_rate', 'N/A')} | {ERROR_RATE_THRESHOLD*100}% | {'🔴' if metrics.get('error_rate', 0) > ERROR_RATE_THRESHOLD else '✅'} |
| Response Time | {metrics.get('response_time', 'N/A')}s | {RESPONSE_TIME_THRESHOLD}s | {'🔴' if metrics.get('response_time', 0) > RESPONSE_TIME_THRESHOLD else '✅'} |

## 🔍 Detected Anomalies
{chr(10).join([f"- **{a['type']}**: {a['message']}" for a in anomalies])}

## 🤖 AI Analysis
{analysis}

---
*Generated by LangChain + Groq (Llama3) • Agentic DevSecOps Monitoring Agent*
"""

    url = f"https://api.github.com/repos/{REPO}/issues"
    payload = {
        "title": title,
        "body": body,
        "labels": ["monitoring", "alert", "automated"]
    }

    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 201:
        print(f"✅ GitHub Issue created: {response.json().get('html_url')}")
    else:
        print(f"❌ Failed to create issue: {response.status_code}")


def main():
    print("🤖 AI Monitoring Agent starting...")
    print(f"Repository: {REPO}")
    print(f"Prometheus: {PROMETHEUS_URL}")

    metrics = collect_metrics()

    print("\n🔍 Detecting anomalies...")
    anomalies = detect_anomalies(metrics)

    if anomalies:
        print(f"⚠️ Found {len(anomalies)} anomaly(ies)!")
        for a in anomalies:
            print(f"  - {a['severity']} {a['type']}: {a['message']}")

        print("\n🧠 Analyzing with LangChain + Groq...")
        analysis = analyze_with_langchain(metrics, anomalies)
        print("✅ Analysis complete!")
        print(analysis)

        print("\n📝 Creating GitHub Issue...")
        create_github_issue(metrics, anomalies, analysis)
    else:
        print("✅ All metrics within normal thresholds — app is healthy!")


if __name__ == "__main__":
    main()
