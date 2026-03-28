import os
import requests
from datetime import datetime

# Configuration
GITHUB_TOKEN = os.environ.get("GH_PAT")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
REPO = os.environ.get("GITHUB_REPOSITORY")
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://192.168.29.131:9090")

# Thresholds
ERROR_RATE_THRESHOLD = 0.05      # 5% error rate
RESPONSE_TIME_THRESHOLD = 2.0    # 2 seconds
REQUEST_RATE_THRESHOLD = 100     # 100 requests/min


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

    # Error rate (4xx + 5xx)
    metrics["error_rate"] = query_prometheus(
        'sum(rate(http_requests_total{status=~"4..|5.."}[5m])) / sum(rate(http_requests_total[5m]))'
    )

    # Average response time
    metrics["response_time"] = query_prometheus(
        'sum(rate(http_request_duration_seconds_sum[5m])) / sum(rate(http_request_duration_seconds_count[5m]))'
    )

    # Total request rate
    metrics["request_rate"] = query_prometheus(
        'sum(rate(http_requests_total[5m])) * 60'
    )

    # Total requests
    metrics["total_requests"] = query_prometheus(
        'sum(http_requests_total)'
    )

    # Print collected metrics
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
                "message": f"Error rate is {metrics['error_rate']*100:.2f}%, exceeding threshold of {ERROR_RATE_THRESHOLD*100}%"
            })

    if metrics.get("response_time") is not None:
        if metrics["response_time"] > RESPONSE_TIME_THRESHOLD:
            anomalies.append({
                "type": "Slow Response Time",
                "severity": "🟠 High",
                "value": f"{metrics['response_time']:.3f}s",
                "threshold": f"{RESPONSE_TIME_THRESHOLD}s",
                "message": f"Response time is {metrics['response_time']:.3f}s, exceeding threshold of {RESPONSE_TIME_THRESHOLD}s"
            })

    return anomalies


def analyze_with_groq(metrics, anomalies):
    """Send metrics to Groq for intelligent analysis"""

    if not GROQ_API_KEY:
        return "❌ Missing GROQ_API_KEY"

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    anomaly_text = "\n".join([f"- {a['type']}: {a['message']}" for a in anomalies]) if anomalies else "No anomalies detected"

    prompt = f"""You are a DevOps monitoring expert analyzing application metrics.

Current Metrics:
- Error Rate: {metrics.get('error_rate', 'N/A')}
- Response Time: {metrics.get('response_time', 'N/A')} seconds
- Request Rate: {metrics.get('request_rate', 'N/A')} req/min
- Total Requests: {metrics.get('total_requests', 'N/A')}

Detected Anomalies:
{anomaly_text}

Provide:
1. **Health Status** - Overall app health (Healthy/Degraded/Critical)
2. **Root Cause Analysis** - What might be causing the anomalies
3. **Immediate Actions** - What to do right now
4. **Prevention** - How to prevent this in future

Be concise and actionable. Use markdown formatting.
"""

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": "You are a DevOps monitoring and performance expert."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            if "choices" in data:
                return data["choices"][0]["message"]["content"]
        return f"❌ Groq API error: {response.status_code}"
    except Exception as e:
        return f"⚠️ Exception: {str(e)}"


def create_github_issue(metrics, anomalies, analysis):
    """Create a GitHub issue for the anomaly"""
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
| Request Rate | {metrics.get('request_rate', 'N/A')} req/min | - | ℹ️ |

## 🔍 Detected Anomalies

{chr(10).join([f"- **{a['type']}**: {a['message']}" for a in anomalies])}

## 🤖 AI Analysis

{analysis}

---
*Generated by AI Monitoring Agent • Powered by Groq (Llama3)*
*Close this issue once the anomaly is resolved.*
"""

    url = f"https://api.github.com/repos/{REPO}/issues"
    payload = {
        "title": title,
        "body": body,
        "labels": ["monitoring", "alert", "automated"]
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code == 201:
        issue_url = response.json().get("html_url")
        print(f"✅ GitHub Issue created: {issue_url}")
    else:
        print(f"❌ Failed to create issue: {response.status_code} {response.text}")


def main():
    print("🤖 AI Monitoring Agent starting...")
    print(f"Repository: {REPO}")
    print(f"Prometheus: {PROMETHEUS_URL}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("")

    # Step 1: Collect metrics
    metrics = collect_metrics()

    # Step 2: Detect anomalies
    print("\n🔍 Detecting anomalies...")
    anomalies = detect_anomalies(metrics)

    if anomalies:
        print(f"⚠️ Found {len(anomalies)} anomaly(ies)!")
        for a in anomalies:
            print(f"  - {a['severity']} {a['type']}: {a['message']}")

        # Step 3: Analyze with Groq
        print("\n🧠 Analyzing with Groq AI...")
        analysis = analyze_with_groq(metrics, anomalies)
        print("✅ Analysis complete!")
        print(analysis)

        # Step 4: Create GitHub Issue
        print("\n📝 Creating GitHub Issue...")
        create_github_issue(metrics, anomalies, analysis)

    else:
        print("✅ All metrics within normal thresholds — app is healthy!")
        print(f"  Error rate: {metrics.get('error_rate', 'N/A')}")
        print(f"  Response time: {metrics.get('response_time', 'N/A')}s")
        print(f"  Request rate: {metrics.get('request_rate', 'N/A')} req/min")


if __name__ == "__main__":
    main()
