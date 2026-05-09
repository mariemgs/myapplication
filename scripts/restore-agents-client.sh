#!/bin/bash
cat > frontend/src/client/agents.ts << 'EOF'
import { OpenAPI } from './core/OpenAPI'
import { request as __request } from './core/request'

export class AgentsService {
    public static getAgentStatus() {
        return __request(OpenAPI, { method: 'GET', url: '/api/v1/agents/status' })
    }
    public static getAgentReports() {
        return __request(OpenAPI, { method: 'GET', url: '/api/v1/agents/reports' })
    }
    public static getMonitoringIssues() {
        return __request(OpenAPI, { method: 'GET', url: '/api/v1/agents/issues' })
    }
    public static getPipelineStatus() {
        return __request(OpenAPI, { method: 'GET', url: '/api/v1/agents/pipeline' })
    }
    public static triggerAgent(data: { workflow_id: string }) {
        return __request(OpenAPI, { method: 'POST', url: '/api/v1/agents/trigger', body: data })
    }
}
EOF
