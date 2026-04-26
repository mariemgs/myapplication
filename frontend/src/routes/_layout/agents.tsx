import { AgentsService } from '@/client'
import { useSuspenseQuery, useMutation } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { Suspense, useState } from 'react'
import { cn } from '@/lib/utils'
import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle,
  Code,
  ExternalLink,
  GitBranch,
  Play,
  RefreshCw,
  Shield,
  Terminal,
  XCircle,
  Zap,
  ShieldAlert,
  Bug,
  Lock,
  FileSearch,
} from 'lucide-react'

export const Route = createFileRoute('/_layout/agents')({
  component: RouteComponent,
  head: () => ({
    meta: [{ title: 'AI Agents — DevSecOps Dashboard' }],
  }),
})

// ── Types ──────────────────────────────────────────────────────────
type TabId = 'agents' | 'security' | 'pipeline' | 'reports'

// ── Helpers ────────────────────────────────────────────────────────
function StatusPill({ value }: { value: string | null }) {
  if (!value) return <span className="text-xs text-muted-foreground">—</span>
  const map: Record<string, string> = {
    success: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    failure: 'bg-red-50 text-red-700 border-red-200',
    skipped: 'bg-gray-100 text-gray-500 border-gray-200',
    in_progress: 'bg-blue-50 text-blue-700 border-blue-200',
    queued: 'bg-yellow-50 text-yellow-700 border-yellow-200',
    never_run: 'bg-gray-100 text-gray-400 border-gray-200',
    unknown: 'bg-gray-100 text-gray-400 border-gray-200',
    error: 'bg-red-50 text-red-400 border-red-100',
  }
  return (
    <span className={cn('px-2 py-0.5 rounded-full text-xs font-semibold border', map[value] ?? map.unknown)}>
      {value}
    </span>
  )
}

function AgentIcon({ icon }: { icon: string }) {
  const size = 'h-4 w-4'
  const map: Record<string, React.ReactNode> = {
    '🔴': <Terminal className={size} />,
    '🔒': <Shield className={size} />,
    '📊': <Activity className={size} />,
    '🔍': <Code className={size} />,
    '🤖': <Zap className={size} />,
  }
  return <>{map[icon] ?? <Bot className={size} />}</>
}

function SectionTitle({ icon, title, subtitle }: { icon: React.ReactNode; title: string; subtitle?: string }) {
  return (
    <div className="flex items-start gap-3 mb-6">
      <div className="rounded-lg bg-muted p-2 mt-0.5">{icon}</div>
      <div>
        <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
        {subtitle && <p className="text-sm text-muted-foreground">{subtitle}</p>}
      </div>
    </div>
  )
}

// ── Tabs ───────────────────────────────────────────────────────────
const TABS: { id: TabId; label: string; icon: React.ReactNode }[] = [
  { id: 'agents', label: 'AI Agents', icon: <Bot className="h-4 w-4" /> },
  { id: 'security', label: 'Security', icon: <ShieldAlert className="h-4 w-4" /> },
  { id: 'pipeline', label: 'Pipeline', icon: <GitBranch className="h-4 w-4" /> },
  { id: 'reports', label: 'Reports', icon: <FileSearch className="h-4 w-4" /> },
]

// ── Agents Tab ─────────────────────────────────────────────────────
function AgentsTab() {
  const { data: agents } = useSuspenseQuery({
    queryFn: () => AgentsService.getAgentStatus() as Promise<any[]>,
    queryKey: ['agents'],
    refetchInterval: 30000,
  })

  const trigger = useMutation({
    mutationFn: (id: string) => AgentsService.triggerAgent({ workflow_id: id }) as Promise<any>,
  })

  const successCount = agents.filter((a: any) => a.conclusion === 'success').length
  const failureCount = agents.filter((a: any) => a.conclusion === 'failure').length

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Total Agents', value: agents.length, color: 'text-foreground', bg: 'bg-muted' },
          { label: 'Healthy', value: successCount, color: 'text-emerald-700', bg: 'bg-emerald-50' },
          { label: 'Failed', value: failureCount, color: 'text-red-700', bg: 'bg-red-50' },
        ].map((s) => (
          <div key={s.label} className={cn('rounded-xl border p-4', s.bg)}>
            <p className="text-xs text-muted-foreground mb-1">{s.label}</p>
            <p className={cn('text-3xl font-bold', s.color)}>{s.value}</p>
          </div>
        ))}
      </div>

      <div className="rounded-xl border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 border-b">
            <tr>
              {['Agent', 'Status', 'Conclusion', 'Last Run', 'Description', ''].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y">
            {agents.map((agent: any) => (
              <tr key={agent.name} className="hover:bg-muted/30 transition-colors">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="rounded-md bg-muted p-1.5">
                      <AgentIcon icon={agent.icon} />
                    </div>
                    <span className="font-medium">{agent.name}</span>
                  </div>
                </td>
                <td className="px-4 py-3"><StatusPill value={agent.status} /></td>
                <td className="px-4 py-3"><StatusPill value={agent.conclusion} /></td>
                <td className="px-4 py-3">
                  <div className="text-xs">
                    <div>{agent.last_run}</div>
                    {agent.run_number && <div className="text-muted-foreground">#{agent.run_number}</div>}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-muted-foreground max-w-[180px] block truncate">{agent.description}</span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2 justify-end">
                    {agent.last_run_url && (
                      <a
                        href={agent.last_run_url}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                      >
                        <ExternalLink className="h-3 w-3" />
                        Logs
                      </a>
                    )}
                    <button
                      onClick={() => trigger.mutate(agent.id ?? agent.name.toLowerCase().replace(' ', '-'))}
                      disabled={trigger.isPending}
                      className="flex items-center gap-1 text-xs font-medium text-indigo-600 hover:text-indigo-800 disabled:opacity-50"
                    >
                      {trigger.isPending ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                      Run
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Security Tab ───────────────────────────────────────────────────
function SecurityTab() {
  const SECURITY_TOOLS = [
    { name: 'Bandit', label: 'Python SAST', icon: <Bug className="h-5 w-5" />, color: 'text-orange-600', bg: 'bg-orange-50 border-orange-200', description: 'Static analysis security testing for Python code', workflow: 'test-backend.yml', checks: ['SQL Injection', 'Hardcoded Secrets', 'Weak Cryptography', 'Command Injection'] },
    { name: 'Trivy', label: 'Container Scan', icon: <Shield className="h-5 w-5" />, color: 'text-blue-600', bg: 'bg-blue-50 border-blue-200', description: 'Vulnerability scanning for Docker images and filesystems', workflow: 'test-docker-compose.yml', checks: ['OS Vulnerabilities', 'Dependency CVEs', 'Misconfigurations', 'Secrets'] },
    { name: 'OWASP ZAP', label: 'DAST', icon: <Lock className="h-5 w-5" />, color: 'text-red-600', bg: 'bg-red-50 border-red-200', description: 'Dynamic application security testing on running app', workflow: 'owasp-zap.yml', checks: ['XSS', 'SQL Injection', 'CSRF', 'Broken Authentication'] },
    { name: 'SonarQube', label: 'Code Quality', icon: <FileSearch className="h-5 w-5" />, color: 'text-purple-600', bg: 'bg-purple-50 border-purple-200', description: 'Code quality and security hotspot analysis', workflow: 'sonarqube.yml', checks: ['Code Smells', 'Bugs', 'Security Hotspots', 'Coverage'] },
    { name: 'pip-audit', label: 'Dependency Scan', icon: <AlertTriangle className="h-5 w-5" />, color: 'text-yellow-600', bg: 'bg-yellow-50 border-yellow-200', description: 'Python dependency vulnerability scanning', workflow: 'test-backend.yml', checks: ['Known CVEs', 'Outdated Packages', 'License Issues'] },
    { name: 'Gitleaks', label: 'Secrets Detection', icon: <Lock className="h-5 w-5" />, color: 'text-pink-600', bg: 'bg-pink-50 border-pink-200', description: 'Detect hardcoded secrets in source code', workflow: 'test-backend.yml', checks: ['API Keys', 'Passwords', 'Tokens', 'Private Keys'] },
  ]

  const { data: pipelineData } = useSuspenseQuery({
    queryFn: () => AgentsService.getPipelineStatus() as Promise<any>,
    queryKey: ['pipeline'],
    refetchInterval: 30000,
  })

  const pipelineMap: Record<string, any> = {}
  if (pipelineData?.pipeline) {
    for (const p of pipelineData.pipeline) {
      pipelineMap[p.name.toLowerCase()] = p
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionTitle icon={<ShieldAlert className="h-5 w-5" />} title="Security Scan Coverage" subtitle="All security tools integrated in the DevSecOps pipeline" />
      <div className="rounded-xl border bg-gradient-to-r from-slate-50 to-slate-100 p-5">
        <div className="flex items-center gap-3 mb-3">
          <CheckCircle className="h-5 w-5 text-emerald-600" />
          <span className="font-semibold">Security Coverage: 6 tools active</span>
        </div>
        <div className="grid grid-cols-3 gap-3 text-sm">
          {[ { label: 'SAST Tools', value: '2', desc: 'Bandit + SonarQube' }, { label: 'DAST Tools', value: '1', desc: 'OWASP ZAP' }, { label: 'Supply Chain', value: '3', desc: 'Trivy + pip-audit + Gitleaks' } ].map((s) => (
            <div key={s.label} className="bg-white rounded-lg border p-3">
              <p className="text-2xl font-bold text-slate-800">{s.value}</p>
              <p className="font-medium text-xs">{s.label}</p>
              <p className="text-xs text-muted-foreground">{s.desc}</p>
            </div>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {SECURITY_TOOLS.map((tool) => {
          const pKey = tool.workflow.replace('.yml', '').replace(/-/g, ' ')
          const pipelineItem = Object.values(pipelineMap).find((p: any) => p?.name?.toLowerCase().includes(pKey.split(' ')[0]))
          return (
            <div key={tool.name} className={cn('rounded-xl border p-5', tool.bg)}>
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className={cn('rounded-lg bg-white border p-2', tool.color)}>{tool.icon}</div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold">{tool.name}</h3>
                      <span className="text-xs bg-white border rounded-full px-2 py-0.5 font-medium">{tool.label}</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">{tool.description}</p>
                  </div>
                </div>
                {pipelineItem && (
                  <div className="flex items-center gap-1.5 shrink-0">
                    <StatusPill value={pipelineItem.conclusion} />
                    {pipelineItem.url && (
                      <a href={pipelineItem.url} target="_blank" rel="noreferrer"><ExternalLink className="h-3.5 w-3.5 text-muted-foreground hover:text-foreground" /></a>
                    )}
                  </div>
                )}
              </div>
              <div className="flex flex-wrap gap-1.5 mt-2">
                {tool.checks.map((check) => <span key={check} className="text-xs bg-white/70 border rounded-md px-2 py-0.5">{check}</span>)}
              </div>
              {pipelineItem && <p className="text-xs text-muted-foreground mt-3">Last run: {pipelineItem.last_run}</p>}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Pipeline Tab ───────────────────────────────────────────────────
function PipelineTab() {
  const { data: pipelineData } = useSuspenseQuery({
    queryFn: () => AgentsService.getPipelineStatus() as Promise<any>,
    queryKey: ['pipeline'],
    refetchInterval: 30000,
  })

  const pipeline = pipelineData?.pipeline ?? []
  const PIPELINE_STAGES = [
    { stage: 'Build & Test', workflows: ['Test Backend', 'Test Docker Compose'], icon: <Terminal className="h-4 w-4" /> },
    { stage: 'Security Scans', workflows: ['Owasp Zap', 'Sonarqube'], icon: <Shield className="h-4 w-4" /> },
    { stage: 'Deploy', workflows: ['Deploy Staging'], icon: <Zap className="h-4 w-4" /> },
  ]

  const pMap: Record<string, any> = {}
  for (const p of pipeline) { pMap[p.name] = p }

  return (
    <div className="flex flex-col gap-6">
      <SectionTitle icon={<GitBranch className="h-5 w-5" />} title="CI/CD Pipeline Status" subtitle="Real-time status of all pipeline stages" />
      {PIPELINE_STAGES.map((stage) => (
        <div key={stage.stage} className="rounded-xl border overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 bg-muted/50 border-b">{stage.icon} <span className="font-semibold text-sm">{stage.stage}</span></div>
          <div className="divide-y">
            {stage.workflows.map((wf) => {
              const item = Object.values(pMap).find((p: any) => p?.name?.toLowerCase().includes(wf.toLowerCase().split(' ')[0]))
              return (
                <div key={wf} className="flex items-center justify-between px-4 py-3 hover:bg-muted/20">
                  <div className="flex items-center gap-3">
                    {item?.conclusion === 'success' ? <CheckCircle className="h-4 w-4 text-emerald-500" /> : item?.conclusion === 'failure' ? <XCircle className="h-4 w-4 text-red-500" /> : <RefreshCw className="h-4 w-4 text-muted-foreground" />}
                    <span className="text-sm font-medium">{wf}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    {item && (
                      <>
                        <span className="text-xs text-muted-foreground">{item.last_run}</span>
                        <StatusPill value={item.conclusion} />
                        {item.url && <a href={item.url} target="_blank" rel="noreferrer"><ExternalLink className="h-3.5 w-3.5 text-muted-foreground hover:text-foreground" /></a>}
                      </>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Reports Tab ────────────────────────────────────────────────────
function ReportsTab() {
  const { data: reportsData } = useSuspenseQuery({
    queryFn: () => AgentsService.getAgentReports() as Promise<any>,
    queryKey: ['agent-reports'],
    refetchInterval: 60000,
  })

  const { data: issuesData } = useSuspenseQuery({
    queryFn: () => AgentsService.getMonitoringIssues() as Promise<any>,
    queryKey: ['monitoring-issues'],
    refetchInterval: 60000,
  })

  const reports = reportsData?.reports ?? []
  const issues = issuesData?.issues ?? []

  const typeConfig: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
    failure: { label: 'Failure Analysis', color: 'text-red-600 bg-red-50 border-red-200', icon: <Terminal className="h-3.5 w-3.5" /> },
    security: { label: 'Security Report', color: 'text-orange-600 bg-orange-50 border-orange-200', icon: <Shield className="h-3.5 w-3.5" /> },
    orchestrator: { label: 'Orchestrator', color: 'text-purple-600 bg-purple-50 border-purple-200', icon: <Zap className="h-3.5 w-3.5" /> },
    review: { label: 'Code Review', color: 'text-blue-600 bg-blue-50 border-blue-200', icon: <Code className="h-3.5 w-3.5" /> },
    unknown: { label: 'Report', color: 'text-gray-600 bg-gray-50 border-gray-200', icon: <FileSearch className="h-3.5 w-3.5" /> },
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <SectionTitle icon={<AlertTriangle className="h-5 w-5 text-orange-500" />} title="Open Monitoring Alerts" subtitle="GitHub Issues created by the AI Monitoring Agent" />
        {issues.length === 0 ? (
          <div className="rounded-xl border bg-emerald-50 border-emerald-200 p-5 flex items-center gap-3">
            <CheckCircle className="h-5 w-5 text-emerald-600" />
            <span className="text-sm font-medium text-emerald-700">No open monitoring alerts — application is healthy!</span>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {issues.map((issue: any) => (
              <a
                key={issue.id}
                href={issue.url}
                target="_blank"
                rel="noreferrer"
                className="flex items-start gap-3 rounded-xl border p-4 hover:bg-muted/30 transition-colors"
              >
                <AlertTriangle className="h-4 w-4 text-orange-500 mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium line-clamp-1">{issue.title}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{issue.created_at}</p>
                </div>
                <ExternalLink className="h-4 w-4 text-muted-foreground shrink-0" />
              </a>
            ))}
          </div>
        )}
      </div>

      <div>
        <SectionTitle icon={<Bot className="h-5 w-5 text-indigo-500" />} title="Recent AI Agent Reports" subtitle="Reports posted as commit comments by AI agents" />
        {reports.length === 0 ? (
          <div className="rounded-xl border p-8 text-center text-sm text-muted-foreground">No reports yet. Push a commit to trigger the AI agents.</div>
        ) : (
          <div className="flex flex-col gap-3">
            {reports.map((report: any) => {
              const cfg = typeConfig[report.type] ?? typeConfig.unknown
              return (
                <div key={report.id} className="rounded-xl border p-4 hover:bg-muted/20 transition-colors">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className={cn('flex items-center gap-1.5 text-xs font-semibold border rounded-full px-2 py-0.5', cfg.color)}>
                        {cfg.icon} {cfg.label}
                      </span>
                      <span className="text-xs text-muted-foreground">commit {report.commit_id}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">{report.created_at}</span>
                      <a href={report.url} target="_blank" rel="noreferrer"><ExternalLink className="h-3.5 w-3.5 text-muted-foreground hover:text-foreground" /></a>
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground line-clamp-3 leading-relaxed">{report.body.replace(/[#*`🤖🔒📊]/g, '').trim().slice(0, 300)}</p>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main Component ─────────────────────────────────────────────────
function RouteComponent() {
  const [activeTab, setActiveTab] = useState<TabId>('agents')

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">DevSecOps AI Control Panel</h1>
        <p className="text-muted-foreground">Monitor agents, security scans, pipeline status and AI reports</p>
      </div>

      <div className="flex gap-1 border-b">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              'flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors',
              activeTab === tab.id ? 'border-foreground text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
            )}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      <Suspense fallback={<div className="py-12 text-center text-sm text-muted-foreground">Loading dashboard data...</div>}>
        {activeTab === 'agents' && <AgentsTab />}
        {activeTab === 'security' && <SecurityTab />}
        {activeTab === 'pipeline' && <PipelineTab />}
        {activeTab === 'reports' && <ReportsTab />}
      </Suspense>
    </div>
  )
}