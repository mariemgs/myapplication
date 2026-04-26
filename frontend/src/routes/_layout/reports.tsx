import { AgentsService } from '@/client'
import { useSuspenseQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { Suspense } from 'react'
import { FileText, Search } from "lucide-react"
import { DataTable } from '@/components/Common/DataTable'
import { columns } from "@/components/Reports/columns"

export const Route = createFileRoute('/_layout/reports')({
  component: RouteComponent,
})

function getReportsQueryOptions() {
  return {
    queryFn: () => AgentsService.getAgentReports(),
    queryKey: ["reports"],
  }
}

function ReportsTable() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ReportsTableContent />
    </Suspense>
  )
}

function ReportsTableContent() {
  const { data } = useSuspenseQuery(getReportsQueryOptions())

  // The backend returns { "reports": [...] }
  const reports = (data as any).reports || []
  if (reports.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center text-center py-12">
        <div className="rounded-full bg-muted p-4 mb-4">
          <FileText className="h-8 w-8 text-muted-foreground" />
        </div>
        <h3 className="text-lg font-semibold">No reports found</h3>
        <p className="text-muted-foreground">Agents haven't generated any reports yet.</p>
      </div>
    )
  }

  return <DataTable columns={columns} data={reports} />
}

function RouteComponent() {
  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Agent Reports</h1>
          <p className="text-muted-foreground">Review recent AI-generated insights</p>
        </div>
      </div>
      <ReportsTable />
    </div>
  )
}