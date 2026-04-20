import { AgentsService } from '@/client'
import { useSuspenseQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { Suspense } from 'react'
import { Search } from "lucide-react"
import { DataTable } from '@/components/Common/DataTable'
import { columns } from "@/components/Agents/columns"

export const Route = createFileRoute('/_layout/agents')({
  component: RouteComponent,
})

function getAgentsQueryOptions() {
  return {
    queryFn: () => AgentsService.getAgentStatus() as Promise<any>,
    queryKey: ["agents"],
  }
}

function AgentsTable() {
  return (
    <Suspense >
      <AgentsTableContent />
    </Suspense>
  )
}
function AgentsTableContent() {
  const { data: agents } = useSuspenseQuery(getAgentsQueryOptions())

  if (agents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center text-center py-12">
        <div className="rounded-full bg-muted p-4 mb-4">
          <Search className="h-8 w-8 text-muted-foreground" />
        </div>
        <h3 className="text-lg font-semibold">You don't have any items yet</h3>
        <p className="text-muted-foreground">Add a new item to get started</p>
      </div>
    )
  }

  return <DataTable columns={columns} data={agents} />
}

function RouteComponent() {
  return <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Agents</h1>
          <p className="text-muted-foreground">Manage your items</p>
        </div>
        {/* <AddItem /> */}
      </div>
      <AgentsTable />
    </div>
}
